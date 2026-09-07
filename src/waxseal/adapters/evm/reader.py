"""EVM adapter for the ledger layer: read over stdlib JSON-RPC, write via an
injected `Signer` (CLAUDE.md rule 1 — `dependencies` stays `[]`).

Nothing in this module is imported by the core. `import waxseal` does not
reach it, `waxseal.adapters.__init__` does not name it, and the `evm` extra
in pyproject.toml is deliberately EMPTY: there is no client to fetch,
because the read path is `eth_call` over the same `Transport` REMOTE.md's
client already uses, and the write path hands a field dict to a `Signer` the
operator constructs. An operator who wants `eth-account` or `cast wallet`
behind that Signer installs it themselves; waxseal never imports it.

WHY TWO ENDPOINTS ARE MANDATORY
--------------------------------
A single RPC endpoint is a single point of *narrative* failure, not merely of
availability. An eclipsing adversary does not have to break the chain; it
only has to be the one voice the client hears. So the reader takes at least
two URLs and every read is asked of all of them:

  * they agree              -> the value, returned;
  * they answered and differ-> `LedgerDisagreement`, naming the pair;
  * fewer than two answered -> `LedgerUnreachable`, naming every silence.

`LedgerDisagreement` is NOT a network error and NOT a tamper verdict. It is
the third value in its own right: two independent observers, both reachable,
reporting different states of the same contract. Picking a winner is exactly
what the adversary needs the client to do, and reporting it as
unreachability would erase the one observation that distinguishes an
eclipse from an outage. It is a separate exception class (F1's,
`ports/ledger.py`) for that reason, and it carries both answers so rule 6 is
satisfied — the degradation reaches the operator, never swallowed.

WHAT A REVERT MEANS, AND WHAT IT DOES NOT
-----------------------------------------
`AnchoringLiveness.isDelinquent` and `.lastSeen` REVERT with
`TrailNotRegistered(bytes32)` for a trail that is unregistered or has never
anchored, instead of returning `false`/zeros. That is deliberate on the
Solidity side: `bool` is two-valued and the honest answer is three-valued.

This adapter therefore treats that specific revert as a MEASURED ABSENCE and
maps it to `None` — the exact case `ports/ledger.py` reserves `None` for
("the contract answered, and it holds nothing"). It is not `unreachable`:
the node answered, deterministically, from state, and a second call would
answer the same. Calling it unreachable would throw away a fact we hold.

What the absence then MEANS is decided by pure domain code, not here:
`delinquency(None, deadline)` (domain/liveness.py) returns `delinquent`
with reason `no_checkpoint_on_ledger` when a deadline exists — a registered
trail that never anchored IS late — and `unreachable` with reason
`deadline_unavailable` when none does, because there is nothing to be late
against. The adapter reports what it measured; the domain decides the
verdict.

Any OTHER revert is a different matter: the contract answered with something
this build cannot interpret, so nothing was measured, and it degrades to
`LedgerUnreachable` with the four-byte error selector spelled in the message
(`_RpcRevert` subclasses it for exactly that reason). Labelled, never
silent. On the WRITE path the same revert is inverted: a transaction the
contract rejects is a positive rejection, not a failure to reach, and it
surfaces as `LedgerError`.

SELECTORS ARE NOT COMPUTED HERE
-------------------------------
Python has no keccak256 (see `domain/abi.py`'s docstring). Function and error
selectors are frozen constants, and `tests/adapters/test_evm.py` compares
every one of them against `contracts/abi/selectors.json` — the file
`forge inspect` writes — plus `cast sig` when Foundry is on PATH.

Some of `domain/abi.py`'s frozen selectors describe an EARLIER shape of the
contracts than the ones `contracts/` actually deploys (`deadline(bytes32)`
vs the deployed `deadlineOf(bytes32)`, a five-argument `submit`, a flattened
`proveEquivocation`). This module uses the deployed set and imports from
`domain/abi.py` only the constants that still match; the cross-check test
asserts that split rather than leaving it to a reader's memory.
"""


from __future__ import annotations

import itertools
import json
import operator
from collections.abc import Callable, Sequence
from datetime import datetime
from typing import Any

from waxseal.adapters.evm._rpc import (
    ERROR_TRAIL_NOT_REGISTERED,
    MIN_ENDPOINTS,
    T,
    _hex_bytes,
    _nonempty,
    _rpc_failure,
    _RpcRevert,
)
from waxseal.adapters.evm.contracts import EvmContracts
from waxseal.adapters.remote import RemoteRequest, Transport, urllib_transport
from waxseal.domain.abi import (
    SELECTOR_BOND_OF,
    SELECTOR_DEADLINE_OF,
    SELECTOR_IS_DELINQUENT,
    SELECTOR_LAST_SEEN,
    SELECTOR_LOOKUP,
    AbiError,
    decode_bool,
    decode_bytes,
    decode_bytes32,
    decode_uint,
    decode_words,
    encode_address,
    encode_bytes32,
    encode_call,
)
from waxseal.domain.bond import (
    BondStatus,
    bond_status_for,
    trail_id_for,
    unreachable_bond,
)
from waxseal.domain.liveness import (
    LEDGER_UNREACHABLE,
    LivenessVerdict,
    OnChainCheckpoint,
    delinquency,
    unreachable_ledger,
)
from waxseal.domain.registry import RegistryCrossCheck, RegistryFinding
from waxseal.ports.ledger import LedgerDisagreement, LedgerUnreachable


class EvmLedgerReader:
    """`LedgerReader` over JSON-RPC, cross-checked across endpoints.

    `block_tag` defaults to `finalized`: a read at `latest` can be undone by
    a reorg, and a value that may be withdrawn is not a measurement. A chain
    or a dev node whose `finalized` lags is therefore reporting less than
    `latest` knows, which is the intended trade — "not yet final" is
    unmeasured, not absent.
    """

    name: str = "evm"

    def __init__(
        self,
        rpc_urls: Sequence[str],
        contracts: EvmContracts,
        *,
        transport: Transport | None = None,
        block_tag: str = "finalized",
        timeout: float = 10.0,
    ) -> None:
        urls = tuple(rpc_urls)
        if len(urls) < MIN_ENDPOINTS:
            raise ValueError(
                f"EvmLedgerReader needs at least {MIN_ENDPOINTS} RPC endpoints to cross-check; "
                f"got {len(urls)}. One endpoint cannot disagree with itself."
            )
        if len(set(urls)) != len(urls):
            raise ValueError(
                "the same RPC endpoint listed twice is one observer counted twice, "
                "which manufactures agreement instead of measuring it"
            )
        self._urls = urls
        self._contracts = contracts
        self._transport = transport if transport is not None else urllib_transport(timeout=timeout)
        self._block_tag = block_tag

    # ------------------------------------------------------------ plumbing

    def _address(self, which: str) -> str:
        address = getattr(self._contracts, which)
        if address is None:
            # Not a crash and not a verdict: we could not ask, because we
            # were never told where. `ledger-status --liveness` without
            # `--registry` must read as unmeasured, not as agreement.
            raise LedgerUnreachable(f"no {which} contract address was configured")
        return str(address)

    def _rpc(self, url: str, what: str, method: str, params: list[Any]) -> Any:
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
        request = RemoteRequest("POST", url, {"content-type": "application/json"}, body)
        try:
            response = self._transport(request)
        except Exception as exc:
            # Deliberately broad. The transport is injected, urllib raises
            # URLError/OSError/ssl errors/ValueError for a refused scheme,
            # and a verifier must degrade to "unmeasured" rather than crash
            # because one node was down.
            raise LedgerUnreachable(f"{url}: {what}: {type(exc).__name__}: {exc}") from exc
        if not 200 <= response.status < 300:
            raise LedgerUnreachable(f"{url}: {what}: HTTP {response.status}")
        try:
            payload = json.loads(response.body)
        except ValueError as exc:
            raise LedgerUnreachable(f"{url}: {what}: the body is not JSON") from exc
        if not isinstance(payload, dict):
            raise LedgerUnreachable(f"{url}: {what}: the body is not a JSON-RPC object")
        if payload.get("error") is not None:
            raise _rpc_failure(f"{url}: {what}", payload["error"])
        if "result" not in payload:
            raise LedgerUnreachable(f"{url}: {what}: neither result nor error")
        return payload["result"]

    def _call(self, url: str, what: str, to: str, data: bytes) -> bytes:
        result = self._rpc(
            url, what, "eth_call", [{"to": to, "data": "0x" + data.hex()}, self._block_tag]
        )
        return _nonempty(f"{url}: {what}", _hex_bytes(f"{url}: {what}", result))

    def _agree(
        self,
        what: str,
        ask: Callable[[str], T],
        *,
        agree: Callable[[T, T], bool] = operator.eq,
    ) -> T:
        """Ask every endpoint; return the answer only if they agree.

        Disagreement is checked BEFORE the quorum, because a measured
        conflict outranks a partial silence: two endpoints contradicting each
        other is a finding even when a third was unreachable, and reporting
        the outage instead would lose it.

        `agree` defaults to plain equality, which is exactly right for every
        caller except `latest_checkpoint` (fg4.42: `OnChainCheckpoint.block_time`
        is a miner-influenced value domain/liveness.py's own docstring calls
        immaterial, so two honest endpoints must not be forced through exact
        equality on it). Audited before adding this parameter: `deadline_s`,
        `registry_lookup`, `bond_status`, and `on_chain_delinquency` all want
        their answers compared exactly, so the default keeps every one of
        them unchanged rather than asking them to pass a comparator they
        have no use for.
        """
        answers: list[tuple[str, T]] = []
        silences: list[str] = []
        for url in self._urls:
            try:
                answers.append((url, ask(url)))
            except LedgerUnreachable as exc:
                silences.append(str(exc))
        for (url_a, value_a), (url_b, value_b) in itertools.combinations(answers, 2):
            if not agree(value_a, value_b):
                raise LedgerDisagreement(
                    f"{what}: endpoints disagree — {url_a} answered {value_a!r}, "
                    f"{url_b} answered {value_b!r}"
                )
        if len(answers) < MIN_ENDPOINTS:
            raise LedgerUnreachable(
                f"{what}: {len(answers)} of {len(self._urls)} endpoints answered, below the "
                f"{MIN_ENDPOINTS} an agreement needs: {'; '.join(silences)}"
            )
        # Whichever endpoint answered first, unconditionally — not min/max.
        # For `latest_checkpoint` this decides what `block_time` comes back
        # when the two agreed only under `_checkpoints_agree`'s tolerance:
        # since that field is already documented as immaterial at the
        # hour-scale granularity liveness deadlines use, which of two
        # near-identical timestamps is returned cannot change any decision,
        # so there is nothing behind picking a tie-break rule more elaborate
        # than "first".
        return answers[0][1]

    # -------------------------------------------------------- LedgerReader

    def latest_checkpoint(self, chain_id: str) -> OnChainCheckpoint | None:
        address = self._address("liveness")
        calldata = encode_call(SELECTOR_LAST_SEEN, [encode_bytes32(trail_id_for(chain_id))])

        def ask(url: str) -> OnChainCheckpoint | None:
            try:
                raw = self._call(url, "lastSeen", address, calldata)
            except _RpcRevert as revert:
                if revert.selector() == ERROR_TRAIL_NOT_REGISTERED:
                    # Measured absence, not silence. See the module docstring.
                    return None
                raise
            # No AbiError guard here, unlike bondOf/lookup below: `_words`
            # has already established four 32-byte words, and neither
            # `decode_uint` nor `decode_bytes32` can fail on one. A guard
            # that cannot fire is a guard nobody can test.
            words = _words(f"{url}: lastSeen", raw, 4)
            return OnChainCheckpoint(
                chain_id=chain_id,
                seq=decode_uint(words[0]),
                entry_hash=decode_bytes32(words[1]),
                root=decode_bytes32(words[2]),
                block_time=decode_uint(words[3]),
            )

        return self._agree(f"latest_checkpoint({chain_id})", ask, agree=_checkpoints_agree)

    def deadline_s(self, chain_id: str) -> int | None:
        address = self._address("liveness")
        calldata = encode_call(SELECTOR_DEADLINE_OF, [encode_bytes32(trail_id_for(chain_id))])

        def ask(url: str) -> int | None:
            raw = self._call(url, "deadlineOf", address, calldata)
            value = decode_uint(_words(f"{url}: deadlineOf", raw, 1)[0])
            # Zero is unambiguous: `registerTrail` reverts on a zero deadline
            # (`ZeroDeadline`), so the only way to read one is an unregistered
            # trail. Reported as None — no deadline configured — never as a
            # deadline of zero seconds, which would make every trail late.
            return value or None

        return self._agree(f"deadline_s({chain_id})", ask)

    def registry_lookup(self, fingerprint: str) -> bytes | None:
        address = self._address("registry")
        calldata = encode_call(SELECTOR_LOOKUP, [encode_bytes32(fingerprint)])

        def ask(url: str) -> bytes | None:
            raw = self._call(url, "lookup", address, calldata)
            try:
                descriptor = decode_bytes(raw)
            except AbiError as exc:
                raise LedgerUnreachable(f"{url}: lookup: {exc}") from exc
            # The contract refuses to register an empty descriptor precisely
            # so that empty means "not registered here" and nothing else.
            return descriptor or None

        return self._agree(f"registry_lookup({fingerprint})", ask)

    def bond_status(self, writer_id: str) -> BondStatus:
        address = self._address("bond")
        calldata = encode_call(SELECTOR_BOND_OF, [encode_address(writer_id)])

        def ask(url: str) -> BondStatus:
            words = _words(f"{url}: bondOf", self._call(url, "bondOf", address, calldata), 4)
            try:
                # Two reads in one return: the amount alone cannot tell
                # "slashed to zero" from "never deposited" (domain/bond.py).
                return bond_status_for(
                    writer_id, amount_wei=decode_uint(words[0]), slashed=decode_bool(words[3])
                )
            except AbiError as exc:
                raise LedgerUnreachable(f"{url}: bondOf: {exc}") from exc

        return self._agree(f"bond_status({writer_id})", ask)

    # ---------------------------------------------------- ternary readings

    def on_chain_delinquency(self, chain_id: str) -> bool | None:
        """`isDelinquent(trailId)` — the CHAIN's own verdict, on its clock.

        Returns None for the revert case, which is the whole reason the
        contract reverts rather than returning `false`. A caller that wants
        the three-valued reading with a reason wants `liveness()`; this is
        here so an operator can compare the chain's answer against the one
        computed locally, and so the revert has a single mapping in one place.
        """
        address = self._address("liveness")
        calldata = encode_call(SELECTOR_IS_DELINQUENT, [encode_bytes32(trail_id_for(chain_id))])

        def ask(url: str) -> bool | None:
            try:
                raw = self._call(url, "isDelinquent", address, calldata)
            except _RpcRevert as revert:
                if revert.selector() == ERROR_TRAIL_NOT_REGISTERED:
                    return None
                raise
            words = _words(f"{url}: isDelinquent", raw, 1)
            try:
                return decode_bool(words[0])
            except AbiError as exc:
                raise LedgerUnreachable(f"{url}: isDelinquent: {exc}") from exc

        return self._agree(f"on_chain_delinquency({chain_id})", ask)

    def liveness(self, chain_id: str, *, now: datetime) -> LivenessVerdict:
        """live / delinquent / unreachable, decided by `domain/liveness.py`.

        `LedgerDisagreement` is deliberately NOT caught: it is not a liveness
        reading at all, and folding it into `unreachable` would drop the pair
        of contradicting endpoints that is the entire content of the finding
        (CLAUDE.md rule 6). The caller catches it and prints both answers.
        """
        try:
            latest = self.latest_checkpoint(chain_id)
            deadline = self.deadline_s(chain_id)
        except LedgerDisagreement:
            raise
        except LedgerUnreachable:
            return unreachable_ledger(LEDGER_UNREACHABLE)
        return delinquency(None if latest is None else latest.block_time, deadline, now=now)

    def bond(self, writer_id: str) -> BondStatus:
        """bonded / slashed / unbonded / unreachable.

        Four values, and `unbonded` is not folded into `slashed`: see
        `domain/bond.BondStatus`. The port allows either raising
        `LedgerUnreachable` or returning `unreachable_bond`, "but never
        both" — `bond_status` raises, this one returns.
        """
        try:
            return self.bond_status(writer_id)
        except LedgerDisagreement:
            raise
        except LedgerUnreachable:
            # The CLI contract's own word for "the chain could not be read".
            # `unreachable_bond` sets the STATUS; this is the reason beside it.
            return unreachable_bond(writer_id, reason=LEDGER_UNREACHABLE)

    def registry_agreement(
        self, cross_check: RegistryCrossCheck, fingerprint: str
    ) -> RegistryFinding:
        """agrees / disagrees / absent / unreachable.

        waxseal-fg4.44: `registry_lookup` already keeps these apart at the
        source, the same way `on_chain_delinquency`/`liveness` above keep a
        recognised `TrailNotRegistered` revert apart from any other failure
        -- `lookup(bytes32)` never reverts at all (`FingerprintRegistry.sol`),
        it answers with empty bytes for an unregistered fingerprint, so a
        `None` RETURNED by `registry_lookup` is a real, measured "no" and a
        `LedgerUnreachable` RAISED by it is nothing measured. This method's
        only job is to not re-merge what the source already told apart:
        `reachable=False` is passed only for the raised case, never inferred
        from the descriptor's own value.
        """
        try:
            descriptor = self.registry_lookup(fingerprint)
        except LedgerDisagreement:
            raise
        except LedgerUnreachable:
            return cross_check.check(fingerprint, None, reachable=False)
        return cross_check.check(fingerprint, descriptor)


def _words(what: str, raw: bytes, expected: int) -> tuple[bytes, ...]:
    try:
        words = decode_words(raw)
    except AbiError as exc:
        raise LedgerUnreachable(f"{what}: {exc}") from exc
    if len(words) != expected:
        raise LedgerUnreachable(
            f"{what}: expected {expected} words back, got {len(words)} — this build is "
            "reading a contract whose return shape it does not know"
        )
    return words


def _checkpoints_agree(
    a: OnChainCheckpoint | None, b: OnChainCheckpoint | None
) -> bool:
    """`_agree`'s comparator for `latest_checkpoint` (fg4.42).

    `OnChainCheckpoint.block_time`'s own docstring (domain/liveness.py) calls
    it "a miner-influenced value with a tolerance of seconds, which is
    immaterial against deadlines measured in hours" — so it must not
    participate in deciding whether two RPC endpoints agree.
    `chain_id`/`seq`/`entry_hash`/`root` are NOT tolerant fields; a
    difference in any of those is compared exactly and IS a real
    disagreement. When either side is a measured absence (`None`), plain
    `==` already does the right thing (`None == None` agrees, `None` next
    to a checkpoint does not), so it is only the two-checkpoint case that
    needs the field-by-field comparison below.
    """
    if isinstance(a, OnChainCheckpoint) and isinstance(b, OnChainCheckpoint):
        return (a.chain_id, a.seq, a.entry_hash, a.root) == (
            b.chain_id,
            b.seq,
            b.entry_hash,
            b.root,
        )
    return a == b
