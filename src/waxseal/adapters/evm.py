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
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Final, TypeVar

from waxseal.adapters.remote import RemoteRequest, Transport, urllib_transport
from waxseal.domain.abi import (
    SELECTOR_BOND_OF,
    SELECTOR_DEADLINE_OF,
    SELECTOR_DEPOSIT,
    SELECTOR_IS_DELINQUENT,
    SELECTOR_LAST_SEEN,
    SELECTOR_LOOKUP,
    SELECTOR_PROVE_EQUIVOCATION,
    SELECTOR_PROVE_NON_EXTENSION,
    SELECTOR_REGISTER,
    SELECTOR_REGISTER_TRAIL,
    SELECTOR_SUBMIT,
    WORD,
    AbiError,
    Dynamic,
    decode_bool,
    decode_bytes,
    decode_bytes32,
    decode_uint,
    decode_words,
    encode_address,
    encode_bytes,
    encode_bytes32,
    encode_bytes32_array,
    encode_call,
    encode_uint,
)
from waxseal.domain.bond import (
    BondStatus,
    DivergentLeaf,
    EquivocationProof,
    NonExtensionProof,
    bond_status_for,
    checkpoint_signing_digest,
    trail_id_for,
    unreachable_bond,
)
from waxseal.domain.checkpoint import Checkpoint
from waxseal.domain.liveness import (
    LEDGER_UNREACHABLE,
    LivenessVerdict,
    OnChainCheckpoint,
    delinquency,
    unreachable_ledger,
)
from waxseal.domain.registry import RegistryCrossCheck, RegistryFinding
from waxseal.ports.ledger import (
    LedgerDisagreement,
    LedgerError,
    LedgerUnreachable,
    Signer,
    TransactionSigner,
)

T = TypeVar("T")

# Two, not one. See the module docstring: one endpoint is one narrative.
MIN_ENDPOINTS: Final = 2

# JSON-RPC's "execution reverted" code, as geth defines it and anvil emits it.
# Matched alongside the message text because not every node populates `code`.
_EXECUTION_REVERTED: Final = 3

# ---------------------------------------------------------------- selectors
#
# NOT frozen here. Every function selector is frozen ONCE, in domain/abi.py,
# whose whole table is cross-checked against `cast sig` and against
# `forge inspect`'s own output (tests/domain/test_abi.py). This module kept
# its own copies of five of them through 0.1.5, from a period when the domain
# table really did describe an earlier contract draft; waxseal-fg4.40
# corrected the table and the copies outlived their reason, leaving two
# hand-maintained lists of the same constants — the exact shape that let six
# selectors drift through every green gate the first time.
# tests/architecture/test_invariants.py::TestSelectorsAreFrozenInOnePlace
# pins the single owner.
#
# Only the alias is local: `SELECTOR_SUBMIT_HEAD` says which of the two
# `submit`-shaped calls in this file is meant, at the call site.
SELECTOR_SUBMIT_HEAD: Final = SELECTOR_SUBMIT

# `error TrailNotRegistered(bytes32)` — the ONE revert this adapter reads as
# a measured absence rather than as a failure to measure.
ERROR_TRAIL_NOT_REGISTERED: Final = bytes.fromhex("45ed42e1")

# A secp256k1 signature as `CheckpointCodec.recoverSigner` reads it: r‖s‖v.
# Anything else recovers address(0) on chain, which the contract reports as a
# BadWriterSignature revert after the gas is already spent.
SIGNATURE_BYTES: Final = 65


class _RpcRevert(LedgerUnreachable):
    """The contract reverted.

    A subclass of `LedgerUnreachable` so that an UNRECOGNISED revert degrades
    to "nothing was measured" by default — the safe direction — while the two
    call sites that recognise `TrailNotRegistered` catch this first and turn
    it into a measured absence. Inheriting the other way round would make
    every unhandled revert look like a successful read.
    """

    def __init__(self, message: str, data: bytes) -> None:
        super().__init__(message)
        self.data = data

    def selector(self) -> bytes:
        return self.data[:4]


@dataclass(frozen=True, slots=True)
class EvmContracts:
    """Deployed addresses. Each is optional because an operator may run the
    liveness contract without a registry, or a registry without a bond."""

    liveness: str | None = None
    registry: str | None = None
    bond: str | None = None


@dataclass(frozen=True, slots=True)
class EvmTxReceipt:
    """A mined, confirmed transaction."""

    tx_hash: str
    block_number: int
    chain_id: int

    def anchor_receipt(self) -> str:
        """`evm:<chainid>:<block>:<txhash>` — the receipt string an
        `.anchors` sidecar records, chosen so an operator can re-derive the
        transaction from the receipt alone without a lookup table."""
        return f"evm:{self.chain_id}:{self.block_number}:{self.tx_hash}"


def leaf_claim(leaf: DivergentLeaf) -> Dynamic:
    """`BondedCheckpoints.LeafClaim` as one ABI tail blob.

    Was a dataclass of its own here through 0.1.5, holding the same three
    fields as `domain/bond.DivergentLeaf` because the domain type did not
    exist yet: the adapter owned both the wire shape AND the evidence. Only
    the shape was ever the adapter's — whether two of these contradict each
    other is RFC 9162 arithmetic, which now lives in domain and is checked
    there before any gas is spent.
    """
    return Dynamic(
        encode_uint(leaf.index)
        + encode_bytes32(leaf.entry_hash)
        + encode_uint(3 * WORD)
        + bytes(encode_bytes32_array(leaf.proof))
    )


def _signed_checkpoint(checkpoint: Checkpoint, signature: bytes) -> Dynamic:
    """`BondedCheckpoints.SignedCheckpoint` as one ABI tail blob.

    A struct with a dynamic member is itself dynamic, so it contributes an
    offset to the head and this whole blob to the tail — which is exactly
    what `Dynamic` already means to `encode_call`. Building it as a blob
    rather than teaching the encoder about tuples keeps `domain/abi.py`
    untouched and keeps the offset arithmetic in one place.
    """
    return Dynamic(
        encode_uint(checkpoint.seq, bits=64)
        + encode_bytes32(checkpoint.entry_hash)
        + encode_bytes32(checkpoint.root)
        + encode_uint(4 * WORD)
        + bytes(encode_bytes(signature))
    )


def _hex_bytes(what: str, value: object) -> bytes:
    if not isinstance(value, str) or not value.startswith("0x"):
        raise LedgerUnreachable(f"{what}: the node returned {value!r}, which is not 0x-hex")
    try:
        return bytes.fromhex(value[2:])
    except ValueError as exc:
        raise LedgerUnreachable(f"{what}: the node returned {value!r}, which is not hex") from exc


def _hex_int(what: str, value: object) -> int:
    if not isinstance(value, str):
        raise LedgerUnreachable(f"{what}: the node returned {value!r}, which is not a quantity")
    try:
        return int(value, 16)
    except ValueError as exc:
        raise LedgerUnreachable(f"{what}: the node returned {value!r}, not a hex quantity") from exc


def _rpc_failure(what: str, error: object) -> LedgerUnreachable:
    """Turn a JSON-RPC `error` member into the right exception.

    An execution revert is the contract SPEAKING; everything else (rate
    limits, bad params, a node that has not synced the block tag) is the node
    failing to answer. Collapsing the two would make a contract's designed
    three-valued reply indistinguishable from an outage.
    """
    if not isinstance(error, Mapping):
        return LedgerUnreachable(f"{what}: the node returned a malformed error member {error!r}")
    message = str(error.get("message", error))
    if error.get("code") == _EXECUTION_REVERTED or "execution reverted" in message.lower():
        raw = _revert_data(error.get("data"))
        return _RpcRevert(f"{what}: reverted ({_selector_text(raw)}): {message}", raw)
    return LedgerUnreachable(f"{what}: {message}")


def _revert_data(value: object) -> bytes:
    """The ABI-encoded revert payload, or empty when there is none to read.

    Empty rather than an exception: a node that reverts without carrying the
    custom error's bytes (some proxies strip them) has still reverted, and
    the caller's decision — is this the one revert we recognise? — is simply
    "no" in that case. Losing the whole answer over a missing detail would be
    the larger error.
    """
    if not isinstance(value, str) or not value.startswith("0x"):
        return b""
    try:
        return bytes.fromhex(value[2:])
    except ValueError:
        return b""


def _selector_text(raw: bytes) -> str:
    return f"custom error 0x{raw[:4].hex()}" if raw else "no revert data"


def _nonempty(what: str, raw: bytes) -> bytes:
    """Guard the "no contract at that address" case.

    `eth_call` against an address holding no code returns `0x` — a SUCCESS
    with an empty body, not a revert. Decoding that yields zero words, and a
    zero-word answer read as "the trail holds nothing" would report a typo in
    a `--liveness` flag as a measured fact about the writer.
    """
    if not raw:
        raise LedgerUnreachable(
            f"{what}: the call returned no data at all — no contract at that address, "
            "or the node has no state at this block tag"
        )
    return raw


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


class EvmLedgerSink:
    """`LedgerSink` over JSON-RPC with an injected `TransactionSigner`.

    The signer is never constructed here and no private key ever reaches
    waxseal: this class assembles the transaction FIELDS, hands them over,
    and broadcasts whatever raw bytes come back. An implementation may shell
    out to `cast wallet`, call `eth-account`, or talk to an HSM.

    Writes go to ONE endpoint, not to the reader's quorum. A transaction is
    submitted, not measured — broadcasting the same signed bytes to several
    nodes is a propagation strategy, not a cross-check, and the confirmation
    that matters is read back through the reader's agreement path afterwards.
    """

    name: str = "evm"

    def __init__(
        self,
        reader: EvmLedgerReader,
        signer: TransactionSigner,
        *,
        rpc_url: str | None = None,
        confirm_tag: str = "finalized",
        poll_interval_s: float = 1.0,
        max_polls: int = 60,
        sleep_fn: Callable[[float], None] = time.sleep,
    ) -> None:
        if max_polls < 1:
            raise ValueError(f"max_polls must be at least 1, got {max_polls}")
        self._reader = reader
        self._signer = signer
        self._url = rpc_url if rpc_url is not None else reader._urls[0]
        self._confirm_tag = confirm_tag
        self._poll_interval_s = poll_interval_s
        self._max_polls = max_polls
        self._sleep = sleep_fn

    # ------------------------------------------------------------ plumbing

    def _rpc(self, what: str, method: str, params: list[Any]) -> Any:
        return self._reader._rpc(self._url, what, method, params)

    def _poll(self, what: str, probe: Callable[[], T | None]) -> T:
        for attempt in range(self._max_polls):
            found = probe()
            if found is not None:
                return found
            if attempt + 1 < self._max_polls:
                self._sleep(self._poll_interval_s)
        raise LedgerUnreachable(f"{what}: still unresolved after {self._max_polls} polls")

    def _send(self, what: str, to: str, data: bytes, *, value: int = 0) -> EvmTxReceipt:
        chain_id = _hex_int(what, self._rpc(what, "eth_chainId", []))
        nonce = _hex_int(
            what, self._rpc(what, "eth_getTransactionCount", [self._signer.address, "pending"])
        )
        block = self._rpc(what, "eth_getBlockByNumber", ["latest", False])
        if not isinstance(block, Mapping):
            raise LedgerUnreachable(f"{what}: the node returned no latest block")
        base_fee = _hex_int(what, block.get("baseFeePerGas"))
        priority_fee = _hex_int(what, self._rpc(what, "eth_maxPriorityFeePerGas", []))
        call = {
            "from": self._signer.address,
            "to": to,
            "data": "0x" + data.hex(),
            "value": hex(value),
        }
        try:
            gas = _hex_int(what, self._rpc(what, "eth_estimateGas", [call]))
        except _RpcRevert as revert:
            # A revert on the WRITE path is the contract rejecting this
            # transaction, which is a positive answer — the opposite of the
            # read path, where an unrecognised revert means nothing was
            # measured. Sending it anyway would burn the operator's gas to
            # learn what the estimate already said.
            raise LedgerError(f"{what}: the contract rejected this call: {revert}") from revert
        fields: dict[str, object] = {
            "type": 2,
            "chainId": chain_id,
            "nonce": nonce,
            "to": to,
            "value": value,
            "data": "0x" + data.hex(),
            "gas": gas,
            # Twice the base fee plus the tip: the base fee can rise by 12.5%
            # per block, so a bare `base + tip` is a transaction that stops
            # being includable the moment one busy block passes.
            "maxFeePerGas": 2 * base_fee + priority_fee,
            "maxPriorityFeePerGas": priority_fee,
            "accessList": [],
        }
        raw = self._signer.sign_transaction(fields)
        if not raw:
            raise LedgerError(f"{what}: the signer returned no transaction bytes")
        try:
            sent = self._rpc(what, "eth_sendRawTransaction", ["0x" + raw.hex()])
        except _RpcRevert as revert:
            raise LedgerError(f"{what}: the node rejected the transaction: {revert}") from revert
        tx_hash = str(sent)
        receipt = self._poll(f"{what}: receipt for {tx_hash}", lambda: self._receipt(what, tx_hash))
        status = _hex_int(what, receipt.get("status"))
        if status != 1:
            raise LedgerError(f"{what}: transaction {tx_hash} reverted on chain (status {status})")
        block_number = _hex_int(what, receipt.get("blockNumber"))
        self._poll(
            f"{what}: {tx_hash} in block {block_number} reaching {self._confirm_tag}",
            lambda: self._confirmed(what, block_number),
        )
        return EvmTxReceipt(tx_hash=tx_hash, block_number=block_number, chain_id=chain_id)

    def _receipt(self, what: str, tx_hash: str) -> Mapping[str, Any] | None:
        result = self._rpc(what, "eth_getTransactionReceipt", [tx_hash])
        return result if isinstance(result, Mapping) else None

    def _confirmed(self, what: str, block_number: int) -> bool | None:
        """True once `confirm_tag` has reached `block_number`, else None.

        None, not False, because `_poll` reads None as "keep waiting" — and
        because "not final yet" is not a measurement that the block was
        excluded. A dev node whose `finalized` never advances will time out
        here with a message naming both numbers rather than claim finality.
        """
        head = self._rpc(what, "eth_getBlockByNumber", [self._confirm_tag, False])
        if not isinstance(head, Mapping):
            return None
        return True if _hex_int(what, head.get("number")) >= block_number else None

    # ---------------------------------------------------------- LedgerSink

    def register_trail(self, chain_id: str, writer: str, deadline_s: int) -> str:
        """Bind a trail id to its writer key and deadline (one-time)."""
        return self.register_trail_receipt(chain_id, writer, deadline_s).tx_hash

    def register_trail_receipt(self, chain_id: str, writer: str, deadline_s: int) -> EvmTxReceipt:
        calldata = encode_call(
            SELECTOR_REGISTER_TRAIL,
            [
                encode_bytes32(trail_id_for(chain_id)),
                encode_address(writer),
                encode_uint(deadline_s, bits=64),
            ],
        )
        return self._send("registerTrail", self._reader._address("liveness"), calldata)

    def submit_checkpoint(
        self,
        chain_id: str,
        checkpoint: Checkpoint,
        signature: bytes,
        *,
        consistency_proof: Sequence[str] = (),
    ) -> str:
        return self.submit_checkpoint_receipt(
            chain_id, checkpoint, signature, consistency_proof=consistency_proof
        ).tx_hash

    def submit_checkpoint_receipt(
        self,
        chain_id: str,
        checkpoint: Checkpoint,
        signature: bytes,
        *,
        consistency_proof: Sequence[str] = (),
    ) -> EvmTxReceipt:
        """Publish a writer-signed head.

        `consistency_proof` is a keyword with a default because
        `ports/ledger.LedgerSink` was written against a five-argument
        `submit` and the deployed contract takes a sixth: an RFC 9162 proof
        that the recorded head's tree is a prefix of this one. Empty is
        correct for the FIRST submit and only the first; afterwards the
        contract reverts `NotAnExtension`, which arrives here as a
        `LedgerError` rather than as a quiet no-op.
        """
        calldata = encode_call(
            SELECTOR_SUBMIT_HEAD,
            [
                encode_bytes32(trail_id_for(chain_id)),
                encode_uint(checkpoint.seq, bits=64),
                encode_bytes32(checkpoint.entry_hash),
                encode_bytes32(checkpoint.root),
                encode_bytes(signature),
                encode_bytes32_array(consistency_proof),
            ],
        )
        return self._send("submit", self._reader._address("liveness"), calldata)

    def register_fingerprint(self, descriptor: bytes) -> str:
        """Publish a descriptor. The contract computes `sha256(descriptor)`
        itself, so there is no fingerprint argument to disagree with it."""
        calldata = encode_call(SELECTOR_REGISTER, [encode_bytes(descriptor)])
        return self._send("register", self._reader._address("registry"), calldata).tx_hash

    def deposit_bond(self, amount_wei: int) -> str:
        """Post or top up the signer's bond."""
        calldata = encode_call(SELECTOR_DEPOSIT, [])
        return self._send(
            "deposit", self._reader._address("bond"), calldata, value=amount_wei
        ).tx_hash

    def submit_fraud_proof(self, proof: EquivocationProof | NonExtensionProof) -> str:
        """Submit a fraud proof to the bond contract. ONE door for both shapes.

        It was not one through 0.1.5: `domain/bond.NonExtensionProof` then
        modelled a consistency-proof CHALLENGE, which `proveNonExtension` does
        not accept — the contract slashes on POSITIVE evidence (one leaf index
        and two inclusion proofs putting different entry hashes there, each
        valid against its own signed root) because a FAILING consistency proof
        shows only that the prover supplied a bad one, and slashing on that
        would let anyone burn an honest writer's bond for the price of gas. So
        this method raised on one of its own two argument types and pointed at
        a second entry point. The domain type is now that positive evidence
        (the challenge kept its behaviour under the honest name
        `NonExtensionChallenge`), and the second door is gone.
        """
        if isinstance(proof, NonExtensionProof):
            return self._submit_non_extension(proof)
        reason = proof.validate()
        if reason is not None:
            # Structural admissibility is free to check here; sending an
            # inadmissible pair only buys a revert and the gas that paid for it.
            raise LedgerError(f"proveEquivocation: the pair is not an equivocation: {reason}")
        calldata = encode_call(
            SELECTOR_PROVE_EQUIVOCATION,
            [
                encode_bytes32(trail_id_for(proof.chain_id)),
                encode_uint(proof.checkpoint_a.seq, bits=64),
                _signed_checkpoint(proof.checkpoint_a, proof.signature_a),
                _signed_checkpoint(proof.checkpoint_b, proof.signature_b),
            ],
        )
        return self._send(
            "proveEquivocation", self._reader._address("bond"), calldata
        ).tx_hash

    def _submit_non_extension(self, proof: NonExtensionProof) -> str:
        """Slash a writer whose newer head contradicts its older one at a leaf
        both trees contain. Private: `submit_fraud_proof` is the door."""
        reason = proof.validate()
        if reason is not None:
            raise LedgerError(
                f"proveNonExtension: the pair is not a non-extension: {reason}"
            )
        calldata = encode_call(
            SELECTOR_PROVE_NON_EXTENSION,
            [
                encode_bytes32(trail_id_for(proof.chain_id)),
                _signed_checkpoint(proof.older, proof.older_signature),
                _signed_checkpoint(proof.newer, proof.newer_signature),
                leaf_claim(proof.in_older),
                leaf_claim(proof.in_newer),
            ],
        )
        return self._send(
            "proveNonExtension", self._reader._address("bond"), calldata
        ).tx_hash


class EvmAnchorSink:
    """`AnchorSink` writing the trail head to the liveness contract.

    This replaces the docs-only example in `docs/anchoring-external-time.md`
    with code. The digest signer and the transaction signer are injected
    SEPARATELY because `ports/ledger.py` keeps them as separate Protocols: a
    key that signs a 32-byte checkpoint digest is not necessarily the key
    that pays for gas, and in a sane deployment it is not.
    """

    name: str = "evm"

    def __init__(
        self,
        sink: EvmLedgerSink,
        chain_id: str,
        signer: Signer,
        *,
        proof_fn: Callable[[Checkpoint], Sequence[str]] | None = None,
    ) -> None:
        self._sink = sink
        self._chain_id = chain_id
        self._signer = signer
        self._proof_fn = proof_fn

    def anchor(self, checkpoint: Checkpoint) -> str:
        """Sign and publish, returning `evm:<chainid>:<block>:<txhash>`.

        `proof_fn` supplies the RFC 9162 consistency proof the contract
        requires from the second submit onwards; `AnchorSink.anchor` is
        handed only a `Checkpoint`, so an operator anchoring repeatedly must
        inject it. Without one, the second anchor raises `LedgerError` when
        the contract refuses — loudly, as `AnchorSink` requires, never as a
        silent no-receipt.
        """
        digest = checkpoint_signing_digest(self._chain_id, checkpoint)
        signature = self._signer.sign(digest)
        if len(signature) != SIGNATURE_BYTES:
            raise LedgerError(
                f"the signer returned {len(signature)} bytes; CheckpointCodec.recoverSigner "
                f"reads exactly {SIGNATURE_BYTES} (r‖s‖v) and recovers address(0) from "
                "anything else, which the contract rejects only after the gas is spent"
            )
        proof = () if self._proof_fn is None else self._proof_fn(checkpoint)
        receipt = self._sink.submit_checkpoint_receipt(
            self._chain_id, checkpoint, signature, consistency_proof=proof
        )
        return receipt.anchor_receipt()
