from __future__ import annotations

import functools
import json
import os
import subprocess
import sys
from collections.abc import Callable, Iterable, Mapping
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from waxseal.domain.bond import DivergentLeaf
from waxseal.domain.checkpoint import Checkpoint
from waxseal.domain.header import Entry
from waxseal.domain.report import (
    CheckSummary,
)
from waxseal.domain.verdict import Verdict
from waxseal.log import AuditLog

if TYPE_CHECKING:
    from waxseal.adapters.evm import EvmContracts, EvmLedgerSink

from waxseal.cli._common import _Check, _default_now

_WAXSEAL_EVM_SIGNER_CMD_MISSING = (
    "WAXSEAL_EVM_SIGNER_CMD is not set. A ledger write needs a signer, and "
    "waxseal never takes a private key on argv or in an env var that "
    "carries key material — the same boundary WAXSEAL_API_KEY and "
    "WAXSEAL_WITNESS_API_KEY already draw for credentials. Set "
    "WAXSEAL_EVM_SIGNER_CMD to an executable this CLI can invoke as "
    "`<cmd> address`, `<cmd> sign-digest 0x<64 hex>`, and `<cmd> sign-tx` "
    "(the transaction fields as a JSON object on stdin) — see "
    "ExternalEvmSigner's docstring for the exact three-verb contract, and "
    "tests/adapters/test_evm_anvil.py's CastSigner for the two operations "
    "(`cast wallet sign --no-hash`, `cast mktx`) a real wrapper needs to "
    "perform behind it"
)

# ============================================================ ledger layer
#
# F4 (Workstream F, Phase 4): CLI surface for the on-chain ledger layer F1
# (ports/domain), F2 (contracts/), and F3 (adapters/evm.py) shipped. Every
# read here goes through `EvmLedgerReader`'s own ternary methods
# (`liveness`, `registry_agreement`, `bond`), never around them, so a chain
# disagreement or an unreachable RPC endpoint reaches the operator exactly
# the way F1/F3 built it to: never silently absorbed into a verdict it did
# not measure.
#
# `_ledger_check` (verify/report) and `_ledger_status` (its own subcommand)
# share the same underlying reads but map them through DIFFERENT verdict
# tables on purpose: `verify`/`report` answer "was the trail edited?", so a
# delinquent or disagreeing ledger can only ever be exit 2 there
# (`LivenessVerdict.to_verify_verdict()`/`RegistryFinding.to_verdict()` both
# exclude BROKEN from their range by construction — this file does not
# police that, the domain types do). `ledger-status` answers a different
# question, "what does the chain say about this writer right now", so a
# delinquent/slashed/unbonded finding there is POSITIVELY DETECTED and is
# exit 1, the same sense `reconcile-tickets` gives its own exit 1.


def _ledger_check(
    entries: Iterable[Entry],
    *,
    rpc_urls: list[str] | None,
    liveness: str | None,
    registry: str | None,
    trail_id: str,
    now_fn: Callable[[], datetime] = _default_now,
) -> _Check:
    """`verify`/`report --rpc/--liveness/--registry` (F4, Phase 4).

    Structurally incapable of contributing exit 1: `LivenessVerdict.
    to_verify_verdict()` and `RegistryFinding.to_verdict()` both map onto
    ``{OK, UNVERIFIABLE}`` only (domain/liveness.py, domain/registry.py), so
    every new reason this dimension can print — ``ledger_delinquent``,
    ``registry_disagreement``, ``registry_fingerprint_not_registered``
    (waxseal-fg4.44: a firm "nobody registered this" answer, distinct from
    ``registry_could_not_be_read``), ``ledger_unreachable`` — reaches exit 2
    and only exit 2, by the shape of the tables it reads through, not by a
    check written here.
    """
    from waxseal.adapters.evm import EvmContracts, EvmLedgerReader
    from waxseal.domain.liveness import LEDGER_UNREACHABLE
    from waxseal.domain.registry import RegistryCrossCheck, VersionRegistry
    from waxseal.ports.ledger import LedgerDisagreement

    lines: list[str] = []
    verdict = Verdict.OK
    reason: str | None = None

    def _absorb(v: Verdict, r: str | None) -> None:
        nonlocal verdict, reason
        verdict = verdict.join(v)
        if r is not None and reason is None:
            reason = r

    try:
        reader = EvmLedgerReader(rpc_urls or [], EvmContracts(liveness=liveness, registry=registry))
    except ValueError as e:
        return _Check(
            CheckSummary(ok=True, checked=0, reason=LEDGER_UNREACHABLE, unverifiable=True),
            f"ledger: {e} — unverifiable, NOT evidence of tampering",
        )

    if liveness is not None:
        try:
            lv = reader.liveness(trail_id, now=now_fn())
        except LedgerDisagreement as e:
            lines.append(f"ledger liveness: DISAGREEMENT (not unreachable) — {e}")
            _absorb(Verdict.UNVERIFIABLE, LEDGER_UNREACHABLE)
        else:
            line = f"ledger liveness: {lv.status}"
            if lv.reason is not None:
                line += f" ({lv.reason})"
            lines.append(line)
            _absorb(lv.to_verify_verdict(), lv.reason)

    if registry is not None:
        fingerprints = sorted({entry.header.hash_version for entry in entries})
        if not fingerprints:
            lines.append("ledger registry: no entries on this trail to cross-check")
        cross_check = RegistryCrossCheck(VersionRegistry())
        for fingerprint in fingerprints:
            try:
                finding = reader.registry_agreement(cross_check, fingerprint)
            except LedgerDisagreement as e:
                lines.append(f"ledger registry {fingerprint}: DISAGREEMENT (not unreachable) — {e}")
                _absorb(Verdict.UNVERIFIABLE, LEDGER_UNREACHABLE)
                continue
            line = f"ledger registry {fingerprint}: {finding.status}"
            if finding.reason is not None:
                line += f" ({finding.reason})"
            lines.append(line)
            _absorb(finding.to_verdict(), finding.reason)

    return _Check(
        CheckSummary(
            ok=True,  # BROKEN is unreachable for this dimension — see docstring.
            checked=1,
            reason=reason,
            unverifiable=verdict is Verdict.UNVERIFIABLE,
        ),
        "\n".join(lines),
    )


def _ledger_status(
    log: AuditLog,
    *,
    rpc_urls: list[str] | None,
    liveness: str,
    registry: str | None,
    bond: str | None,
    writer: str | None,
    trail_id: str,
    as_json: bool,
    now_fn: Callable[[], datetime] = _default_now,
) -> int:
    """`waxseal ledger-status` (F4, Phase 4).

    Exit codes reuse ``Verdict.to_exit_code()``, the SAME convention
    ``_reconcile_tickets`` above already establishes (``cli/tickets.py``):
    0 = every configured dimension came back clean (live, and registry
    agrees if ``--registry`` was given, and bonded if ``--bond`` was given);
    1 = a POSITIVELY DETECTED finding — delinquent, slashed, or unbonded —
    the same "detected, not tampered" sense ``reconcile-tickets`` gives its
    own exit 1; 2 = unreachable, endpoints disagree, or malformed input
    (nothing could be measured, never rendered as "0 findings" — CLAUDE.md
    rule 5). The trail-missing case (exit 3) is handled by ``main()``'s
    shared trail-opening plumbing before this function is ever called,
    exactly as it already is for ``reconcile-tickets``.
    """

    from waxseal.adapters.evm import EvmContracts, EvmLedgerReader
    from waxseal.domain.registry import RegistryCrossCheck, VersionRegistry
    from waxseal.ports.ledger import LedgerDisagreement

    try:
        reader = EvmLedgerReader(
            rpc_urls or [], EvmContracts(liveness=liveness, registry=registry, bond=bond)
        )
    except ValueError as e:
        print(f"unverifiable: {e} — nothing was checked")
        return 2

    findings: list[tuple[str, Verdict, str]] = []

    try:
        lv = reader.liveness(trail_id, now=now_fn())
    except LedgerDisagreement as e:
        findings.append(("liveness", Verdict.UNVERIFIABLE, f"liveness: DISAGREEMENT — {e}"))
    else:
        line = f"liveness: {lv.status}"
        if lv.reason is not None:
            line += f" ({lv.reason})"
        if lv.age_s is not None:
            line += f", age={lv.age_s}s"
        if lv.deadline_s is not None:
            line += f", deadline={lv.deadline_s}s"
        findings.append(("liveness", lv.to_verdict(), line))

    if registry is not None:
        fingerprints = sorted({entry.header.hash_version for entry in log.entries()})
        if not fingerprints:
            findings.append(
                ("registry", Verdict.OK, "registry: no entries on this trail to cross-check")
            )
        cross_check = RegistryCrossCheck(VersionRegistry())
        for fingerprint in fingerprints:
            try:
                finding = reader.registry_agreement(cross_check, fingerprint)
            except LedgerDisagreement as e:
                findings.append(
                    (
                        f"registry:{fingerprint}",
                        Verdict.UNVERIFIABLE,
                        f"registry {fingerprint}: DISAGREEMENT — {e}",
                    )
                )
                continue
            line = f"registry {fingerprint}: {finding.status}"
            if finding.reason is not None:
                line += f" ({finding.reason})"
            findings.append((f"registry:{fingerprint}", finding.to_verdict(), line))

    if bond is not None:
        assert writer is not None  # main() already refused --bond without --writer
        try:
            bs = reader.bond(writer)
        except LedgerDisagreement as e:
            findings.append(("bond", Verdict.UNVERIFIABLE, f"bond: DISAGREEMENT — {e}"))
        else:
            line = f"bond: {bs.status}"
            if bs.reason is not None:
                line += f" ({bs.reason})"
            if bs.amount_wei is not None:
                line += f", amount_wei={bs.amount_wei}"
            findings.append(("bond", bs.to_verdict(), line))

    overall = functools.reduce(Verdict.join, (v for _, v, _ in findings), Verdict.OK)

    if as_json:
        print(
            json.dumps(
                {
                    "trail_id": trail_id,
                    "verdict": overall.value,
                    "findings": [
                        {"dimension": label, "verdict": v.value, "detail": line}
                        for label, v, line in findings
                    ],
                }
            )
        )
    else:
        for _, _, line in findings:
            print(line)
        print(f"ledger-status: {overall.value}")

    return overall.to_exit_code()


def _split_signer_command(command: str, *, windows: bool) -> list[str]:
    """Split ``WAXSEAL_EVM_SIGNER_CMD`` into argv without mangling Windows paths.

    ``shlex.split`` in its default POSIX mode treats a backslash as an escape,
    so ``D:\\a\\waxseal\\.venv\\Scripts\\python.exe fake_signer.py`` came out
    as ``DawaxsealvenvScriptspython.exe`` and every Windows CI job failed the
    entire ledger-write surface with WinError 2 (0.1.5 MR, 01/09/2026 — masked
    until then because an earlier failing step always stopped the suite first).
    On Windows a backslash is a path separator, never an escape: split in
    non-POSIX mode, which preserves it, then strip the double quotes non-POSIX
    mode leaves attached so a spaced path is still one argv element.
    """
    import shlex

    if not windows:
        return shlex.split(command)
    parts = shlex.split(command, posix=False)
    return [
        part[1:-1] if len(part) >= 2 and part[0] == '"' and part[-1] == '"' else part
        for part in parts
    ]


class ExternalEvmSigner:
    """A ``TransactionSigner`` (ports/ledger.py) that shells out to an
    operator-supplied program named by ``WAXSEAL_EVM_SIGNER_CMD`` — never a
    key on argv or in an env var carrying key material (CLAUDE.md; this
    boundary is the same one ``WAXSEAL_API_KEY``/``WAXSEAL_WITNESS_API_KEY``
    already draw for credentials). This process holds no crypto library
    (rule 1), so it cannot sign anything itself; everything it needs from a
    signer is three operations, and this class defines the small CLI
    sub-protocol an external program must answer to supply them:

      * ``<cmd> address``               -> the signer's 0x address, on stdout.
      * ``<cmd> sign-digest 0x<hex>``    -> a 65-byte r‖s‖v signature over
        exactly those 32 bytes (RAW, not re-hashed — ``cast wallet sign
        --no-hash`` in Foundry's own terms: the contract recomputes its own
        digest and must recover this signer's address from it directly),
        0x-hex on stdout.
      * ``<cmd> sign-tx``                -> the fields ``EvmLedgerSink``
        assembles for a transaction (``type``, ``chainId``, ``nonce``,
        ``to``, ``value``, ``data``, ``gas``, ``maxFeePerGas``,
        ``maxPriorityFeePerGas``, ``accessList``), as a JSON object on
        STDIN; a raw RLP-encoded signed transaction, 0x-hex, on stdout.

    ``tests/adapters/test_evm_anvil.py``'s ``CastSigner`` shows the two
    concrete operations a real signer needs to perform (``cast wallet sign
    --no-hash`` and ``cast mktx``); this class is the three-verb CLI wrapper
    an operator's own script sits behind, so waxseal itself never touches
    ``cast`` or any other signing tool directly.
    """

    def __init__(self, command: str) -> None:
        self._command = command
        self.address = self._run("address")
        self.public_id = self.address

    def _argv(self, *args: str) -> list[str]:

        return [*_split_signer_command(self._command, windows=os.name == "nt"), *args]

    def _run(self, *args: str, input_text: str | None = None) -> str:

        from waxseal.ports.ledger import LedgerError

        try:
            completed = subprocess.run(  # noqa: S603 - argv list, no shell; the command is the operator's WAXSEAL_EVM_SIGNER_CMD
                self._argv(*args),
                input=input_text,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise LedgerError(
                f"WAXSEAL_EVM_SIGNER_CMD ({self._command!r}) could not run {args[0]!r}: {exc}"
            ) from exc
        if completed.returncode != 0:
            raise LedgerError(
                f"WAXSEAL_EVM_SIGNER_CMD {args[0]!r} exited {completed.returncode}: "
                f"{completed.stderr.strip()}"
            )
        return completed.stdout.strip()

    def _run_hex(self, *args: str, input_text: str | None = None) -> bytes:
        from waxseal.ports.ledger import LedgerError

        out = self._run(*args, input_text=input_text)
        text = out[2:] if out.startswith("0x") else out
        try:
            return bytes.fromhex(text)
        except ValueError as exc:
            raise LedgerError(
                f"WAXSEAL_EVM_SIGNER_CMD {args[0]!r} printed {out!r}, which is not hex"
            ) from exc

    def sign(self, digest32: bytes) -> bytes:
        return self._run_hex("sign-digest", "0x" + digest32.hex())

    def sign_transaction(self, fields: Mapping[str, object]) -> bytes:

        return self._run_hex("sign-tx", input_text=json.dumps(dict(fields)))


def _evm_signer() -> ExternalEvmSigner:

    from waxseal.ports.ledger import LedgerError

    command = os.environ.get("WAXSEAL_EVM_SIGNER_CMD")
    if not command:
        raise LedgerError(_WAXSEAL_EVM_SIGNER_CMD_MISSING)
    return ExternalEvmSigner(command)


def _evm_write_sink(
    rpc_urls: list[str] | None, contracts: EvmContracts, write_rpc: str | None
) -> tuple[EvmLedgerSink, ExternalEvmSigner]:
    """The sink every ledger WRITE command builds from: a reader (needed for
    its own multi-endpoint invariant and contract-address bookkeeping, per
    ``EvmLedgerSink``'s own constructor) plus the operator's external signer.
    One signer instance plays both roles ``EvmAnchorSink`` keeps separate
    (digest signer, transaction signer) — a real deployment wanting two
    different keys runs two different ``WAXSEAL_EVM_SIGNER_CMD``-backed CLI
    invocations instead, which this bead does not need to plumb through."""
    from waxseal.adapters.evm import EvmLedgerReader, EvmLedgerSink

    reader = EvmLedgerReader(rpc_urls or [], contracts)
    signer = _evm_signer()
    return EvmLedgerSink(reader, signer, rpc_url=write_rpc), signer


def _evm_write_url(rpc_urls: list[str] | None, write_rpc: str | None) -> str:
    if write_rpc is not None:
        return write_rpc
    assert rpc_urls  # _evm_write_sink's EvmLedgerReader construction already validated len>=2
    return rpc_urls[0]


def _eth_chain_id(url: str) -> int:
    """The EVM numeric chain id at ``url``, fetched through the PUBLIC
    Transport surface (adapters/remote.py) rather than by reaching into
    ``EvmLedgerSink``'s own private request-building (``_send``/``_rpc`` are
    internal to adapters/evm.py — the same encapsulation boundary the audit
    trail's own backend attribute draws, extended here to the ledger
    adapter). Printed
    before every ledger write (see ``_describe_write``) so an operator can
    confirm which network is about to receive a transaction before it does.
    """

    from waxseal.adapters.remote import RemoteRequest, urllib_transport
    from waxseal.ports.ledger import LedgerError

    transport = urllib_transport(timeout=10.0)
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []}).encode()
    request = RemoteRequest("POST", url, {"content-type": "application/json"}, body)
    try:
        response = transport(request)
        payload = json.loads(response.body)
        if not isinstance(payload, dict) or "result" not in payload:
            raise LedgerError(f"{url}: eth_chainId: unexpected response {payload!r}")
        return int(payload["result"], 16)
    except (OSError, ValueError) as exc:
        raise LedgerError(f"{url}: could not determine chain id before sending: {exc}") from exc


def _describe_write(*, rpc_url: str, contract: str, action: str) -> None:
    """Print what is about to be sent before it is sent (CLAUDE.md's F4
    plan: "mỗi lệnh ghi in rõ chain id + contract + tx trước khi gửi" —
    every write command names its network, its contract, and its action
    before broadcasting anything)."""
    print(f"chain_id={_eth_chain_id(rpc_url)} contract={contract} action={action} rpc={rpc_url}")


def _registry_publish(
    *, descriptor_of: str, registry_addr: str, rpc_urls: list[str] | None, write_rpc: str | None
) -> int:
    """`waxseal registry publish` (F4). NOT a chain-entry append — the same
    footing `anchor` already has (CLAUDE.md's CLI contract forbids the CLI
    writing to the audit TRAIL, not to an external ledger). The descriptor
    bytes come from this build's own ``VersionRegistry``, never from the
    operator: ``--descriptor-of`` only names WHICH fingerprint to publish,
    and the contract computes ``sha256(descriptor)`` itself, so there is no
    argument here that could disagree with the bytes sent.
    """
    from waxseal.adapters.evm import EvmContracts
    from waxseal.domain.registry import VersionRegistry, descriptor_frame
    from waxseal.ports.ledger import LedgerError

    registry = VersionRegistry()
    if not registry.knows(descriptor_of):
        print(
            f"error: {descriptor_of!r} is not a fingerprint this build's VersionRegistry "
            "holds field names for — nothing to publish",
            file=sys.stderr,
        )
        return 1
    descriptor = descriptor_frame(registry.fields(descriptor_of))

    try:
        sink, _signer = _evm_write_sink(rpc_urls, EvmContracts(registry=registry_addr), write_rpc)
    except (ValueError, LedgerError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    try:
        _describe_write(
            rpc_url=_evm_write_url(rpc_urls, write_rpc),
            contract=registry_addr,
            action=f"register(fingerprint={descriptor_of})",
        )
        tx_hash = sink.register_fingerprint(descriptor)
    except (OSError, ValueError, LedgerError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(f"tx={tx_hash}")
    return 0


def _bond_deposit(
    *, bond_addr: str, rpc_urls: list[str] | None, write_rpc: str | None, amount_wei: int
) -> int:
    """`waxseal bond deposit` (F4). NOT a chain-entry append (see
    `_registry_publish`'s docstring — same footing as `anchor`)."""
    from waxseal.adapters.evm import EvmContracts
    from waxseal.ports.ledger import LedgerError

    if amount_wei <= 0:
        print(f"error: --amount-wei must be positive, got {amount_wei}", file=sys.stderr)
        return 1
    try:
        sink, _signer = _evm_write_sink(rpc_urls, EvmContracts(bond=bond_addr), write_rpc)
    except (ValueError, LedgerError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    try:
        _describe_write(
            rpc_url=_evm_write_url(rpc_urls, write_rpc),
            contract=bond_addr,
            action=f"deposit(amount_wei={amount_wei})",
        )
        tx_hash = sink.deposit_bond(amount_wei)
    except (OSError, ValueError, LedgerError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(f"tx={tx_hash}")
    return 0


def _strip_0x(value: str) -> str:
    return value[2:] if value.startswith("0x") else value


def _checkpoint_from_json(raw: Any) -> Checkpoint:
    if not isinstance(raw, dict):
        raise ValueError(f"a checkpoint must be a JSON object, got {type(raw).__name__}")
    return Checkpoint(seq=int(raw["seq"]), entry_hash=raw["entry_hash"], root=raw["root"])


def _divergent_leaf_from_json(raw: Any) -> DivergentLeaf:
    if not isinstance(raw, dict):
        raise ValueError(f"a leaf claim must be a JSON object, got {type(raw).__name__}")
    return DivergentLeaf(
        index=int(raw["index"]),
        entry_hash=raw["entry_hash"],
        proof=tuple(_strip_0x(p) for p in raw.get("proof", ())),
    )


def _bond_prove(
    *, bond_addr: str, rpc_urls: list[str] | None, write_rpc: str | None, proof_path: Path
) -> int:
    """`waxseal bond prove <proof.json>` (F4). NOT a chain-entry append (see
    `_registry_publish`'s docstring).

    Two proof shapes, ONE entry point. Both are domain proof objects and both
    go through `EvmLedgerSink.submit_fraud_proof`, which validates each
    before spending gas. Through 0.1.5 the non-extension half could not:
    `domain.bond.NonExtensionProof` then modelled a consistency-proof
    challenge the deployed contract does not accept, so this path assembled
    adapter-level leaf claims and called a second, unvalidated entry point.
    The asymmetry domain/bond.py describes is between the two KINDS of
    evidence, not between two ways out of this file.
    """

    from waxseal.adapters.evm import EvmContracts
    from waxseal.domain.bond import EquivocationProof, NonExtensionProof
    from waxseal.ports.ledger import LedgerError

    try:
        raw = json.loads(proof_path.read_text())
    except OSError as e:
        print(f"error: cannot read {proof_path}: {e}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as e:
        print(f"error: {proof_path} is not valid JSON: {e}", file=sys.stderr)
        return 1

    kind = raw.get("kind") if isinstance(raw, dict) else None
    if kind not in ("equivocation", "non_extension"):
        print(
            f"error: {proof_path}: 'kind' must be 'equivocation' or 'non_extension', "
            f"got {kind!r}",
            file=sys.stderr,
        )
        return 1

    try:
        if kind == "equivocation":
            equivocation: EquivocationProof | None = EquivocationProof(
                chain_id=raw["chain_id"],
                checkpoint_a=_checkpoint_from_json(raw["checkpoint_a"]),
                signature_a=bytes.fromhex(_strip_0x(raw["signature_a"])),
                checkpoint_b=_checkpoint_from_json(raw["checkpoint_b"]),
                signature_b=bytes.fromhex(_strip_0x(raw["signature_b"])),
            )
            non_extension: NonExtensionProof | None = None
        else:
            equivocation = None
            non_extension = NonExtensionProof(
                chain_id=raw["chain_id"],
                older=_checkpoint_from_json(raw["older"]),
                newer=_checkpoint_from_json(raw["newer"]),
                older_signature=bytes.fromhex(_strip_0x(raw["older_signature"])),
                newer_signature=bytes.fromhex(_strip_0x(raw["newer_signature"])),
                in_older=_divergent_leaf_from_json(raw["in_older"]),
                in_newer=_divergent_leaf_from_json(raw["in_newer"]),
            )
    except (KeyError, TypeError, ValueError) as e:
        print(f"error: {proof_path}: malformed {kind} proof: {e}", file=sys.stderr)
        return 1

    try:
        sink, _signer = _evm_write_sink(rpc_urls, EvmContracts(bond=bond_addr), write_rpc)
    except (ValueError, LedgerError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    try:
        write_url = _evm_write_url(rpc_urls, write_rpc)
        if equivocation is not None:
            _describe_write(rpc_url=write_url, contract=bond_addr, action="proveEquivocation")
            tx_hash = sink.submit_fraud_proof(equivocation)
        else:
            assert non_extension is not None
            _describe_write(rpc_url=write_url, contract=bond_addr, action="proveNonExtension")
            tx_hash = sink.submit_fraud_proof(non_extension)
    except (KeyError, TypeError, ValueError, OSError, LedgerError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(f"tx={tx_hash}")
    return 0
