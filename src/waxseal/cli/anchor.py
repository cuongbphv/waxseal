from __future__ import annotations

import json
import sys
from collections.abc import Sequence
from pathlib import Path

from waxseal.adapters.remote import RemoteError
from waxseal.cli._anchors import _witness_api_key
from waxseal.cli.ledger import (
    _evm_write_sink,
)
from waxseal.domain.checkpoint import Checkpoint
from waxseal.log import AuditLog


def _anchor(
    log: AuditLog,
    trail: Path,
    *,
    witnesses: list[str] | None = None,
    tsa_url: str | None = None,
    ots_calendar: str | None = None,
    evm_rpc: list[str] | None = None,
    evm_liveness: str | None = None,
    evm_write_rpc: str | None = None,
    evm_trail_id: str | None = None,
    evm_consistency_proof_file: Path | None = None,
) -> int:

    from waxseal.adapters.anchors import MultiAnchorSink
    from waxseal.adapters.attest import AggregateReader
    from waxseal.ports.ledger import LedgerError

    # Read-only: binding the accumulator into the checkpoint needs the bytes
    # on disk, not the seal key the CLI deliberately never holds. Anchoring a
    # sealed trail without the binding would publish a chain shape nothing
    # ties back to the seals.
    try:
        sink = _anchor_sink(
            trail,
            tsa_url=tsa_url,
            ots_calendar=ots_calendar,
            evm_rpc=evm_rpc,
            evm_liveness=evm_liveness,
            evm_write_rpc=evm_write_rpc,
            evm_trail_id=evm_trail_id,
            evm_consistency_proof_file=evm_consistency_proof_file,
        )
    except (ValueError, LedgerError, OSError, json.JSONDecodeError) as e:
        # Preparing the EVM sink (bad --evm-rpc count, WAXSEAL_EVM_SIGNER_CMD
        # missing or failing, an unreadable/malformed consistency-proof
        # file) fails BEFORE any transaction exists to fail loudly later —
        # nothing was sent, nothing recorded, same as the "no anchor_sink"
        # ValueError case below.
        print(f"error: could not prepare the anchor sink: {e}", file=sys.stderr)
        return 1
    anchored = log.with_anchor_sink(sink, aggregate_source=AggregateReader(trail))
    try:
        cp = anchored.anchor()
    except ValueError as e:
        # Both sources ("no anchor_sink", "cannot anchor an empty trail") name
        # something the operator can act on. A bare non-zero exit does not.
        print(f"error: {e}", file=sys.stderr)
        return 1
    except (OSError, RuntimeError) as e:
        # An external sink that could not publish. RecordingAnchorSink wrote
        # nothing, so the sidecar still says what it said before, and an operator
        # who sees this must not believe a third party holds this checkpoint.
        # With two independent sinks configured this only fires when BOTH
        # failed (MultiAnchorSink's own contract): if either one held, the
        # loop below reports it instead of this all-or-nothing message.
        print(f"error: external anchor failed, nothing recorded: {e}", file=sys.stderr)
        return 1
    record: dict[str, object] = {"seq": cp.seq, "entry_hash": cp.entry_hash, "root": cp.root}
    if cp.agg_commit is not None:
        record["agg_commit"] = cp.agg_commit
        record["agg_epoch"] = cp.agg_epoch
    print(json.dumps(record))

    # waxseal-4yk: --tsa-url and --ots-calendar publish the SAME checkpoint to
    # two independent domains now (tau rises by one per domain reached, per
    # the anchor-selection corollary). One sink being unreachable must not
    # cost the other its record (CLAUDE.md rule 6): MultiAnchorSink already
    # let the reachable sink's record land; this only has to label the one
    # that didn't, in the same "error: ... nothing recorded" wording the
    # single-sink path above uses for a total failure.
    failed = False
    if isinstance(sink, MultiAnchorSink):
        for name, reason in sink.failures:
            print(
                f"error: external anchor failed, nothing recorded for {name}: {reason}",
                file=sys.stderr,
            )
            failed = True

    if not witnesses:
        return 1 if failed else 0
    witness_rc = _publish_to_witnesses(cp, witnesses)
    return 1 if (failed or witness_rc) else 0


def _anchor_sink(
    trail: Path,
    *,
    tsa_url: str | None,
    ots_calendar: str | None,
    evm_rpc: list[str] | None = None,
    evm_liveness: str | None = None,
    evm_write_rpc: str | None = None,
    evm_trail_id: str | None = None,
    evm_consistency_proof_file: Path | None = None,
) -> object:
    """The sink `anchor` publishes through.

    With no external target this stays the local sidecar it has always been.
    a queue and a local cross-check, explicitly not an independent witness
    (adapters/anchors.py says so). With one, the sidecar becomes the filing
    cabinet for a receipt somebody else issued, which is the only version of
    this that survives an attacker holding the disk. With more than one
    (waxseal-4yk added --tsa-url + --ots-calendar; F4 adds --evm-liveness as
    a third), a ``MultiAnchorSink`` fans the SAME checkpoint (computed once
    by ``AuditLog.anchor()``) out to every independently-recording sink, so
    one run reaches several independent trust domains instead of requiring
    one run per domain.
    """

    from waxseal.adapters.anchors import FileAnchorSink, MultiAnchorSink, RecordingAnchorSink

    sinks: list[object] = []
    if tsa_url is not None:
        from waxseal.adapters.rfc3161 import Rfc3161AnchorSink

        sinks.append(RecordingAnchorSink(trail, Rfc3161AnchorSink(tsa_url)))
    if ots_calendar is not None:
        from waxseal.adapters.ots import OtsAnchorSink

        sinks.append(RecordingAnchorSink(trail, OtsAnchorSink(ots_calendar)))
    if evm_liveness is not None:
        from waxseal.adapters.evm import EvmAnchorSink, EvmContracts

        trail_id = evm_trail_id if evm_trail_id is not None else str(trail.resolve())
        proof: tuple[str, ...] = ()
        if evm_consistency_proof_file is not None:
            proof = tuple(json.loads(evm_consistency_proof_file.read_text(encoding="utf-8")))
        ledger_sink, digest_signer = _evm_write_sink(
            evm_rpc, EvmContracts(liveness=evm_liveness), evm_write_rpc
        )

        def _fixed_consistency_proof(
            _cp: Checkpoint, _proof: tuple[str, ...] = proof
        ) -> Sequence[str]:
            # `_proof` is bound as a default argument, not read from the
            # enclosing scope at call time: closing over a loop/branch
            # variable directly is the classic late-binding bug, and this
            # function is itself only ever built once per `_anchor_sink`
            # call, but the default-argument form costs nothing and rules
            # the bug class out rather than relying on that.
            return _proof

        sinks.append(
            RecordingAnchorSink(
                trail,
                EvmAnchorSink(
                    ledger_sink,
                    trail_id,
                    digest_signer,
                    proof_fn=_fixed_consistency_proof if proof else None,
                ),
            )
        )
    # len(sinks) > 1, not == 2: --evm-liveness makes a THIRD independently-
    # recording sink possible alongside --tsa-url/--ots-calendar, and
    # MultiAnchorSink itself already accepts any number >= 2 (its own
    # constructor only refuses fewer). The old `== 2` here would have
    # silently dropped every sink past the first two once this bead added a
    # third — never exercised until this bead, because only two existed.
    if len(sinks) > 1:
        return MultiAnchorSink(sinks)
    if sinks:
        return sinks[0]
    return FileAnchorSink(trail)


def _publish_to_witnesses(cp: Checkpoint, urls: list[str]) -> int:
    """Publish one checkpoint to every configured witness.

    A failed publish exits 1. Unlike automatic anchoring, which is
    best-effort because it must never break an append, this was asked for
    explicitly, and an operator who ran `anchor --witness` and got exit 0 is
    entitled to believe the witness has it.
    """
    from waxseal.adapters.witness import HTTPWitness

    failed = False
    for url in urls:
        witness = HTTPWitness(url, api_key=_witness_api_key())
        try:
            receipt = witness.anchor(cp)
        except (OSError, RemoteError, RuntimeError) as e:
            # stdout like every other verdict this CLI prints: an operator
            # piping the output to a log must not lose the one line saying
            # the checkpoint never left the machine.
            print(f"WITNESS PUBLISH FAILED {witness.name}: {e}")
            failed = True
            continue
        suffix = f" (receipt {receipt})" if receipt is not None else " (no receipt given)"
        print(f"published to witness {witness.name}{suffix}")
    return 1 if failed else 0
