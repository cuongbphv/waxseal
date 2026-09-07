from __future__ import annotations

import json
import sys
from collections.abc import Callable
from dataclasses import replace
from datetime import datetime
from pathlib import Path

from waxseal.adapters.anchors import AnchorRecord
from waxseal.cli._anchors import (
    _anchor_check,
    _observed_anchor_records,
    _observed_anchor_sinks,
    _observed_anchor_unreadable,
    _observed_ledger_ok,
    _observed_witness_consistent,
    _receipts_check,
    _witness_exit_code,
    _witness_verdicts,
)
from waxseal.cli._common import _Check, _combine, _default_now
from waxseal.cli.ledger import _ledger_check
from waxseal.cli.pin import _pin_check, _save_pin
from waxseal.cli.segments import _is_hex
from waxseal.domain.pinning import PinState
from waxseal.domain.report import (
    CheckSummary,
)
from waxseal.domain.separation import (
    SeparationTopology,
)
from waxseal.domain.verdict import Verdict
from waxseal.domain.witnessing import WitnessVerdict
from waxseal.log import AuditLog


def _report(
    log: AuditLog,
    trail: Path | None,
    *,
    check_anchors: bool,
    as_json: bool,
    pin_path: Path | None = None,
    target: str | None = None,
    chain_id: str | None = None,
    witnesses: list[str] | None = None,
    now_fn: Callable[[], datetime] = _default_now,
    declare_expect_anchor_binding: bool = False,
    declare_max_anchor_age_s: int | None = None,
    declare_topology: SeparationTopology | None = None,
    tsa_ca_file: Path | None = None,
    ledger_rpc_urls: list[str] | None = None,
    ledger_liveness: str | None = None,
    ledger_registry: str | None = None,
    ledger_trail_id: str | None = None,
) -> int:

    from waxseal.domain.report import build_report

    # One read pass for both halves: the verdict and the summary describe the
    # same bytes, and reading the trail twice to produce them made a read-only
    # command cost double on a large trail. dropped_writes stays None for the
    # same reason verify uses measure_drops=False: a CLI process observed no
    # writes, so it must report "not measured", never zero.
    result, entries = log._verify_and_entries()

    # Anchors and witnesses are measured before the pin check, same reorder
    # as _verify and for the same reason: _pin_check needs what this run
    # OBSERVED to compare against a declared_topology (waxseal-7tk.3.2).
    # build_report renders everything in one pass at the end, so, unlike
    # _verify, there is no per-check print order to preserve here.
    anchors: CheckSummary | None = None
    observed_anchor_sinks: int | None = None
    observed_anchor_records: tuple[AnchorRecord, ...] | None = None
    observed_anchor_unreadable: bool | None = None
    if check_anchors and trail is not None:
        anchors = _anchor_check(log, trail, tsa_ca_file=tsa_ca_file).summary
        observed_anchor_sinks = _observed_anchor_sinks(trail)
        observed_anchor_records = _observed_anchor_records(trail)
        observed_anchor_unreadable = _observed_anchor_unreadable(trail)

    witness_verdicts: tuple[WitnessVerdict, ...] | None = None
    observed_witness_consistent: bool | None = None
    if witnesses:
        witness_verdicts = tuple(_witness_verdicts(log, witnesses))
        observed_witness_consistent = _observed_witness_consistent(list(witness_verdicts))

    # Ledger (waxseal-fg4.45), measured here — before the pin check, same
    # reorder as _verify's and for the same reason: _pin_check needs THIS
    # run's ledger result to compare against a declared_topology.ledger.
    ledger_check: _Check | None = None
    observed_ledger_ok: bool | None = None
    if ledger_liveness is not None or ledger_registry is not None:
        assert ledger_trail_id is not None  # main() always fills this in
        ledger_check = _ledger_check(
            entries,
            rpc_urls=ledger_rpc_urls,
            liveness=ledger_liveness,
            registry=ledger_registry,
            trail_id=ledger_trail_id,
            now_fn=now_fn,
        )
        observed_ledger_ok = _observed_ledger_ok(ledger_check)

    pin: CheckSummary | None = None
    pending_pin: PinState | None = None
    if pin_path is not None:
        assert target is not None  # main() always passes both together
        pin_check, pending_pin = _pin_check(
            log,
            pin_path,
            target=target,
            chain_id=chain_id,
            now_fn=now_fn,
            observed_anchor_sinks=observed_anchor_sinks,
            observed_witness_consistent=observed_witness_consistent,
            observed_anchor_records=observed_anchor_records,
            observed_anchor_unreadable=observed_anchor_unreadable,
            declare_expect_anchor_binding=declare_expect_anchor_binding,
            declare_max_anchor_age_s=declare_max_anchor_age_s,
            declare_topology=declare_topology,
            observed_ledger_ok=observed_ledger_ok,
        )
        pin = pin_check.summary
    if trail is not None:
        from waxseal.adapters.drops import read_drop_count

        count = read_drop_count(trail)
        if count is not None:
            result = replace(result, dropped_writes=count, drops_source="sidecar")

    # Unconditional, exactly as in `_verify`: there is nothing external to
    # contact, and the absent case is the one an auditor most needs printed.
    # `report` had no receipts dimension at all until this, so the document
    # that outlives the terminal was the one place receipt coverage could not
    # be read off (waxseal-fg4.24).
    receipts = _receipts_check(log, trail).summary

    # τ (waxseal-mfi, closing conformance.md gap G1): `None` when no --pin was
    # given, or the pin carries no declared_topology: same rule as _verify's
    # own derivation, never inferred as 0 or 1 either way.
    declared_topology = pending_pin.declared_topology if pending_pin is not None else None

    # ledger_check itself was already computed above, before the pin check
    # (waxseal-fg4.45) — only its computation moved, matching `_verify`'s own
    # anchor_check/witness_verdicts precedent; nothing below this line reads
    # anything that was not already true before this bead.

    report = build_report(
        result,
        entries,
        anchors=anchors,
        pin=pin,
        witnesses=witness_verdicts,
        receipts=receipts,
        declared_topology=declared_topology,
    )
    # domain/report.py's AuditReport has no ledger field (F4 owns cli.py
    # only, not domain/**), so the ledger dimension is layered on at this
    # boundary instead: an extra top-level JSON key, additive and never
    # overwriting anything build_report already produced, and an extra
    # printed section after the markdown document for the text case.
    if as_json:
        payload = json.loads(report.to_json())
        if ledger_check is not None:
            payload["ledger"] = {
                "ok": ledger_check.verdict is not Verdict.BROKEN,
                "unverifiable": ledger_check.verdict is Verdict.UNVERIFIABLE,
                "detail": ledger_check.line,
            }
        print(json.dumps(payload))
    else:
        # to_markdown() already ends with a newline.
        print(report.to_markdown(), end="")
        if ledger_check is not None:
            print("\n## Ledger\n")
            print(ledger_check.line)

    codes = [0]
    if not result.ok:
        codes.append(1)
    elif result.unverifiable:
        codes.append(2)
    # receipts joins anchors/pin in the verdict, not only in the prose: a
    # document that prints RECEIPTS BROKEN and exits 0 is the collapse this
    # library exists to prevent, and `verify` has always counted it.
    for summary in (anchors, pin, receipts):
        if summary is not None:
            codes.append(_Check(summary, "").exit_code)
    if witness_verdicts is not None:
        codes.append(_witness_exit_code(list(witness_verdicts)))
    if ledger_check is not None:
        codes.append(ledger_check.exit_code)
    code = _combine(codes)
    if pending_pin is not None and code != 1:
        # Same rule as _verify's write site: only exit 1 freezes the pin;
        # exit 2 advances because unverifiable is not tampered (SPEC.md
        # section 13).
        _save_pin(pin_path, pending_pin)
    return code


def _export_proof(log: AuditLog, seq: int) -> int:
    from waxseal.domain.export import build_proof_bundle, bundle_to_json

    entries = list(log.entries())
    try:
        bundle = build_proof_bundle(entries, seq)
    except IndexError as e:
        # The operator named a row that is not there. Printing some other
        # row's proof would be worse than refusing.
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(bundle_to_json(bundle))
    return 0


def _verify_proof(bundle_path: Path) -> int:
    from waxseal.domain.export import bundle_from_json, verify_proof_bundle
    from waxseal.domain.registry import VersionRegistry

    try:
        text = bundle_path.read_text(encoding="utf-8")
    except OSError as e:
        # Same spirit as a missing trail: nothing was read, nothing created.
        print(f"error: cannot read bundle: {e}", file=sys.stderr)
        return 3
    try:
        bundle = bundle_from_json(text)
    except ValueError as e:
        # Includes a bundle format this build does not know. That is a
        # refusal to parse, deliberately not a tampering verdict, since the two
        # must never be spelled the same way.
        print(f"error: cannot read bundle: {e}", file=sys.stderr)
        return 1

    result = verify_proof_bundle(bundle, VersionRegistry())
    if not result.ok:
        print(f"BROKEN at seq={bundle.header.seq}: {result.reason}")
        return 1
    if result.unverifiable:
        print(
            f"ok: seq={bundle.header.seq} is in the anchored batch "
            f"(root {bundle.root[:12]}…), but its schema fingerprint "
            f"{bundle.header.hash_version[:12]}… is unknown to this build — "
            "the entry hash could NOT be independently recomputed. "
            "Unverifiable by name, NOT evidence of tampering."
        )
        return 2
    print(
        f"ok: seq={bundle.header.seq} verified against root {bundle.root[:12]}… "
        f"(batch of {bundle.batch_size})"
    )
    return 0


def _consistency(log: AuditLog, *, old_seq: int, old_root: str) -> int:
    """Does today's trail extend the state the operator recorded earlier?

    The check a pin file makes automatically, offered here for a head that
    was recorded ANYWHERE: a ticket, a signed release, another host's copy
    of `waxseal checkpoint` output. A failed proof is evidence of a split
    view or rewritten history; which side is honest is an operator's
    decision, never this command's (CLAUDE.md rule 4).
    """
    from waxseal.domain.anchoring import batch_root, consistency_proof, verify_consistency

    # Malformed inputs are screened out BEFORE proving: verify_consistency
    # fails closed on them, and reporting an operator's typo as INCONSISTENT
    # would manufacture split-view evidence out of a slipped key.
    if old_seq < 0:
        print(
            "unverifiable: --old-seq must be a seq the trail once reached (>= 0) — "
            "nothing was checked"
        )
        return 2
    if len(old_root) != 64 or not _is_hex(old_root):
        print(
            "unverifiable: --old-root is not a 64-character hex SHA-256 root — "
            "nothing was checked"
        )
        return 2

    hashes = log.entry_hashes()
    old_size = old_seq + 1
    if old_size > len(hashes):
        # Could be a truncated trail; could be a mistyped --old-seq. From
        # here the two are indistinguishable, and a proof over entries that
        # are not there cannot be computed, so this is "cannot check",
        # stated with the ambiguity, never a tampering pronouncement.
        print(
            f"unverifiable: --old-seq {old_seq} is beyond the current head "
            f"(seq {len(hashes) - 1 if hashes else 'none — empty trail'}) — a "
            "consistency proof cannot be computed. If that seq was truly recorded, "
            "a truncation is one explanation and a mistyped --old-seq is another; "
            "this command cannot tell them apart"
        )
        return 2

    proof = consistency_proof(hashes, old_size)
    new_root = batch_root(hashes)
    if verify_consistency(old_root, old_size, new_root, len(hashes), proof):
        print(
            f"consistent: the current head (seq {len(hashes) - 1}, root "
            f"{new_root[:12]}…) extends the recorded state at seq {old_seq} "
            f"(RFC 9162 consistency proof, {len(proof)} hash(es))"
        )
        return 0
    print(
        f"INCONSISTENT at seq 0..{old_seq}: the trail's first {old_size} entries "
        f"produce root {batch_root(hashes[:old_size])[:12]}…, not the recorded "
        f"{old_root[:12]}… — evidence of a split view or rewritten history; "
        "which state is honest is an operator's decision, this command only "
        "reports that the two cannot both be the same log"
    )
    return 1


def _verify_handoff(delegate_log: AuditLog, *, origin_path: Path) -> int:
    """Check every cross-trail handoff binding recorded on ``delegate_log``
    against ``origin_path``'s current history (SPEC D3; domain/handoff.py).

    Read-only against both trails, appending nothing (CLAUDE.md's CLI
    contract: "the CLI never appends chain entries"). ``binding_holds`` is a
    pure comparison against the origin trail's OWN current entry hashes, so
    a failure here is a genuinely detected mismatch (the origin's history no
    longer matches what the binding committed to at handoff time): exit 1,
    not exit 2's "unverifiable": unlike an unknown fingerprint, there is
    nothing ambiguous left to resolve once the hashes are in hand.
    """

    from waxseal.domain.handoff import (
        HANDOFF_PAYLOAD_TYPE,
        HandoffBinding,
        binding_holds,
        from_payload,
    )

    bindings: list[tuple[int, HandoffBinding]] = []
    for entry in delegate_log.entries():
        if entry.header.payload_type != HANDOFF_PAYLOAD_TYPE:
            continue
        if entry.payload is None:
            # Header-only reader (Entry's own contract: None means "not
            # available here", matching sources/decisions.py's/files.py's
            # treatment of the same case) -- unavailable to check is a
            # third answer, never "does not hold" (rule 5).
            print(
                f"seq {entry.header.seq}: handoff-binding payload unavailable "
                "to this reader — skipped, not checked"
            )
            continue
        bindings.append((entry.header.seq, from_payload(json.loads(entry.payload))))

    if not bindings:
        print("nothing to check: no handoff-binding entries on this trail")
        return 0

    if not origin_path.exists():
        print(f"error: no such origin trail: {origin_path}", file=sys.stderr)
        return 3

    origin_hashes = AuditLog.open(origin_path).entry_hashes()

    all_hold = True
    for seq, binding in bindings:
        holds = binding_holds(binding, origin_hashes)
        print(
            f"seq {seq}: binding to chain {binding.chain_id!r} seq {binding.seq} "
            f"({binding.head_hash[:12]}…) — {'holds' if holds else 'DOES NOT HOLD'}"
        )
        if not holds:
            all_hold = False

    if all_hold:
        print(f"all {len(bindings)} handoff binding(s) hold against {origin_path}")
        return 0
    print(
        f"at least one handoff binding no longer holds against {origin_path} — "
        "the origin trail's history no longer matches what was recorded at "
        "handoff time; which side is honest is an operator's decision "
        "(CLAUDE.md rule 4)"
    )
    return 1
