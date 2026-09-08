from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from waxseal.cli._anchors import (
    _print_drop_count,
    _receipts_check,
    _tau_line,
    _witness_exit_code,
    _witness_line,
)
from waxseal.cli._common import _combine, _default_now
from waxseal.cli._dimensions import _observe
from waxseal.cli.pin import _save_pin
from waxseal.domain.pinning import PinState
from waxseal.domain.separation import (
    SeparationTopology,
)
from waxseal.log import AuditLog


def _verify(
    log: AuditLog,
    trail: Path | None,
    *,
    check_anchors: bool = False,
    is_url: bool = False,
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
    # A CLI process saw no writes, so it cannot measure drops (None, not 0).
    # One materializing pass: the chain verdict and the hashes every later
    # dimension (anchors, witnesses, pin, receipts, ledger) is computed over.
    # Each of those used to call entry_hashes() on its own, rematerializing
    # the same trail (P1 / test_perf_receipts.TestVerifyReadsHashesOnce).
    result, entries = log._verify_and_entries()
    hashes = [e.entry_hash for e in entries]
    codes = [0]
    if not result.ok:
        print(f"BROKEN at seq={result.broken_seq}: {result.reason} (checked={result.checked})")
        codes.append(1)
    elif result.unverifiable:
        print(
            f"ok (checked={result.checked}) but {len(result.unverifiable)} unverifiable "
            f"row(s) at seq={list(result.unverifiable)} — unknown schema fingerprint, "
            "NOT evidence of tampering"
        )
        codes.append(2)
    else:
        print(f"ok (checked={result.checked})")
        if is_url and result.checked == 0:
            # GET /entries 404 means "empty" identically for a genuinely
            # fresh chain and for a mistyped chain_id/wrong path, unlike a
            # local path, there is no Path.exists() probe to tell them apart.
            # A bare "ok" here would let a typo silently verify nothing while
            # looking successful (CLAUDE.md rule 6: a degraded guard must be
            # labelled, never silent).
            print(
                "note: checked=0 for a remote URL target is indistinguishable "
                "from a wrong chain_id/path — this cannot confirm the chain "
                "you intended is actually reachable and non-empty"
            )
    _print_drop_count(trail)

    # Every remaining dimension is checked even when an earlier one already
    # failed: an operator investigating a break needs to know whether the pin
    # and the anchors agree with it, not just that the run stopped.
    #
    # Anchors and witnesses are MEASURED here, ahead of the pin check, so
    # _pin_check can compare a declared_topology against what this run
    # actually observed (waxseal-7tk.3.2). Each dimension's own line still
    # PRINTS in the original order (pin, then anchors, then witnesses), so
    # only the underlying computation moved earlier, not the output.
    observed = _observe(
        log,
        trail,
        entries,
        hashes,
        check_anchors=check_anchors,
        tsa_ca_file=tsa_ca_file,
        witnesses=witnesses,
        ledger_rpc_urls=ledger_rpc_urls,
        ledger_liveness=ledger_liveness,
        ledger_registry=ledger_registry,
        ledger_trail_id=ledger_trail_id,
        now_fn=now_fn,
    )

    pending_pin: PinState | None = None
    if pin_path is not None:
        check, pending_pin = observed.pin_check(
            log,
            pin_path,
            target=target,
            chain_id=chain_id,
            now_fn=now_fn,
            declare_expect_anchor_binding=declare_expect_anchor_binding,
            declare_max_anchor_age_s=declare_max_anchor_age_s,
            declare_topology=declare_topology,
            hashes=hashes,
        )
        print(check.line)
        codes.append(check.exit_code)

    if observed.anchor_check is not None:
        print(observed.anchor_check.line)
        # Anchor breakage escalates to 1 regardless of the chain's own exit
        # code: it is still "broken", just a different dimension of it.
        codes.append(observed.anchor_check.exit_code)

    if observed.witness_verdicts is not None:
        for verdict in observed.witness_verdicts:
            print(_witness_line(verdict))
        codes.append(_witness_exit_code(observed.witness_verdicts))

    if observed.ledger_check is not None:
        # Printed here, in the ORIGINAL position, even though it was
        # computed earlier above: only the computation moved, matching the
        # anchor_check/witness_verdicts precedent this function already
        # follows for the same reason.
        print(observed.ledger_check.line)
        codes.append(observed.ledger_check.exit_code)

    receipts_check = _receipts_check(log, trail, hashes=hashes)
    print(receipts_check.line)
    codes.append(receipts_check.exit_code)

    # τ (waxseal-mfi, closing conformance.md gap G1): printed unconditionally,
    # never only when --pin is given: "not declared" must be as loud as any
    # other rule-5 "not measured" state, not something an operator only sees
    # by asking. `None` when no --pin was given, or the pin carries no
    # declared_topology; never inferred as 0 or 1 either way.
    declared_topology = pending_pin.declared_topology if pending_pin is not None else None
    print(_tau_line(declared_topology))

    code = _combine(codes)
    if pending_pin is not None and code != 1:
        # Only exit 1 (broken) freezes the pin, since advancing then would launder
        # the break into the new baseline. Exit 2 DOES advance (SPEC.md
        # section 13): unverifiable is not tampered, and refusing to pin a
        # trail with unknown fingerprints would disable pinning for exactly
        # the forward-compatible case this library exists for.
        _save_pin(pin_path, pending_pin)
    return code
