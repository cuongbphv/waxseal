"""What one `verify` or `report` run OBSERVES before it checks the pin.

`_verify` and `_report` each measured the anchor, witness and ledger
dimensions with the same lines, then handed the same eight observations to
`_pin_check`. Two copies of a measurement that feeds a declared-vs-observed
comparison (waxseal-7tk.3.2) is how two commands come to disagree about one
trail; this module is the one place the measurement happens. Printing and
rendering stay with the callers: `verify` prints each dimension's line in its
own frozen order, `report` folds them into one document.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
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
    _witness_verdicts,
)
from waxseal.cli._common import _Check
from waxseal.cli.ledger import _ledger_check
from waxseal.cli.pin import _pin_check
from waxseal.domain.header import Entry
from waxseal.domain.pinning import PinState
from waxseal.domain.separation import SeparationTopology
from waxseal.domain.witnessing import WitnessVerdict
from waxseal.log import AuditLog


@dataclass(frozen=True, slots=True)
class _Observed:
    """One run's measurements. ``None`` throughout means "not measured", never
    "measured clean" or "measured absent" (rule 5): `_pin_check` compares a
    declared topology only against dimensions that were actually observed."""

    anchor_check: _Check | None = None
    anchor_sinks: int | None = None
    anchor_records: tuple[AnchorRecord, ...] | None = None
    anchor_unreadable: bool | None = None
    witness_verdicts: list[WitnessVerdict] | None = None
    witness_consistent: bool | None = None
    ledger_check: _Check | None = None
    ledger_ok: bool | None = None

    def pin_check(
        self,
        log: AuditLog,
        pin_path: Path,
        *,
        target: str | None,
        chain_id: str | None,
        now_fn: Callable[[], datetime],
        declare_expect_anchor_binding: bool,
        declare_max_anchor_age_s: int | None,
        declare_topology: SeparationTopology | None,
        hashes: list[str],
    ) -> tuple[_Check, PinState | None]:
        assert target is not None  # main() always passes both together
        return _pin_check(
            log,
            pin_path,
            target=target,
            chain_id=chain_id,
            now_fn=now_fn,
            observed_anchor_sinks=self.anchor_sinks,
            observed_witness_consistent=self.witness_consistent,
            observed_anchor_records=self.anchor_records,
            observed_anchor_unreadable=self.anchor_unreadable,
            declare_expect_anchor_binding=declare_expect_anchor_binding,
            declare_max_anchor_age_s=declare_max_anchor_age_s,
            declare_topology=declare_topology,
            observed_ledger_ok=self.ledger_ok,
            hashes=hashes,
        )


def _observe(
    log: AuditLog,
    trail: Path | None,
    entries: list[Entry],
    hashes: list[str],
    *,
    check_anchors: bool,
    tsa_ca_file: Path | None,
    witnesses: list[str] | None,
    ledger_rpc_urls: list[str] | None,
    ledger_liveness: str | None,
    ledger_registry: str | None,
    ledger_trail_id: str | None,
    now_fn: Callable[[], datetime],
) -> _Observed:
    """Measure the anchor, witness and ledger dimensions, in that order, over
    the ``entries``/``hashes`` one materializing pass already produced."""
    anchor_check: _Check | None = None
    observed_anchor_sinks: int | None = None
    observed_anchor_records: tuple[AnchorRecord, ...] | None = None
    observed_anchor_unreadable: bool | None = None
    # trail is None only for a URL target, and main() already forces
    # check_anchors False in that case (no local sidecar to check), and this
    # guard just makes that invariant visible to mypy, not a new behavior.
    if check_anchors and trail is not None:
        anchor_check = _anchor_check(log, trail, tsa_ca_file=tsa_ca_file, hashes=hashes)
        observed_anchor_sinks = _observed_anchor_sinks(trail)
        observed_anchor_records = _observed_anchor_records(trail)
        observed_anchor_unreadable = _observed_anchor_unreadable(trail)

    witness_verdicts: list[WitnessVerdict] | None = None
    observed_witness_consistent: bool | None = None
    if witnesses:
        witness_verdicts = _witness_verdicts(log, witnesses, hashes=hashes)
        observed_witness_consistent = _observed_witness_consistent(witness_verdicts)

    # Ledger (waxseal-fg4.45), measured here for the same reason anchors and
    # witnesses already are above: `_pin_check` needs THIS run's ledger
    # result to compare against a declared_topology.ledger, and can only do
    # that if the check has already run by the time `_pin_check` is called.
    # F4 originally computed this AFTER `_pin_check` (still true in the
    # `report` builder below at the time of writing) — printing was
    # unaffected either way, since `_ledger_check` is idempotent, but the
    # comparison inside `_pin_check` was structurally unreachable: nothing
    # had been measured yet for it to read.
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

    return _Observed(
        anchor_check=anchor_check,
        anchor_sinks=observed_anchor_sinks,
        anchor_records=observed_anchor_records,
        anchor_unreadable=observed_anchor_unreadable,
        witness_verdicts=witness_verdicts,
        witness_consistent=observed_witness_consistent,
        ledger_check=ledger_check,
        ledger_ok=observed_ledger_ok,
    )
