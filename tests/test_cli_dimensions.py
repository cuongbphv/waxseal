"""The measurement `verify` and `report` share before either checks the pin.

`_verify` and `_report` each measured the anchor, witness and ledger
dimensions with the same lines and handed the same eight observations to
`_pin_check`. Two copies of a measurement that feeds a declared-vs-observed
comparison is how two commands come to disagree about one trail; these tests
pin the single seam both now go through.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from waxseal import AuditLog
from waxseal.cli import _dimensions, report, verify
from waxseal.cli._common import _Check
from waxseal.domain.report import CheckSummary


def _trail(path: Path) -> AuditLog:
    log = AuditLog.open(path)
    for i in range(3):
        log.append(payload={"i": i}, payload_type="test")
    return log


def _now() -> datetime:
    return datetime(2026, 9, 8, tzinfo=UTC)


def test_verify_and_report_both_measure_through_the_shared_seam() -> None:
    assert vars(verify)["_observe"] is _dimensions._observe
    assert vars(report)["_observe"] is _dimensions._observe


def test_nothing_requested_measures_nothing(tmp_path: Path) -> None:
    # Rule 5: a dimension that was not asked for is None ("not measured"),
    # never False or 0, so `_pin_check` sees "no evidence" rather than
    # "evidence against".
    trail = tmp_path / "trail.jsonl"
    log = _trail(trail)
    _result, entries = log._verify_and_entries()
    observed = _dimensions._observe(
        log,
        trail,
        entries,
        [e.entry_hash for e in entries],
        check_anchors=False,
        tsa_ca_file=None,
        witnesses=None,
        ledger_rpc_urls=None,
        ledger_liveness=None,
        ledger_registry=None,
        ledger_trail_id=None,
        now_fn=_now,
    )
    assert observed == _dimensions._Observed()


def test_anchors_are_measured_only_for_a_local_trail(tmp_path: Path) -> None:
    # trail is None only for a URL target: main() already forces check_anchors
    # off there, and the seam keeps that invariant even if a caller forgets.
    log = _trail(tmp_path / "trail.jsonl")
    _result, entries = log._verify_and_entries()
    observed = _dimensions._observe(
        log,
        None,
        entries,
        [e.entry_hash for e in entries],
        check_anchors=True,
        tsa_ca_file=None,
        witnesses=None,
        ledger_rpc_urls=None,
        ledger_liveness=None,
        ledger_registry=None,
        ledger_trail_id=None,
        now_fn=_now,
    )
    assert observed.anchor_check is None
    assert observed.anchor_sinks is None


def test_the_pin_check_receives_every_observation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    seen: dict[str, Any] = {}
    check = _Check(CheckSummary(ok=True, checked=0), "stub")

    def fake_pin_check(log: AuditLog, pin_path: Path, **kwargs: Any) -> tuple[_Check, None]:
        seen.update(kwargs)
        return check, None

    monkeypatch.setattr(_dimensions, "_pin_check", fake_pin_check)
    ledger = _Check(CheckSummary(ok=True, checked=1), "ledger")
    observed = _dimensions._Observed(
        anchor_check=check,
        anchor_sinks=2,
        anchor_records=(),
        anchor_unreadable=False,
        witness_verdicts=[],
        witness_consistent=True,
        ledger_check=ledger,
        ledger_ok=True,
    )
    log = _trail(tmp_path / "trail.jsonl")
    result = observed.pin_check(
        log,
        tmp_path / "pin.json",
        target="trail.jsonl",
        chain_id=None,
        now_fn=_now,
        declare_expect_anchor_binding=True,
        declare_max_anchor_age_s=60,
        declare_topology=None,
        hashes=["a"],
    )
    assert result == (check, None)
    assert seen == {
        "target": "trail.jsonl",
        "chain_id": None,
        "now_fn": _now,
        "observed_anchor_sinks": 2,
        "observed_witness_consistent": True,
        "observed_anchor_records": (),
        "observed_anchor_unreadable": False,
        "declare_expect_anchor_binding": True,
        "declare_max_anchor_age_s": 60,
        "declare_topology": None,
        "observed_ledger_ok": True,
        "hashes": ["a"],
    }
