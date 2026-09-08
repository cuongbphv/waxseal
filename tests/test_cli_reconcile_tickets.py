"""CLI: `waxseal reconcile-tickets` — D2, exogenous admission tickets.

Wires domain/tickets.py's issued-vs-present reconciliation (the one
construction in the paper's re-analysis that turns a dropped write into one
*positively detected*) into a read-only subcommand, matching how every other
read-only capability here (`verify`, `report`, `checkpoint`, `consistency`)
is exposed. waxseal never issues a ticket; `--issued` is the operator's own
report of what the exogenous issuer actually granted.

Exit codes reuse `Verdict.to_exit_code()`: 0 = no positively-detected drop,
1 = a drop WAS positively detected (BROKEN), 2 = unmeasured — issuer data
unavailable or malformed input (never conflated with "0 drops").
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from waxseal import AuditLog
from waxseal.cli import main
from waxseal.domain.tickets import TICKET_PAYLOAD_TYPE, Ticket, to_payload

OTHER_PT = "application/vnd.test.event+json"


def trail_with_tickets(tmp_path: Path, issuer: str, ticket_ids: list[int]) -> Path:
    path = tmp_path / "trail.jsonl"
    log = AuditLog.open(path)
    for tid in ticket_ids:
        log.append(
            payload=to_payload(Ticket(issuer=issuer, ticket_id=tid)),
            payload_type=TICKET_PAYLOAD_TYPE,
        )
    return path


class TestPositivelyDetectedDrop:
    def test_missing_ticket_in_closed_window_exits_1_and_names_it(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # lease_size=4: ticket 2 never reached the trail; window [4,7] (the
        # open one) is fully present, so window [0,3] is closed and its gap
        # is a positive detection.
        path = trail_with_tickets(tmp_path, "iss", [0, 1, 3, 4])
        code = main(
            [
                "reconcile-tickets",
                str(path),
                "--issuer",
                "iss",
                "--lease-size",
                "4",
                "--issued",
                "0,1,2,3,4",
            ]
        )
        out = capsys.readouterr().out
        assert code == 1
        assert "2" in out
        assert "detected" in out.lower()

    def test_json_mode_names_the_missing_ticket(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = trail_with_tickets(tmp_path, "iss", [0, 1, 3, 4])
        code = main(
            [
                "reconcile-tickets",
                str(path),
                "--issuer",
                "iss",
                "--lease-size",
                "4",
                "--issued",
                "0,1,2,3,4",
                "--json",
            ]
        )
        payload = json.loads(capsys.readouterr().out)
        assert code == 1
        assert payload["missing"] == [2]
        assert payload["verdict"] == "broken"
        assert payload["measured"] is True


class TestBlindSpot:
    def test_open_window_never_reported_as_clean(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # Single open window [0,3]; ticket 0 present, 1/2/3 missing = L-1.
        path = trail_with_tickets(tmp_path, "iss", [0])
        code = main(
            [
                "reconcile-tickets",
                str(path),
                "--issuer",
                "iss",
                "--lease-size",
                "4",
                "--issued",
                "0-3",
            ]
        )
        out = capsys.readouterr().out
        assert code == 0  # not positively detected — still open
        assert "clean" not in out.lower()
        assert "blind spot" in out.lower()
        assert "1" in out and "2" in out and "3" in out

    def test_json_carries_blind_spot_fields(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = trail_with_tickets(tmp_path, "iss", [0])
        main(
            [
                "reconcile-tickets",
                str(path),
                "--issuer",
                "iss",
                "--lease-size",
                "4",
                "--issued",
                "0-3",
                "--json",
            ]
        )
        payload = json.loads(capsys.readouterr().out)
        assert payload["blind_spot_window"] == [0, 3]
        assert payload["blind_spot_missing"] == [1, 2, 3]
        assert payload["blind_spot_bound"] == 3


class TestIssuerUnreachable:
    def test_omitted_issued_is_unmeasured_exit_2_not_zero_drops(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = trail_with_tickets(tmp_path, "iss", [0, 1, 2])
        code = main(["reconcile-tickets", str(path), "--issuer", "iss", "--lease-size", "4"])
        out = capsys.readouterr().out
        assert code == 2
        assert "unmeasured" in out.lower()

    def test_json_reports_measured_false_with_null_counts(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = trail_with_tickets(tmp_path, "iss", [0, 1, 2])
        main(["reconcile-tickets", str(path), "--issuer", "iss", "--lease-size", "4", "--json"])
        payload = json.loads(capsys.readouterr().out)
        assert payload["measured"] is False
        assert payload["missing"] is None
        assert payload["blind_spot_missing"] is None
        assert payload["verdict"] == "unverifiable"


class TestMalformedInput:
    def test_malformed_issued_spec_is_unverifiable_not_a_crash(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = trail_with_tickets(tmp_path, "iss", [0])
        code = main(
            [
                "reconcile-tickets",
                str(path),
                "--issuer",
                "iss",
                "--lease-size",
                "4",
                "--issued",
                "not-a-number",
            ]
        )
        out = capsys.readouterr().out
        assert code == 2
        assert "unverifiable" in out.lower()

    def test_backwards_range_in_issued_spec_is_unverifiable(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = trail_with_tickets(tmp_path, "iss", [0])
        code = main(
            [
                "reconcile-tickets",
                str(path),
                "--issuer",
                "iss",
                "--lease-size",
                "4",
                "--issued",
                "5-2",
            ]
        )
        out = capsys.readouterr().out
        assert code == 2
        assert "unverifiable" in out.lower()

    def test_lease_size_below_one_is_unverifiable(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = trail_with_tickets(tmp_path, "iss", [0])
        code = main(
            [
                "reconcile-tickets",
                str(path),
                "--issuer",
                "iss",
                "--lease-size",
                "0",
                "--issued",
                "0",
            ]
        )
        out = capsys.readouterr().out
        assert code == 2
        assert "unverifiable" in out.lower()


class TestUnreadableEntriesAndIssuerFiltering:
    def test_entries_from_a_different_issuer_are_not_counted(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = trail_with_tickets(tmp_path, "other-issuer", [0, 1, 2, 3])
        code = main(
            [
                "reconcile-tickets",
                str(path),
                "--issuer",
                "iss",
                "--lease-size",
                "4",
                "--issued",
                "0-3",
            ]
        )
        out = capsys.readouterr().out
        assert code == 0
        # Nothing from the other issuer counts as present, so every issued
        # number in the (still-open) window is a blind-spot candidate.
        assert "blind spot" in out.lower()

    def test_unparseable_ticket_entry_downgrades_verdict_not_silently_ignored(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = tmp_path / "trail.jsonl"
        log = AuditLog.open(path)
        log.append(
            payload=to_payload(Ticket(issuer="iss", ticket_id=0)),
            payload_type=TICKET_PAYLOAD_TYPE,
        )
        # A ticket-typed payload that fails to parse as a Ticket.
        log.append(payload={"issuer": "iss"}, payload_type=TICKET_PAYLOAD_TYPE)

        code = main(
            [
                "reconcile-tickets",
                str(path),
                "--issuer",
                "iss",
                "--lease-size",
                "4",
                "--issued",
                "0",
                "--json",
            ]
        )
        payload = json.loads(capsys.readouterr().out)
        assert code == 2  # unverifiable — join() with the unreadable entry
        assert payload["verdict"] == "unverifiable"
        assert payload["unreadable"] == [1]


class TestNoTicketsIssuedYet:
    def test_empty_issued_set_is_measured_ok_with_no_window(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = tmp_path / "trail.jsonl"
        log = AuditLog.open(path)
        log.append(payload={"unrelated": True}, payload_type=OTHER_PT)
        code = main(
            [
                "reconcile-tickets",
                str(path),
                "--issuer",
                "iss",
                "--lease-size",
                "4",
                "--issued",
                "",
            ]
        )
        out = capsys.readouterr().out
        assert code == 0
        assert "nothing to reconcile" in out.lower()


class TestMissingTrail:
    def test_nonexistent_trail_exits_3(self, tmp_path: Path) -> None:
        code = main(
            [
                "reconcile-tickets",
                str(tmp_path / "nope.jsonl"),
                "--issuer",
                "iss",
                "--lease-size",
                "4",
                "--issued",
                "0",
            ]
        )
        assert code == 3
