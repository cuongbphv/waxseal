"""Tests for exogenous admission tickets (domain/tickets.py).

D2 (docs/plans/waxseal-paper-conformance.md): the one construction in the
paper's re-analysis that turns a dropped write into a *positively detected*
one, the counterweight to the coverage-impossibility theorem. waxseal never
issues a ticket (that is a separate, exogenous authority's job) — it only
carries one in an entry's payload and reconciles issued-vs-present.

Three required behaviors, each with its own test class below:

1. A ticket the issuer confirms it issued, that never reaches the trail, is
   named exactly as a positively-detected drop.
2. Up to L-1 tickets inside the still-open lease window can never be told
   apart from "not yet used" — the report must state that bound explicitly
   and must never claim the run is clean.
3. Issuer data unavailable this run is `measured=False`, distinct from "0
   drops" (CLAUDE.md rule 5: unmeasured != absent).
"""

from __future__ import annotations

import json

import pytest

from waxseal.domain.header import Entry, EntryHeader
from waxseal.domain.tickets import (
    TICKET_PAYLOAD_TYPE,
    Ticket,
    TicketReconciliation,
    TicketScan,
    from_payload,
    reconcile_tickets,
    render_reconciliation,
    scan_tickets,
    to_payload,
)
from waxseal.domain.verdict import Verdict

OTHER_PT = "application/vnd.test.other+json"


def header(seq: int, payload_type: str) -> EntryHeader:
    return EntryHeader(
        seq=seq,
        ts="2026-08-29T00:00:00Z",
        hash_version="deadbeef" * 8,
        payload_type=payload_type,
        payload_hash="0" * 64,
        prev_hash="0" * 64,
    )


def ticket_entry(seq: int, issuer: str, ticket_id: int) -> Entry:
    payload = json.dumps(to_payload(Ticket(issuer=issuer, ticket_id=ticket_id))).encode()
    return Entry(header=header(seq, TICKET_PAYLOAD_TYPE), entry_hash="e" * 64, payload=payload)


class TestTicketSchema:
    def test_round_trips_through_payload(self) -> None:
        t = Ticket(issuer="lease-server-1", ticket_id=42)
        assert from_payload(to_payload(t)) == t

    def test_rejects_empty_issuer(self) -> None:
        with pytest.raises(ValueError, match="issuer"):
            Ticket(issuer="", ticket_id=0)

    def test_rejects_negative_ticket_id(self) -> None:
        with pytest.raises(ValueError, match="ticket_id"):
            Ticket(issuer="i", ticket_id=-1)

    def test_rejects_non_int_ticket_id(self) -> None:
        with pytest.raises(ValueError, match="ticket_id"):
            Ticket(issuer="i", ticket_id=True)  # bool is not an int here

    def test_from_payload_rejects_non_dict(self) -> None:
        with pytest.raises(ValueError, match="JSON object"):
            from_payload(["not", "a", "dict"])

    def test_from_payload_rejects_missing_fields(self) -> None:
        with pytest.raises(ValueError):
            from_payload({"issuer": "i"})


class TestScanTickets:
    def test_collects_present_ticket_ids_for_one_issuer(self) -> None:
        entries = [
            ticket_entry(0, "iss", 0),
            ticket_entry(1, "iss", 1),
            Entry(header=header(2, OTHER_PT), entry_hash="e" * 64, payload=b"{}"),
        ]
        scan = scan_tickets(entries, issuer="iss")
        assert scan.present == frozenset({0, 1})
        assert scan.unreadable == ()

    def test_ignores_tickets_from_a_different_issuer(self) -> None:
        entries = [ticket_entry(0, "other-issuer", 5)]
        scan = scan_tickets(entries, issuer="iss")
        assert scan.present == frozenset()

    def test_reports_unreadable_ticket_entries_separately_not_silently(self) -> None:
        malformed = Entry(
            header=header(0, TICKET_PAYLOAD_TYPE), entry_hash="e" * 64, payload=b"not json"
        )
        header_only = Entry(
            header=header(1, TICKET_PAYLOAD_TYPE), entry_hash="e" * 64, payload=None
        )
        scan = scan_tickets([malformed, header_only], issuer="iss")
        assert scan.present == frozenset()
        assert scan.unreadable == (0, 1)


class TestPositivelyDetectedDrop:
    """A ticket the issuer confirms issued, missing from a CLOSED lease
    window (a later lease already issued), is named exactly."""

    def test_missing_ticket_in_a_closed_window_is_named(self) -> None:
        # lease_size=4: window0=[0,3] (closed — window1 below is issued too),
        # window1=[4,7] is the open one. Ticket 2 never reached the trail.
        result = reconcile_tickets(
            present={0, 1, 3, 4},
            issued={0, 1, 2, 3, 4},
            lease_size=4,
        )
        assert result.measured is True
        assert result.missing == (2,)
        assert result.verdict is Verdict.BROKEN

    def test_multiple_missing_tickets_named_exactly(self) -> None:
        result = reconcile_tickets(
            present={0, 8},
            issued={0, 1, 2, 3, 8},
            lease_size=4,
        )
        # window of max_issued(8) with lease_size=4 is [8, 11] (open).
        # window [0,3] is closed: 1, 2, 3 are missing there.
        assert result.missing == (1, 2, 3)
        assert result.verdict is Verdict.BROKEN

    def test_no_missing_in_closed_windows_is_not_broken(self) -> None:
        result = reconcile_tickets(
            present={0, 1, 2, 3, 8},
            issued={0, 1, 2, 3, 8},
            lease_size=4,
        )
        assert result.missing == ()
        assert result.verdict is Verdict.OK

    def test_render_names_missing_tickets(self) -> None:
        result = reconcile_tickets(present={0}, issued={0, 1, 2, 3, 8}, lease_size=4)
        lines = "\n".join(render_reconciliation(result))
        assert "1" in lines and "2" in lines and "3" in lines
        assert "detected" in lines.lower()


class TestBlindSpotBound:
    """L-1 drops inside the still-open lease window must be reported as an
    explicit blind spot, never rendered as a clean run."""

    def test_all_but_one_missing_in_the_open_window_is_the_blind_spot(self) -> None:
        # lease_size=4, single window [0,3] (no higher lease issued yet, so
        # it is the OPEN window) — ticket 0 present, 1/2/3 missing = L-1.
        result = reconcile_tickets(present={0}, issued={0, 1, 2, 3}, lease_size=4)
        assert result.missing == ()  # not positively detected: window is open
        assert result.blind_spot_window == (0, 3)
        assert result.blind_spot_missing == (1, 2, 3)
        assert len(result.blind_spot_missing) == result.blind_spot_bound == 3

    def test_report_never_claims_clean_when_blind_spot_is_populated(self) -> None:
        result = reconcile_tickets(present={0}, issued={0, 1, 2, 3}, lease_size=4)
        lines = "\n".join(render_reconciliation(result))
        assert "clean" not in lines.lower()
        assert "blind spot" in lines.lower()
        # The bound itself (L-1) must be stated, not just implied by a list.
        assert "3" in lines

    def test_bound_is_stated_even_when_nothing_is_missing_there(self) -> None:
        result = reconcile_tickets(present={0, 1, 2, 3}, issued={0, 1, 2, 3}, lease_size=4)
        assert result.blind_spot_missing == ()
        lines = "\n".join(render_reconciliation(result))
        assert "blind spot" in lines.lower()
        assert "clean" not in lines.lower()

    def test_bound_is_stated_even_with_no_tickets_issued_at_all(self) -> None:
        result = reconcile_tickets(present=set(), issued=set(), lease_size=4)
        assert result.blind_spot_window is None
        lines = "\n".join(render_reconciliation(result))
        assert "3" in lines  # L-1 structural bound still named
        assert "clean" not in lines.lower()


class TestIssuerUnreachable:
    """Issuer data unavailable this run must read as UNMEASURED, never as
    '0 drops' (CLAUDE.md rule 5: None != 0)."""

    def test_none_issued_is_unmeasured_not_zero_drops(self) -> None:
        result = reconcile_tickets(present={0, 1, 2}, issued=None, lease_size=4)
        assert result.measured is False
        assert result.missing is None
        assert result.blind_spot_missing is None
        assert result.blind_spot_window is None
        assert result.verdict is Verdict.UNVERIFIABLE

    def test_render_distinguishes_unmeasured_from_zero_drops(self) -> None:
        result = reconcile_tickets(present={0, 1, 2}, issued=None, lease_size=4)
        lines = "\n".join(render_reconciliation(result))
        assert "unmeasured" in lines.lower()
        assert "detected: 0" not in lines.lower()
        assert "no positively-detected drops" not in lines.lower()


class TestRenderWithScan:
    def test_appends_unreadable_note_when_scan_has_unreadable_entries(self) -> None:
        result = reconcile_tickets(present={0}, issued={0}, lease_size=4)
        scan = TicketScan(present=frozenset({0}), unreadable=(3, 7))
        lines = "\n".join(render_reconciliation(result, scan=scan))
        assert "unreadable" in lines.lower()
        assert "3" in lines and "7" in lines
        assert "entries" in lines.lower()

    def test_singular_wording_for_exactly_one_unreadable_entry(self) -> None:
        result = reconcile_tickets(present={0}, issued={0}, lease_size=4)
        scan = TicketScan(present=frozenset({0}), unreadable=(3,))
        lines = "\n".join(render_reconciliation(result, scan=scan))
        assert "1 entry " in lines.lower() or "1 entry claim" in lines.lower()

    def test_no_unreadable_note_when_scan_is_clean(self) -> None:
        result = reconcile_tickets(present={0}, issued={0}, lease_size=4)
        scan = TicketScan(present=frozenset({0}), unreadable=())
        lines = "\n".join(render_reconciliation(result, scan=scan))
        assert "unreadable" not in lines.lower()


class TestValidation:
    def test_rejects_lease_size_below_one(self) -> None:
        with pytest.raises(ValueError, match="lease_size"):
            reconcile_tickets(present=set(), issued=set(), lease_size=0)

    def test_rejects_negative_issued_ticket_numbers(self) -> None:
        with pytest.raises(ValueError, match="issued"):
            reconcile_tickets(present=set(), issued={-1}, lease_size=4)


class TestDataclassesAreFrozen:
    def test_ticket_scan_is_frozen(self) -> None:
        scan = TicketScan(present=frozenset(), unreadable=())
        with pytest.raises(AttributeError):
            scan.present = frozenset({1})  # type: ignore[misc]

    def test_reconciliation_is_frozen(self) -> None:
        result = reconcile_tickets(present=set(), issued=None, lease_size=1)
        assert isinstance(result, TicketReconciliation)
        with pytest.raises(AttributeError):
            result.measured = True  # type: ignore[misc]
