"""Tests for the AI incident record family (domain/incident.py).

E2a. Three things this file exists to pin down:

1. The record can fill Decree 142/2026/NĐ-CP form Mẫu AI01a §II-§III, and
   every timestamp on it is accepted as an opaque non-empty string at
   construction. Parsing at write time would turn a newer writer's timestamp
   shape into "a bad row" — the beads v1.2.2 failure class.
2. A submission recorded after the fact appends a NEW row and the reader
   FOLDS by ``incident_id``, latest row winning as a whole record. A
   field-wise merge would synthesise a record nobody ever wrote.
3. The window reading is anchored on ``confirmed_at`` (Điều 19(3)(c)), never
   on ``detected_at``, and every state it cannot measure comes back
   ``unmeasured`` with a reason that names its own cause.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from waxseal.domain.header import Entry, EntryHeader
from waxseal.domain.incident import (
    INCIDENT_PAYLOAD_TYPE,
    IncidentRecord,
    IncidentScan,
    IncidentView,
    WindowReading,
    WindowStatus,
    from_payload,
    render_incidents,
    scan_incidents,
    to_payload,
    window_status,
)

OTHER_PT = "application/vnd.test.other+json"

CONFIRMED = "2026-09-01T08:00:00+00:00"
DETECTED = "2026-09-01T07:00:00+00:00"
WINDOW_72H = timedelta(hours=72)


def header(seq: int, payload_type: str) -> EntryHeader:
    return EntryHeader(
        seq=seq,
        ts="2026-09-01T08:00:00Z",
        hash_version="deadbeef" * 8,
        payload_type=payload_type,
        payload_hash="0" * 64,
        prev_hash="0" * 64,
    )


def a_record(**overrides: Any) -> IncidentRecord:
    base: dict[str, Any] = {
        "incident_id": "inc-1",
        "system_id": "AI-ID-2026-0001",
        "detected_at": DETECTED,
        "severity": "nghiem trong",
    }
    base.update(overrides)
    return IncidentRecord(**base)


def incident_entry(seq: int, record: IncidentRecord) -> Entry:
    payload = json.dumps(to_payload(record)).encode()
    return Entry(header=header(seq, INCIDENT_PAYLOAD_TYPE), entry_hash="e" * 64, payload=payload)


def a_view(**overrides: Any) -> IncidentView:
    record = a_record(**overrides)
    return IncidentView(
        incident_id=record.incident_id,
        first_seq=0,
        latest_seq=0,
        rows=1,
        latest=record,
    )


def at(hour: int, *, minute: int = 0) -> datetime:
    return datetime(2026, 9, 1, hour, minute, tzinfo=UTC)


class TestIncidentPayloadType:
    def test_payload_type_names_the_schema_and_its_version(self) -> None:
        assert INCIDENT_PAYLOAD_TYPE == "application/vnd.waxseal.ai-incident.v1+json"


class TestIncidentSchema:
    def test_required_fields_round_trip(self) -> None:
        record = a_record()
        assert from_payload(to_payload(record)) == record

    def test_every_field_round_trips(self) -> None:
        record = a_record(
            confirmed_at=CONFIRMED,
            summary="model approved a transfer it should have held",
            consequence_kinds=("tai san", "quyen con nguoi, quyen rieng tu"),
            operating_status="da tam dung",
            report_ref="CTT-2026-000123",
            reported_at="2026-09-02T09:30:00+00:00",
            trace_id="trace-7",
        )
        assert from_payload(to_payload(record)) == record

    def test_optionals_serialize_as_explicit_null_never_omitted(self) -> None:
        payload = to_payload(a_record())
        for key in (
            "confirmed_at",
            "summary",
            "operating_status",
            "report_ref",
            "reported_at",
            "trace_id",
        ):
            assert key in payload, key
            assert payload[key] is None, key

    def test_consequence_kinds_serialize_as_a_json_list(self) -> None:
        payload = to_payload(a_record(consequence_kinds=("tinh mang, suc khoe",)))
        assert payload["consequence_kinds"] == ["tinh mang, suc khoe"]
        assert to_payload(a_record())["consequence_kinds"] == []

    def test_payload_is_json_serializable(self) -> None:
        # The payload goes to AuditLog.append, which canonicalizes it: a tuple
        # that never became a list would only fail there, one layer away.
        assert json.loads(json.dumps(to_payload(a_record()))) == to_payload(a_record())

    def test_unknown_extra_keys_are_ignored_not_rejected(self) -> None:
        payload = to_payload(a_record())
        payload["consequence_estimate_persons"] = 4200
        assert from_payload(payload) == a_record()

    def test_from_payload_rejects_a_non_dict(self) -> None:
        with pytest.raises(ValueError, match="JSON object"):
            from_payload(["not", "a", "dict"])

    @pytest.mark.parametrize("field", ["incident_id", "system_id", "detected_at", "severity"])
    def test_from_payload_rejects_a_missing_required_field(self, field: str) -> None:
        payload = to_payload(a_record())
        del payload[field]
        with pytest.raises(ValueError, match=field):
            from_payload(payload)

    def test_from_payload_rejects_a_wrong_typed_required_field(self) -> None:
        payload = to_payload(a_record())
        payload["severity"] = 5
        with pytest.raises(ValueError, match="severity"):
            from_payload(payload)

    def test_from_payload_rejects_a_wrong_typed_optional_field(self) -> None:
        payload = to_payload(a_record())
        payload["report_ref"] = 12345
        with pytest.raises(ValueError, match="report_ref"):
            from_payload(payload)

    def test_from_payload_rejects_a_string_where_a_kind_list_belongs(self) -> None:
        # tuple("tai san") would silently become 7 one-character "kinds".
        payload = to_payload(a_record())
        payload["consequence_kinds"] = "tai san"
        with pytest.raises(ValueError, match="consequence_kinds"):
            from_payload(payload)

    def test_from_payload_reads_a_null_kind_list_as_none_declared(self) -> None:
        payload = to_payload(a_record())
        payload["consequence_kinds"] = None
        assert from_payload(payload).consequence_kinds == ()

    def test_from_payload_reads_an_absent_kind_list_as_none_declared(self) -> None:
        payload = to_payload(a_record())
        del payload["consequence_kinds"]
        assert from_payload(payload).consequence_kinds == ()

    def test_rejects_an_empty_kind_string(self) -> None:
        with pytest.raises(ValueError, match="consequence_kinds"):
            a_record(consequence_kinds=("",))

    def test_rejects_a_list_instead_of_a_tuple_of_kinds(self) -> None:
        with pytest.raises(ValueError, match="consequence_kinds"):
            a_record(consequence_kinds=["tai san"])

    @pytest.mark.parametrize("field", ["incident_id", "system_id", "detected_at", "severity"])
    def test_rejects_an_empty_required_field(self, field: str) -> None:
        with pytest.raises(ValueError, match=field):
            a_record(**{field: ""})

    def test_record_is_immutable(self) -> None:
        record = a_record()
        with pytest.raises(AttributeError):
            record.severity = "khac"  # type: ignore[misc]

    def test_an_unrecognised_severity_is_recorded_verbatim(self) -> None:
        # A vocabulary this build has not seen is a newer writer, not a bad
        # row; normalizing it would be waxseal restating the caller's own
        # declaration (the same rule that keeps DecisionRecord.risk_tier free).
        record = a_record(severity="P0/kich hoat dung khan cap")
        assert from_payload(to_payload(record)).severity == "P0/kich hoat dung khan cap"

    @pytest.mark.parametrize(
        "value",
        ["not a timestamp at all", "2026-09-01 08:00", "1756713600", "hôm qua"],
    )
    def test_a_timestamp_is_any_non_empty_string_at_construction(self, value: str) -> None:
        # Parsing here would make a newer writer's format "a bad row" (beads
        # v1.2.2). The READER reports what it cannot parse as unmeasured.
        record = a_record(detected_at=value, confirmed_at=value, reported_at=value)
        assert from_payload(to_payload(record)) == record

    def test_no_recorded_submission_is_none_not_a_claim_of_non_submission(self) -> None:
        # rule 5: waxseal cannot know whether a report was filed, only what
        # this trail records.
        assert a_record().report_ref is None
        assert a_record().reported_at is None


class TestScanIncidents:
    def test_two_rows_with_one_id_fold_to_one_view_with_the_newest_winning(self) -> None:
        first = a_record(confirmed_at=CONFIRMED)
        restated = a_record(
            confirmed_at=CONFIRMED,
            report_ref="CTT-2026-000123",
            reported_at="2026-09-02T09:30:00+00:00",
        )
        scan = scan_incidents([incident_entry(0, first), incident_entry(4, restated)])
        assert len(scan.views) == 1
        view = scan.views[0]
        assert view.incident_id == "inc-1"
        assert view.first_seq == 0
        assert view.latest_seq == 4
        assert view.rows == 2
        assert view.latest == restated
        assert scan.unreadable == ()

    def test_a_third_row_keeps_counting_and_keeps_the_first_seq(self) -> None:
        entries = [
            incident_entry(1, a_record()),
            incident_entry(2, a_record(operating_status="hoat dong han che")),
            incident_entry(9, a_record(operating_status="da tam dung")),
        ]
        view = scan_incidents(entries).views[0]
        assert (view.first_seq, view.latest_seq, view.rows) == (1, 9, 3)
        assert view.latest.operating_status == "da tam dung"

    def test_distinct_ids_keep_chain_order_of_first_appearance(self) -> None:
        entries = [
            incident_entry(0, a_record(incident_id="inc-b")),
            incident_entry(1, a_record(incident_id="inc-a")),
            incident_entry(2, a_record(incident_id="inc-b")),
        ]
        assert [v.incident_id for v in scan_incidents(entries).views] == ["inc-b", "inc-a"]

    def test_a_header_only_row_and_a_malformed_row_are_reported_unreadable(self) -> None:
        malformed = Entry(
            header=header(0, INCIDENT_PAYLOAD_TYPE), entry_hash="e" * 64, payload=b"not json"
        )
        header_only = Entry(
            header=header(1, INCIDENT_PAYLOAD_TYPE), entry_hash="e" * 64, payload=None
        )
        wrong_shape = Entry(
            header=header(2, INCIDENT_PAYLOAD_TYPE), entry_hash="e" * 64, payload=b"{}"
        )
        scan = scan_incidents([malformed, header_only, wrong_shape])
        assert scan.views == ()
        assert scan.unreadable == (0, 1, 2)

    def test_other_payload_types_are_ignored(self) -> None:
        other = Entry(header=header(0, OTHER_PT), entry_hash="e" * 64, payload=b'{"x":1}')
        scan = scan_incidents([other, incident_entry(1, a_record())])
        assert len(scan.views) == 1
        assert scan.unreadable == ()

    def test_empty_input_yields_empty_tuples(self) -> None:
        scan = scan_incidents([])
        assert scan == IncidentScan(views=(), unreadable=())

    def test_scan_is_frozen(self) -> None:
        scan = scan_incidents([])
        with pytest.raises(AttributeError):
            scan.views = ()  # type: ignore[misc]

    def test_view_is_frozen(self) -> None:
        view = a_view()
        with pytest.raises(AttributeError):
            view.rows = 9  # type: ignore[misc]


class TestWindowStatusMeasured:
    def test_a_submission_inside_the_window_reads_as_recorded_within(self) -> None:
        view = a_view(
            confirmed_at=CONFIRMED,
            report_ref="CTT-1",
            reported_at="2026-09-02T08:00:00+00:00",
        )
        reading = window_status(view, window=WINDOW_72H, now=at(23))
        assert reading.status is WindowStatus.REPORT_RECORDED_WITHIN_WINDOW
        assert reading.elapsed_h == pytest.approx(24.0)

    def test_exactly_equal_to_the_window_is_within_it(self) -> None:
        # Điều 19(3)(a) says "trong thời hạn 72 giờ": the boundary instant is
        # inside the window, so `<=`, never `<`.
        view = a_view(confirmed_at=CONFIRMED, reported_at="2026-09-04T08:00:00+00:00")
        reading = window_status(view, window=WINDOW_72H, now=at(9))
        assert reading.status is WindowStatus.REPORT_RECORDED_WITHIN_WINDOW
        assert reading.elapsed_h == pytest.approx(72.0)

    def test_a_submission_beyond_the_window_reads_as_recorded_after(self) -> None:
        view = a_view(confirmed_at=CONFIRMED, reported_at="2026-09-04T08:00:01+00:00")
        reading = window_status(view, window=WINDOW_72H, now=at(9))
        assert reading.status is WindowStatus.REPORT_RECORDED_AFTER_WINDOW
        assert reading.elapsed_h is not None and reading.elapsed_h > 72.0

    def test_a_z_suffixed_timestamp_parses(self) -> None:
        view = a_view(confirmed_at="2026-09-01T08:00:00Z", reported_at="2026-09-01T20:00:00Z")
        reading = window_status(view, window=WINDOW_72H, now=at(21))
        assert reading.status is WindowStatus.REPORT_RECORDED_WITHIN_WINDOW
        assert reading.elapsed_h == pytest.approx(12.0)

    def test_no_submission_and_time_remaining_reads_as_window_open(self) -> None:
        view = a_view(confirmed_at=CONFIRMED)
        reading = window_status(view, window=WINDOW_72H, now=at(20))
        assert reading.status is WindowStatus.WINDOW_OPEN
        assert reading.elapsed_h == pytest.approx(12.0)

    def test_no_submission_once_the_window_has_gone_by(self) -> None:
        view = a_view(confirmed_at=CONFIRMED)
        now = datetime(2026, 9, 5, 8, 0, tzinfo=UTC)
        reading = window_status(view, window=WINDOW_72H, now=now)
        assert reading.status is WindowStatus.NO_REPORT_RECORDED_PAST_WINDOW
        assert reading.elapsed_h == pytest.approx(96.0)

    def test_the_boundary_instant_still_counts_as_open(self) -> None:
        view = a_view(confirmed_at=CONFIRMED)
        now = datetime(2026, 9, 4, 8, 0, tzinfo=UTC)
        assert window_status(view, window=WINDOW_72H, now=now).status is WindowStatus.WINDOW_OPEN

    def test_reading_is_frozen(self) -> None:
        reading = window_status(a_view(confirmed_at=CONFIRMED), window=WINDOW_72H, now=at(9))
        assert isinstance(reading, WindowReading)
        with pytest.raises(AttributeError):
            reading.status = WindowStatus.UNMEASURED  # type: ignore[misc]


class TestWindowStatusUnmeasured:
    """Every unmeasured reading names its own cause, in the manner CLAUDE.md's
    instance 10 requires: "unchecked" with no cause is only marginally better
    than silence."""

    def test_a_missing_confirmed_at_is_unmeasured_and_never_falls_back(self) -> None:
        reading = window_status(a_view(), window=WINDOW_72H, now=at(9))
        assert reading.status is WindowStatus.UNMEASURED
        assert reading.elapsed_h is None
        assert "confirmed_at" in reading.reason
        assert "19(3)(c)" in reading.reason
        # The one substitution that must never happen silently.
        assert "detected_at" in reading.reason

    def test_an_unparseable_confirmed_at_is_unmeasured(self) -> None:
        reading = window_status(a_view(confirmed_at="hôm qua"), window=WINDOW_72H, now=at(9))
        assert reading.status is WindowStatus.UNMEASURED
        assert "confirmed_at" in reading.reason
        assert "ISO-8601" in reading.reason

    def test_a_naive_confirmed_at_is_unmeasured(self) -> None:
        # Comparing naive to aware raises in Python; guessing a zone would be
        # inventing evidence. Unmeasured is the only honest answer.
        reading = window_status(
            a_view(confirmed_at="2026-09-01T08:00:00"), window=WINDOW_72H, now=at(9)
        )
        assert reading.status is WindowStatus.UNMEASURED
        assert "confirmed_at" in reading.reason
        assert "offset" in reading.reason

    def test_an_unparseable_reported_at_is_unmeasured(self) -> None:
        reading = window_status(
            a_view(confirmed_at=CONFIRMED, reported_at="yesterday"),
            window=WINDOW_72H,
            now=at(9),
        )
        assert reading.status is WindowStatus.UNMEASURED
        assert "reported_at" in reading.reason
        assert "ISO-8601" in reading.reason

    def test_a_naive_reported_at_is_unmeasured(self) -> None:
        reading = window_status(
            a_view(confirmed_at=CONFIRMED, reported_at="2026-09-02T09:00:00"),
            window=WINDOW_72H,
            now=at(9),
        )
        assert reading.status is WindowStatus.UNMEASURED
        assert "reported_at" in reading.reason
        assert "offset" in reading.reason

    def test_a_reported_at_before_confirmed_at_is_unmeasured_not_within(self) -> None:
        # A caller-asserted contradiction. Reading it as "within" would print
        # a compliant window out of two numbers that cannot both be true.
        reading = window_status(
            a_view(confirmed_at=CONFIRMED, reported_at="2026-08-30T08:00:00+00:00"),
            window=WINDOW_72H,
            now=at(9),
        )
        assert reading.status is WindowStatus.UNMEASURED
        assert "reported_at" in reading.reason
        assert "confirmed_at" in reading.reason
        assert "earlier" in reading.reason

    def test_a_report_ref_without_a_reported_at_is_unmeasured(self) -> None:
        reading = window_status(
            a_view(confirmed_at=CONFIRMED, report_ref="CTT-2026-000123"),
            window=WINDOW_72H,
            now=at(9),
        )
        assert reading.status is WindowStatus.UNMEASURED
        assert "report_ref" in reading.reason
        assert "reported_at" in reading.reason

    def test_a_now_before_confirmed_at_is_unmeasured(self) -> None:
        reading = window_status(a_view(confirmed_at=CONFIRMED), window=WINDOW_72H, now=at(7))
        assert reading.status is WindowStatus.UNMEASURED
        assert "confirmed_at" in reading.reason
        assert "as-of" in reading.reason

    def test_a_naive_now_is_unmeasured(self) -> None:
        reading = window_status(
            a_view(confirmed_at=CONFIRMED),
            window=WINDOW_72H,
            now=datetime(2026, 9, 2, 9, 0),
        )
        assert reading.status is WindowStatus.UNMEASURED
        assert "as-of" in reading.reason
        assert "offset" in reading.reason

    def test_an_unparseable_reported_at_beats_a_naive_now(self) -> None:
        # A recorded submission time is read against confirmed_at alone; the
        # as-of clock is not consulted, so its shape cannot change the reason.
        reading = window_status(
            a_view(confirmed_at=CONFIRMED, reported_at="yesterday"),
            window=WINDOW_72H,
            now=datetime(2026, 9, 2, 9, 0),
        )
        assert "reported_at" in reading.reason


class TestRenderIncidents:
    FORBIDDEN = ("unreported", "missed", "late", "breach")

    def rendered(self, *args: Any, **kwargs: Any) -> str:
        return "\n".join(render_incidents(*args, **kwargs))

    def test_the_caller_asserted_qualification_is_on_the_status_line(self) -> None:
        scan = scan_incidents([incident_entry(0, a_record(confirmed_at=CONFIRMED))])
        lines = render_incidents(scan, window=WINDOW_72H, now=at(20))
        status_lines = [line for line in lines if WindowStatus.WINDOW_OPEN.value in line]
        assert status_lines, lines
        for line in status_lines:
            assert "by caller-asserted time" in line

    def test_the_four_forbidden_words_are_absent(self) -> None:
        # In the manner tests/test_cli_preflight.py asserts "tamper-proof" is
        # absent: this renderer reports what the trail records, and every one
        # of these words asserts a finding about an obligation that waxseal
        # has no standing to make.
        entries = [
            incident_entry(0, a_record(confirmed_at=CONFIRMED)),
            incident_entry(
                1,
                a_record(
                    incident_id="inc-2",
                    confirmed_at=CONFIRMED,
                    reported_at="2026-09-09T08:00:00+00:00",
                    report_ref="CTT-2",
                    consequence_kinds=("tai san",),
                    operating_status="da tam dung",
                ),
            ),
            incident_entry(2, a_record(incident_id="inc-3")),
            Entry(
                header=header(3, INCIDENT_PAYLOAD_TYPE),
                entry_hash="e" * 64,
                payload=b"not json",
            ),
        ]
        now = datetime(2026, 9, 10, 8, 0, tzinfo=UTC)
        text = self.rendered(scan_incidents(entries), window=WINDOW_72H, now=now).lower()
        for word in self.FORBIDDEN:
            assert word not in text, word

    def test_the_time_basis_is_stated_before_anything_else(self) -> None:
        lines = render_incidents(scan_incidents([]))
        assert "CALLER-ASSERTED" in lines[0]

    def test_zero_records_is_not_evidence_that_none_occurred(self) -> None:
        text = self.rendered(scan_incidents([]))
        assert "0 incident record" in text
        assert "not evidence that none occurred" in text

    def test_records_are_listed_with_their_seqs_and_row_count(self) -> None:
        entries = [incident_entry(0, a_record()), incident_entry(3, a_record())]
        text = self.rendered(scan_incidents(entries))
        assert "inc-1" in text
        assert "first_seq=0" in text
        assert "rows=2" in text

    def test_an_undeclared_operating_status_and_kind_list_say_so(self) -> None:
        text = self.rendered(scan_incidents([incident_entry(0, a_record())]))
        assert "not declared" in text
        assert "none declared" in text

    def test_a_declared_operating_status_and_kind_list_are_shown_verbatim(self) -> None:
        record = a_record(
            operating_status="hoat dong han che", consequence_kinds=("tai san", "an ninh")
        )
        text = self.rendered(scan_incidents([incident_entry(0, record)]))
        assert "hoat dong han che" in text
        assert "tai san" in text and "an ninh" in text

    def test_a_recorded_submission_reference_is_shown(self) -> None:
        record = a_record(report_ref="CTT-2026-000123")
        text = self.rendered(scan_incidents([incident_entry(0, record)]))
        assert "CTT-2026-000123" in text

    def test_no_recorded_submission_never_reads_as_no_report_filed(self) -> None:
        text = self.rendered(scan_incidents([incident_entry(0, a_record())]))
        assert "no submission is recorded on this trail" in text
        assert "not evidence" in text

    def test_unreadable_rows_are_named_not_folded_into_the_count(self) -> None:
        entries = [
            incident_entry(0, a_record()),
            Entry(
                header=header(5, INCIDENT_PAYLOAD_TYPE),
                entry_hash="e" * 64,
                payload=b"not json",
            ),
        ]
        text = self.rendered(scan_incidents(entries))
        assert "unreadable" in text
        assert "5" in text

    def test_no_window_lines_when_no_window_is_given(self) -> None:
        scan = scan_incidents([incident_entry(0, a_record(confirmed_at=CONFIRMED))])
        text = self.rendered(scan)
        assert "by caller-asserted time" not in text
        assert WindowStatus.WINDOW_OPEN.value not in text

    def test_no_window_lines_when_the_as_of_time_is_missing(self) -> None:
        # Both halves are required: a window with no as-of time cannot be
        # measured, and inventing one from the process clock inside a pure
        # domain function is exactly what rule 8 forbids.
        scan = scan_incidents([incident_entry(0, a_record(confirmed_at=CONFIRMED))])
        text = self.rendered(scan, window=WINDOW_72H)
        assert "by caller-asserted time" not in text

    def test_an_unmeasured_reading_is_rendered_with_its_reason(self) -> None:
        scan = scan_incidents([incident_entry(0, a_record())])
        text = self.rendered(scan, window=WINDOW_72H, now=at(9))
        assert WindowStatus.UNMEASURED.value in text
        assert "19(3)(c)" in text

    def test_the_window_size_is_named_so_the_reading_is_reproducible(self) -> None:
        scan = scan_incidents([incident_entry(0, a_record(confirmed_at=CONFIRMED))])
        text = self.rendered(scan, window=WINDOW_72H, now=at(20))
        assert "72" in text
