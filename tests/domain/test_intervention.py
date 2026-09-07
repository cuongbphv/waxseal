"""Tests for the human-intervention record family (domain/intervention.py).

E2b. The record evidences that intervention decisions were RETAINED
UNALTERED, which is what Decree 142/2026/NĐ-CP Điều 11(5) ("nhà cung cấp,
bên triển khai phải lưu trữ đầy đủ nhật ký vận hành và các quyết định can
thiệp") and Điều 15(2)(c) ask for. It cannot evidence that no intervention
mechanism was obstructed — Law on AI 134/2025/QH15 Điều 7(4)'s prohibition —
because a mechanism that was switched off writes nothing, and no log
witnesses its own absence.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from waxseal.domain.header import Entry, EntryHeader
from waxseal.domain.intervention import (
    INTERVENTION_PAYLOAD_TYPE,
    InterventionRecord,
    InterventionScan,
    from_payload,
    scan_interventions,
    to_payload,
)

OTHER_PT = "application/vnd.test.other+json"


def header(seq: int, payload_type: str) -> EntryHeader:
    return EntryHeader(
        seq=seq,
        ts="2026-09-01T08:00:00Z",
        hash_version="deadbeef" * 8,
        payload_type=payload_type,
        payload_hash="0" * 64,
        prev_hash="0" * 64,
    )


def a_record(**overrides: Any) -> InterventionRecord:
    base: dict[str, Any] = {
        "intervention_id": "iv-1",
        "system_id": "AI-ID-2026-0001",
        "actor_ref": "analyst-7",
        "action": "halt",
    }
    base.update(overrides)
    return InterventionRecord(**base)


def intervention_entry(seq: int, record: InterventionRecord) -> Entry:
    payload = json.dumps(to_payload(record)).encode()
    return Entry(
        header=header(seq, INTERVENTION_PAYLOAD_TYPE), entry_hash="e" * 64, payload=payload
    )


class TestInterventionPayloadType:
    def test_payload_type_names_the_schema_and_its_version(self) -> None:
        assert (
            INTERVENTION_PAYLOAD_TYPE
            == "application/vnd.waxseal.human-intervention.v1+json"
        )


class TestInterventionSchema:
    def test_required_fields_round_trip(self) -> None:
        record = a_record()
        assert from_payload(to_payload(record)) == record

    def test_every_field_round_trips(self) -> None:
        record = a_record(
            decision_ref="d-88",
            rationale="threshold drift, held pending review",
            trace_id="trace-3",
        )
        assert from_payload(to_payload(record)) == record

    def test_optionals_serialize_as_explicit_null_never_omitted(self) -> None:
        payload = to_payload(a_record())
        for key in ("decision_ref", "rationale", "trace_id"):
            assert key in payload, key
            assert payload[key] is None, key

    def test_unknown_extra_keys_are_ignored_not_rejected(self) -> None:
        payload = to_payload(a_record())
        payload["emergency_stop_seconds"] = 3
        assert from_payload(payload) == a_record()

    def test_from_payload_rejects_a_non_dict(self) -> None:
        with pytest.raises(ValueError, match="JSON object"):
            from_payload("not a dict")

    @pytest.mark.parametrize(
        "field", ["intervention_id", "system_id", "actor_ref", "action"]
    )
    def test_from_payload_rejects_a_missing_required_field(self, field: str) -> None:
        payload = to_payload(a_record())
        del payload[field]
        with pytest.raises(ValueError, match=field):
            from_payload(payload)

    def test_from_payload_rejects_a_wrong_typed_required_field(self) -> None:
        payload = to_payload(a_record())
        payload["action"] = ["halt"]
        with pytest.raises(ValueError, match="action"):
            from_payload(payload)

    def test_from_payload_rejects_a_wrong_typed_optional_field(self) -> None:
        payload = to_payload(a_record())
        payload["decision_ref"] = 7
        with pytest.raises(ValueError, match="decision_ref"):
            from_payload(payload)

    @pytest.mark.parametrize(
        "field", ["intervention_id", "system_id", "actor_ref", "action"]
    )
    def test_rejects_an_empty_required_field(self, field: str) -> None:
        with pytest.raises(ValueError, match=field):
            a_record(**{field: ""})

    def test_record_is_immutable(self) -> None:
        record = a_record()
        with pytest.raises(AttributeError):
            record.action = "override"  # type: ignore[misc]

    def test_an_unrecognised_action_is_recorded_verbatim(self) -> None:
        # Mẫu AI08a §V.6 counts supervision interventions and §V.9 counts
        # emergency-stop activations; a deployer picks stable labels for those
        # two. waxseal recommends, never enumerates.
        record = a_record(action="dừng khẩn cấp")
        assert from_payload(to_payload(record)).action == "dừng khẩn cấp"

    def test_a_decision_ref_naming_a_decision_not_on_this_trail_is_not_an_error(
        self,
    ) -> None:
        # The decision may live on another trail or predate this one; there is
        # deliberately no cross-check here.
        assert a_record(decision_ref="d-from-another-trail").decision_ref == (
            "d-from-another-trail"
        )

    def test_an_intervention_tied_to_no_decision_is_legitimate(self) -> None:
        # Halting a whole system is not an act on one decision.
        assert a_record().decision_ref is None


class TestScanInterventions:
    def test_records_are_paired_with_their_seq_in_chain_order(self) -> None:
        entries = [
            intervention_entry(1, a_record(intervention_id="iv-a")),
            intervention_entry(4, a_record(intervention_id="iv-b")),
        ]
        scan = scan_interventions(entries)
        assert [seq for seq, _ in scan.records] == [1, 4]
        assert [r.intervention_id for _, r in scan.records] == ["iv-a", "iv-b"]
        assert scan.unreadable == ()

    def test_a_header_only_row_and_a_malformed_row_are_reported_unreadable(self) -> None:
        malformed = Entry(
            header=header(0, INTERVENTION_PAYLOAD_TYPE),
            entry_hash="e" * 64,
            payload=b"not json",
        )
        header_only = Entry(
            header=header(1, INTERVENTION_PAYLOAD_TYPE), entry_hash="e" * 64, payload=None
        )
        wrong_shape = Entry(
            header=header(2, INTERVENTION_PAYLOAD_TYPE), entry_hash="e" * 64, payload=b"{}"
        )
        scan = scan_interventions([malformed, header_only, wrong_shape])
        assert scan.records == ()
        assert scan.unreadable == (0, 1, 2)

    def test_other_payload_types_are_ignored(self) -> None:
        other = Entry(header=header(0, OTHER_PT), entry_hash="e" * 64, payload=b'{"x":1}')
        scan = scan_interventions([other, intervention_entry(1, a_record())])
        assert len(scan.records) == 1
        assert scan.unreadable == ()

    def test_empty_input_yields_empty_tuples(self) -> None:
        assert scan_interventions([]) == InterventionScan(records=(), unreadable=())

    def test_scan_is_frozen(self) -> None:
        scan = scan_interventions([])
        with pytest.raises(AttributeError):
            scan.records = ()  # type: ignore[misc]

    def test_repeated_ids_are_not_folded(self) -> None:
        # Unlike an incident, an intervention is the act itself: two rows with
        # one id are two acts a caller labelled alike, never one restated.
        entries = [intervention_entry(0, a_record()), intervention_entry(1, a_record())]
        assert len(scan_interventions(entries).records) == 2
