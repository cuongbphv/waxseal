"""Tests for the incident source: recording AI incidents onto a chain.

What this layer must get right is the same short list the decision source has:
the log's redactor runs BEFORE the payload is hashed (a summary is free text a
human typed under pressure — exactly where a pasted token ends up), the
payload bytes are the canonical ones the chain already defines, the two
backends agree byte-for-byte, and reading rows back never aborts the audit
over one row somebody rewrote.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from waxseal import AuditLog
from waxseal.adapters.redactors import REDACTED, RegexRedactor
from waxseal.domain.incident import (
    INCIDENT_PAYLOAD_TYPE,
    IncidentRecord,
    scan_incidents,
    to_payload,
)
from waxseal.sources.incidents import iter_incidents, record_incident

FIXED_TS = "2026-09-01T09:00:00+00:00"


def open_log(path: Path, **kwargs: object) -> AuditLog:
    return AuditLog.open(path, now_fn=lambda: FIXED_TS, **kwargs)  # type: ignore[arg-type]


def disk_payloads(trail: Path) -> list[bytes]:
    """Payload bytes as actually stored: the JSONL envelope base64s them."""
    return [
        base64.b64decode(json.loads(line)["payload_b64"])
        for line in trail.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def tamper_payload(trail: Path, seq: int, old: bytes, new: bytes) -> None:
    """Rewrite stored payload bytes in place, keeping the envelope itself valid."""
    lines = trail.read_text(encoding="utf-8").splitlines()
    obj = json.loads(lines[seq])
    payload = base64.b64decode(obj["payload_b64"]).replace(old, new)
    obj["payload_b64"] = base64.b64encode(payload).decode("ascii")
    lines[seq] = json.dumps(obj)
    trail.write_text("\n".join(lines) + "\n", encoding="utf-8")


def a_record(**overrides: Any) -> IncidentRecord:
    base: dict[str, Any] = {
        "incident_id": "inc-1",
        "system_id": "AI-ID-2026-0001",
        "detected_at": "2026-09-01T07:00:00+00:00",
        "severity": "nghiem trong",
    }
    base.update(overrides)
    return IncidentRecord(**base)


class TestRecordIncident:
    def test_entry_carries_the_incident_payload_type(self, tmp_path: Path) -> None:
        log = open_log(tmp_path / "trail.jsonl")
        entry = record_incident(log, a_record())
        assert entry.header.payload_type == INCIDENT_PAYLOAD_TYPE

    def test_payload_bytes_are_the_canonical_serialization(self, tmp_path: Path) -> None:
        log = open_log(tmp_path / "trail.jsonl")
        record = a_record(consequence_kinds=("tai san",))
        entry = record_incident(log, record)
        assert entry.payload is not None
        assert json.loads(entry.payload) == to_payload(record)
        assert entry.payload == json.dumps(
            to_payload(record), sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")

    def test_recorded_incidents_chain_and_verify(self, tmp_path: Path) -> None:
        log = open_log(tmp_path / "trail.jsonl")
        for i in range(3):
            record_incident(log, a_record(incident_id=f"inc-{i}"))
        result = log.verify()
        assert result.ok and result.checked == 3

    def test_log_redactor_runs_before_the_payload_is_hashed(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        log = open_log(trail, redactor=RegexRedactor())
        record_incident(
            log, a_record(summary="agent had used Bearer abcdefghijklmnop to call the API")
        )
        stored = disk_payloads(trail)[0]
        assert b"abcdefghijklmnop" not in stored
        assert b"abcdefghijklmnop" not in trail.read_bytes()
        assert REDACTED.encode() in stored

    def test_payload_hash_commits_to_the_redacted_bytes(self, tmp_path: Path) -> None:
        log = open_log(tmp_path / "trail.jsonl", redactor=RegexRedactor())
        entry = record_incident(log, a_record(summary="Bearer abcdefghijklmnop"))
        assert entry.payload is not None
        assert hashlib.sha256(entry.payload).hexdigest() == entry.header.payload_hash
        assert log.verify().ok

    def test_jsonl_and_sqlite_produce_identical_entry_hashes(self, tmp_path: Path) -> None:
        record = a_record(consequence_kinds=("tai san", "an ninh quoc gia"))
        jsonl_entry = record_incident(open_log(tmp_path / "t.jsonl"), record)
        sqlite_entry = record_incident(open_log(tmp_path / "t.db"), record)
        assert jsonl_entry.entry_hash == sqlite_entry.entry_hash
        assert jsonl_entry.payload == sqlite_entry.payload

    def test_a_tampered_incident_payload_is_detected(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        log = open_log(trail)
        record_incident(log, a_record())
        record_incident(log, a_record(incident_id="inc-2", severity="thap"))
        tamper_payload(trail, 1, b'"thap"', b'"caox"')
        result = open_log(trail).verify()
        assert not result.ok
        assert result.reason == "payload_hash_mismatch"
        assert result.broken_seq == 1

    def test_a_submission_is_recorded_by_appending_never_by_editing(
        self, tmp_path: Path
    ) -> None:
        # The append-only update path: the second row carries report_ref and
        # the reader folds them, latest row winning as a whole record.
        trail = tmp_path / "trail.jsonl"
        log = open_log(trail)
        record_incident(log, a_record(confirmed_at="2026-09-01T08:00:00+00:00"))
        record_incident(
            log,
            a_record(
                confirmed_at="2026-09-01T08:00:00+00:00",
                report_ref="CTT-2026-000123",
                reported_at="2026-09-02T09:00:00+00:00",
            ),
        )
        scan = scan_incidents(open_log(trail).entries())
        assert len(scan.views) == 1
        assert scan.views[0].rows == 2
        assert scan.views[0].latest.report_ref == "CTT-2026-000123"
        assert open_log(trail).verify().ok


class TestIterIncidents:
    def test_yields_only_incident_entries_at_row_level(self, tmp_path: Path) -> None:
        log = open_log(tmp_path / "trail.jsonl")
        log.append(payload={"tool": "bash"}, payload_type="application/vnd.test.tool+json")
        record_incident(log, a_record(incident_id="inc-a"))
        record_incident(log, a_record(incident_id="inc-a", report_ref="CTT-1"))
        record_incident(log, a_record(incident_id="inc-b"))

        found = list(iter_incidents(log))
        # Row level, not folded: folding is the domain's job.
        assert [e.header.seq for e, _ in found] == [1, 2, 3]
        assert [r.incident_id for _, r in found] == ["inc-a", "inc-a", "inc-b"]  # type: ignore[union-attr]

    def test_filters_by_incident_id(self, tmp_path: Path) -> None:
        log = open_log(tmp_path / "trail.jsonl")
        record_incident(log, a_record(incident_id="inc-a"))
        record_incident(log, a_record(incident_id="inc-b"))
        found = list(iter_incidents(log, incident_id="inc-b"))
        assert [r.incident_id for _, r in found] == ["inc-b"]  # type: ignore[union-attr]

    def test_malformed_payload_yields_none_rather_than_raising(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        log = open_log(trail)
        record_incident(log, a_record())
        record_incident(log, a_record(incident_id="inc-2"))
        tamper_payload(trail, 1, b'"inc-2"', b'123456')

        reopened = open_log(trail)
        found = list(iter_incidents(reopened))
        assert len(found) == 2
        assert found[1][1] is None
        assert not reopened.verify().ok

    def test_non_json_payload_yields_none(self, tmp_path: Path) -> None:
        log = open_log(tmp_path / "trail.jsonl")
        log.append(payload=b"not json at all", payload_type=INCIDENT_PAYLOAD_TYPE)
        assert [r for _, r in iter_incidents(log)] == [None]

    def test_entry_without_payload_bytes_yields_none(self, tmp_path: Path) -> None:
        from typing import cast

        from waxseal.adapters.memory import MemoryBackend
        from waxseal.domain.header import Entry

        log = AuditLog(MemoryBackend(), now_fn=lambda: FIXED_TS)
        record_incident(log, a_record())
        backend = cast(MemoryBackend, log._backend)
        stored = list(backend.entries())[0]
        backend._entries[0] = Entry(
            header=stored.header, entry_hash=stored.entry_hash, payload=None
        )
        assert [r for _, r in iter_incidents(log)] == [None]

    def test_an_unreadable_row_is_excluded_when_filtering_by_id(
        self, tmp_path: Path
    ) -> None:
        # An unreadable row has no incident_id to match on; counting it in on
        # the strength of a field nobody could read would be worse.
        log = open_log(tmp_path / "trail.jsonl")
        log.append(payload=b"{}", payload_type=INCIDENT_PAYLOAD_TYPE)
        assert list(iter_incidents(log, incident_id="inc-1")) == []

    def test_the_filter_says_out_loud_that_it_omits_unreadable_rows(self) -> None:
        # rule 6: a filter that drops rows must say so where a caller reads
        # it, not leave the omission for someone to discover from a count.
        doc = iter_incidents.__doc__ or ""
        assert "unreadable" in doc
        assert "scan_incidents" in doc

    @pytest.mark.parametrize("name", ["trail.jsonl", "trail.db"])
    def test_every_field_survives_the_round_trip_on_both_backends(
        self, tmp_path: Path, name: str
    ) -> None:
        log = open_log(tmp_path / name)
        record = a_record(
            confirmed_at="2026-09-01T08:00:00+00:00",
            summary="held the batch",
            consequence_kinds=("tai san", "dich vu cong, dich vu thiet yeu"),
            operating_status="da tam dung",
            report_ref="CTT-2026-000123",
            reported_at="2026-09-02T09:00:00+00:00",
            trace_id="trace-9",
        )
        record_incident(log, record)
        _, read_back = next(iter(iter_incidents(log)))
        assert read_back == record
