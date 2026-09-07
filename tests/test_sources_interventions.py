"""Tests for the human-intervention source: recording interventions onto a chain.

Same short list as the incident source: the log's redactor runs BEFORE the
payload is hashed (a rationale is free text a human typed while stopping
something), the payload bytes are canonical, the two backends agree
byte-for-byte, and reading rows back never aborts over one rewritten row.
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
from waxseal.domain.intervention import (
    INTERVENTION_PAYLOAD_TYPE,
    InterventionRecord,
    scan_interventions,
    to_payload,
)
from waxseal.sources.interventions import iter_interventions, record_intervention

FIXED_TS = "2026-09-01T09:00:00+00:00"


def open_log(path: Path, **kwargs: object) -> AuditLog:
    return AuditLog.open(path, now_fn=lambda: FIXED_TS, **kwargs)  # type: ignore[arg-type]


def disk_payloads(trail: Path) -> list[bytes]:
    return [
        base64.b64decode(json.loads(line)["payload_b64"])
        for line in trail.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def tamper_payload(trail: Path, seq: int, old: bytes, new: bytes) -> None:
    lines = trail.read_text(encoding="utf-8").splitlines()
    obj = json.loads(lines[seq])
    payload = base64.b64decode(obj["payload_b64"]).replace(old, new)
    obj["payload_b64"] = base64.b64encode(payload).decode("ascii")
    lines[seq] = json.dumps(obj)
    trail.write_text("\n".join(lines) + "\n", encoding="utf-8")


def a_record(**overrides: Any) -> InterventionRecord:
    base: dict[str, Any] = {
        "intervention_id": "iv-1",
        "system_id": "AI-ID-2026-0001",
        "actor_ref": "analyst-7",
        "action": "halt",
    }
    base.update(overrides)
    return InterventionRecord(**base)


class TestRecordIntervention:
    def test_entry_carries_the_intervention_payload_type(self, tmp_path: Path) -> None:
        log = open_log(tmp_path / "trail.jsonl")
        entry = record_intervention(log, a_record())
        assert entry.header.payload_type == INTERVENTION_PAYLOAD_TYPE

    def test_payload_bytes_are_the_canonical_serialization(self, tmp_path: Path) -> None:
        log = open_log(tmp_path / "trail.jsonl")
        record = a_record(decision_ref="d-88")
        entry = record_intervention(log, record)
        assert entry.payload is not None
        assert json.loads(entry.payload) == to_payload(record)
        assert entry.payload == json.dumps(
            to_payload(record), sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")

    def test_recorded_interventions_chain_and_verify(self, tmp_path: Path) -> None:
        log = open_log(tmp_path / "trail.jsonl")
        for i in range(3):
            record_intervention(log, a_record(intervention_id=f"iv-{i}"))
        result = log.verify()
        assert result.ok and result.checked == 3

    def test_the_header_ts_is_the_time_of_the_act(self, tmp_path: Path) -> None:
        # There is deliberately no occurred_at field: unlike an incident, the
        # intervention IS the act being recorded.
        log = open_log(tmp_path / "trail.jsonl")
        entry = record_intervention(log, a_record())
        assert entry.header.ts == FIXED_TS
        assert "occurred_at" not in to_payload(a_record())

    def test_log_redactor_runs_before_the_payload_is_hashed(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        log = open_log(trail, redactor=RegexRedactor())
        record_intervention(
            log, a_record(rationale="revoked the key Bearer abcdefghijklmnop by hand")
        )
        stored = disk_payloads(trail)[0]
        assert b"abcdefghijklmnop" not in stored
        assert b"abcdefghijklmnop" not in trail.read_bytes()
        assert REDACTED.encode() in stored

    def test_payload_hash_commits_to_the_redacted_bytes(self, tmp_path: Path) -> None:
        log = open_log(tmp_path / "trail.jsonl", redactor=RegexRedactor())
        entry = record_intervention(log, a_record(rationale="Bearer abcdefghijklmnop"))
        assert entry.payload is not None
        assert hashlib.sha256(entry.payload).hexdigest() == entry.header.payload_hash
        assert log.verify().ok

    def test_jsonl_and_sqlite_produce_identical_entry_hashes(self, tmp_path: Path) -> None:
        record = a_record(decision_ref="d-88", rationale="held")
        jsonl_entry = record_intervention(open_log(tmp_path / "t.jsonl"), record)
        sqlite_entry = record_intervention(open_log(tmp_path / "t.db"), record)
        assert jsonl_entry.entry_hash == sqlite_entry.entry_hash
        assert jsonl_entry.payload == sqlite_entry.payload

    def test_a_tampered_intervention_payload_is_detected(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        log = open_log(trail)
        record_intervention(log, a_record())
        record_intervention(log, a_record(intervention_id="iv-2", action="override"))
        tamper_payload(trail, 1, b'"override"', b'"overrid3"')
        result = open_log(trail).verify()
        assert not result.ok
        assert result.reason == "payload_hash_mismatch"
        assert result.broken_seq == 1

    def test_recorded_rows_are_readable_by_the_domain_scan(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        log = open_log(trail)
        record_intervention(log, a_record(action="dừng khẩn cấp"))
        scan = scan_interventions(open_log(trail).entries())
        assert [r.action for _, r in scan.records] == ["dừng khẩn cấp"]
        assert scan.unreadable == ()


class TestIterInterventions:
    def test_yields_only_intervention_entries(self, tmp_path: Path) -> None:
        log = open_log(tmp_path / "trail.jsonl")
        log.append(payload={"tool": "bash"}, payload_type="application/vnd.test.tool+json")
        record_intervention(log, a_record(intervention_id="iv-a"))
        log.append(payload={"tool": "ls"}, payload_type="application/vnd.test.tool+json")
        record_intervention(log, a_record(intervention_id="iv-b"))

        found = list(iter_interventions(log))
        assert [r.intervention_id for _, r in found] == ["iv-a", "iv-b"]  # type: ignore[union-attr]
        assert [e.header.seq for e, _ in found] == [1, 3]

    def test_filters_by_decision_ref(self, tmp_path: Path) -> None:
        log = open_log(tmp_path / "trail.jsonl")
        record_intervention(log, a_record(intervention_id="iv-a", decision_ref="d-1"))
        record_intervention(log, a_record(intervention_id="iv-b", decision_ref="d-2"))
        record_intervention(log, a_record(intervention_id="iv-c"))
        found = list(iter_interventions(log, decision_ref="d-2"))
        assert [r.intervention_id for _, r in found] == ["iv-b"]  # type: ignore[union-attr]

    def test_malformed_payload_yields_none_rather_than_raising(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        log = open_log(trail)
        record_intervention(log, a_record())
        record_intervention(log, a_record(intervention_id="iv-2"))
        tamper_payload(trail, 1, b'"iv-2"', b'123456')

        reopened = open_log(trail)
        found = list(iter_interventions(reopened))
        assert len(found) == 2
        assert found[1][1] is None
        assert not reopened.verify().ok

    def test_non_json_payload_yields_none(self, tmp_path: Path) -> None:
        log = open_log(tmp_path / "trail.jsonl")
        log.append(payload=b"not json at all", payload_type=INTERVENTION_PAYLOAD_TYPE)
        assert [r for _, r in iter_interventions(log)] == [None]

    def test_entry_without_payload_bytes_yields_none(self, tmp_path: Path) -> None:
        from typing import cast

        from waxseal.adapters.memory import MemoryBackend
        from waxseal.domain.header import Entry

        log = AuditLog(MemoryBackend(), now_fn=lambda: FIXED_TS)
        record_intervention(log, a_record())
        backend = cast(MemoryBackend, log._backend)
        stored = list(backend.entries())[0]
        backend._entries[0] = Entry(
            header=stored.header, entry_hash=stored.entry_hash, payload=None
        )
        assert [r for _, r in iter_interventions(log)] == [None]

    def test_an_unreadable_row_is_excluded_when_filtering_by_decision_ref(
        self, tmp_path: Path
    ) -> None:
        log = open_log(tmp_path / "trail.jsonl")
        log.append(payload=b"{}", payload_type=INTERVENTION_PAYLOAD_TYPE)
        assert list(iter_interventions(log, decision_ref="d-1")) == []

    def test_the_filter_says_out_loud_that_it_omits_unreadable_rows(self) -> None:
        doc = iter_interventions.__doc__ or ""
        assert "unreadable" in doc
        assert "scan_interventions" in doc

    @pytest.mark.parametrize("name", ["trail.jsonl", "trail.db"])
    def test_every_field_survives_the_round_trip_on_both_backends(
        self, tmp_path: Path, name: str
    ) -> None:
        log = open_log(tmp_path / name)
        record = a_record(
            decision_ref="d-88", rationale="threshold drift", trace_id="trace-3"
        )
        record_intervention(log, record)
        _, read_back = next(iter(iter_interventions(log)))
        assert read_back == record
