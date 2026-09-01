"""Tests for the AI decision source: recording decisions onto a chain.

This is the layer a bank's agent actually calls. What it must get right:
redaction runs before anything is hashed (including the input commitment),
the payload bytes are the canonical ones the chain already defines, and
reading decisions back never crashes on a row somebody rewrote.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest

from waxseal import AuditLog
from waxseal.adapters.redactors import REDACTED, RegexRedactor
from waxseal.domain.decision import (
    DECISION_PAYLOAD_TYPE,
    DecisionRecord,
    HumanOversight,
    ModelRef,
    to_payload,
)
from waxseal.sources.decisions import commit_input, iter_decisions, record_decision

FIXED_TS = "2026-08-23T09:00:00+00:00"


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


def a_record(**overrides: object) -> DecisionRecord:
    base: dict[str, object] = {
        "decision_id": "d-1",
        "decision_type": "transaction_approval",
        "system_id": "payments-agent",
        "model": ModelRef(name="risk-llm", version="2026.08"),
        "input_commitment": commit_input({"amount": 100}),
        "outcome": "approve",
    }
    base.update(overrides)
    return DecisionRecord(**base)  # type: ignore[arg-type]


class TestCommitInput:
    def test_commitment_is_the_sha256_of_the_canonical_payload_bytes(self) -> None:
        expected = hashlib.sha256(b'{"amount":100,"currency":"VND"}').hexdigest()
        assert commit_input({"currency": "VND", "amount": 100}) == expected

    def test_key_order_does_not_change_the_commitment(self) -> None:
        assert commit_input({"a": 1, "b": 2}) == commit_input({"b": 2, "a": 1})

    def test_bytes_input_is_committed_as_given(self) -> None:
        assert commit_input(b"raw") == hashlib.sha256(b"raw").hexdigest()

    def test_redactor_runs_before_the_commitment_is_computed(self) -> None:
        # The security property: the commitment is over the redacted form, so
        # it cannot be used to confirm a guess at the real secret. Without
        # this ordering the trail would leak a verifier for the cleartext.
        secret = {"api_key": "sk-abcdefghijklmnopqrstuvwx"}
        assert commit_input(secret, redactor=RegexRedactor()) == commit_input(
            {"api_key": REDACTED}
        )

    def test_two_different_secrets_share_one_commitment_once_redacted(self) -> None:
        r = RegexRedactor()
        one = commit_input({"api_key": "sk-aaaaaaaaaaaaaaaaaaaaaaaa"}, redactor=r)
        two = commit_input({"api_key": "sk-bbbbbbbbbbbbbbbbbbbbbbbb"}, redactor=r)
        assert one == two

    def test_a_redactor_is_not_applied_to_bytes_input(self) -> None:
        # Bytes are opaque to the dict-shaped Redactor port; silently passing
        # them through a redactor that cannot see inside would be a fail-open
        # guard pretending to work (rule 6). Refuse instead.
        with pytest.raises(ValueError, match="bytes"):
            commit_input(b"raw", redactor=RegexRedactor())

    def test_non_dict_non_bytes_input_is_rejected(self) -> None:
        with pytest.raises(TypeError):
            commit_input("a string")  # type: ignore[arg-type]

    def test_commitment_is_a_valid_record_input_commitment(self) -> None:
        DecisionRecord(
            decision_id="d",
            decision_type="t",
            system_id="s",
            model=ModelRef(name="m", version="v"),
            input_commitment=commit_input({}),
            outcome="approve",
        )


class TestRecordDecision:
    def test_entry_carries_the_decision_payload_type(self, tmp_path: Path) -> None:
        log = open_log(tmp_path / "trail.jsonl")
        entry = record_decision(log, a_record())
        assert entry.header.payload_type == DECISION_PAYLOAD_TYPE

    def test_payload_bytes_are_the_canonical_serialization(self, tmp_path: Path) -> None:
        log = open_log(tmp_path / "trail.jsonl")
        record = a_record()
        entry = record_decision(log, record)
        assert entry.payload is not None
        assert json.loads(entry.payload) == to_payload(record)
        # Canonical: sorted keys, no whitespace. Two writers must produce the
        # same bytes for the same record or their hashes disagree.
        assert entry.payload == json.dumps(
            to_payload(record), sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")

    def test_recorded_decisions_chain_and_verify(self, tmp_path: Path) -> None:
        log = open_log(tmp_path / "trail.jsonl")
        for i in range(3):
            record_decision(log, a_record(decision_id=f"d-{i}"))
        result = log.verify()
        assert result.ok and result.checked == 3

    def test_log_redactor_runs_before_the_payload_is_hashed(self, tmp_path: Path) -> None:
        # A rationale is free text an agent wrote; it is exactly where a
        # pasted token ends up. Cleartext must never reach disk.
        trail = tmp_path / "trail.jsonl"
        log = open_log(trail, redactor=RegexRedactor())
        record_decision(
            log, a_record(rationale="checked with Bearer abcdefghijklmnop")
        )
        stored = disk_payloads(trail)[0]
        assert b"abcdefghijklmnop" not in stored
        assert b"abcdefghijklmnop" not in trail.read_bytes()
        assert REDACTED.encode() in stored

    def test_payload_hash_commits_to_the_redacted_bytes(self, tmp_path: Path) -> None:
        log = open_log(tmp_path / "trail.jsonl", redactor=RegexRedactor())
        entry = record_decision(log, a_record(rationale="Bearer abcdefghijklmnop"))
        assert entry.payload is not None
        assert hashlib.sha256(entry.payload).hexdigest() == entry.header.payload_hash
        assert log.verify().ok

    def test_jsonl_and_sqlite_produce_identical_entry_hashes(self, tmp_path: Path) -> None:
        # Backend parity: the same decision must hash byte-for-byte alike, or
        # a trail migrated between backends would read as tampered.
        record = a_record()
        jsonl_entry = record_decision(open_log(tmp_path / "t.jsonl"), record)
        sqlite_entry = record_decision(open_log(tmp_path / "t.db"), record)
        assert jsonl_entry.entry_hash == sqlite_entry.entry_hash
        assert jsonl_entry.payload == sqlite_entry.payload

    def test_a_tampered_decision_payload_is_detected(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        log = open_log(trail)
        record_decision(log, a_record(outcome="deny"))
        tamper_payload(trail, 0, b'"deny"', b'"appr"')
        result = open_log(trail).verify()
        assert not result.ok
        assert result.reason == "payload_hash_mismatch"
        assert result.broken_seq == 0


class TestIterDecisions:
    def test_yields_only_decision_entries(self, tmp_path: Path) -> None:
        log = open_log(tmp_path / "trail.jsonl")
        log.append(payload={"tool": "bash"}, payload_type="application/vnd.test.tool+json")
        record_decision(log, a_record(decision_id="d-a"))
        log.append(payload={"tool": "ls"}, payload_type="application/vnd.test.tool+json")
        record_decision(log, a_record(decision_id="d-b"))

        found = list(iter_decisions(log))
        assert [r.decision_id for _, r in found] == ["d-a", "d-b"]  # type: ignore[union-attr]
        assert [e.header.seq for e, _ in found] == [1, 3]

    def test_filters_by_decision_type(self, tmp_path: Path) -> None:
        log = open_log(tmp_path / "trail.jsonl")
        record_decision(log, a_record(decision_id="d-a", decision_type="risk_scanning"))
        record_decision(log, a_record(decision_id="d-b", decision_type="payment"))
        found = list(iter_decisions(log, decision_type="payment"))
        assert [r.decision_id for _, r in found] == ["d-b"]  # type: ignore[union-attr]

    def test_malformed_payload_yields_none_rather_than_raising(self, tmp_path: Path) -> None:
        # rule 6: a row this reader cannot parse is reported, never silently
        # skipped and never allowed to abort the audit of the other rows.
        trail = tmp_path / "trail.jsonl"
        log = open_log(trail)
        record_decision(log, a_record())
        record_decision(log, a_record(decision_id="d-2"))
        tamper_payload(trail, 1, b'"d-2"', b'12345')

        found = list(iter_decisions(trail_log := open_log(trail)))
        assert len(found) == 2
        assert found[1][1] is None
        # The chain still has its own, separate verdict about those bytes.
        assert not trail_log.verify().ok

    def test_non_json_payload_yields_none(self, tmp_path: Path) -> None:
        log = open_log(tmp_path / "trail.jsonl")
        log.append(payload=b"not json at all", payload_type=DECISION_PAYLOAD_TYPE)
        assert [r for _, r in iter_decisions(log)] == [None]

    def test_malformed_row_is_excluded_when_filtering_by_type(self, tmp_path: Path) -> None:
        # An unparseable row has no decision_type to match; it must not be
        # silently counted into a filtered view as if it did.
        log = open_log(tmp_path / "trail.jsonl")
        log.append(payload=b"{}", payload_type=DECISION_PAYLOAD_TYPE)
        assert list(iter_decisions(log, decision_type="payment")) == []

    def test_entry_without_payload_bytes_yields_none(self, tmp_path: Path) -> None:
        # A header-only reader (Entry.payload is None) has nothing to parse;
        # that is "not available here", not "malformed".
        from typing import cast

        from waxseal.adapters.memory import MemoryBackend
        from waxseal.domain.header import Entry

        log = AuditLog(MemoryBackend(), now_fn=lambda: FIXED_TS)
        record_decision(log, a_record())
        stored = list(log._backend.entries())[0]
        # AuditLog.__init__ types its backend param `JSONLBackend | Any` --
        # cast rather than reach for the private attribute through a name
        # mypy can partly see, since MemoryBackend is neither JSONLBackend
        # nor a declared member of that union.
        backend = cast(MemoryBackend, log._backend)
        backend._entries[0] = Entry(
            header=stored.header, entry_hash=stored.entry_hash, payload=None
        )
        assert [r for _, r in iter_decisions(log)] == [None]

    def test_oversight_survives_the_round_trip(self, tmp_path: Path) -> None:
        log = open_log(tmp_path / "trail.jsonl")
        oversight = HumanOversight(mode="reviewed", reviewer_ref="analyst-7", action="confirmed")
        record_decision(log, a_record(human_oversight=oversight))
        _, read_back = next(iter(iter_decisions(log)))
        assert read_back is not None
        assert read_back.human_oversight == oversight
