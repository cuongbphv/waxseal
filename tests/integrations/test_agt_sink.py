"""Tests for the AGT audit sink (integrations/agt.py).

Contract verified against agent-governance-toolkit 4.1.0 /
agent-governance-toolkit-core 4.1.0 (real PyPI wheels downloaded and read,
2026-09-01) and re-checked against agent-governance-toolkit-core 5.0.0:

- `agentmesh.governance.audit_backends.AuditSink` is a `@runtime_checkable
  Protocol` (write/write_batch/verify_integrity/close). AGT's own
  `AuditLog.log()` calls `sink.write(entry)` synchronously with NO
  try/except of its own — a raise from the sink aborts the governed call,
  so this sink's own never-veto discipline is load-bearing here, more so
  than the other 8 integrations whose HOST already swallows a raise.
- `AuditEntry` carries no model identity anywhere in its schema — verified
  by reading the pydantic model definition directly, not inferred.

AGT is NOT a test dependency and no fake module is registered in
sys.modules: `WaxsealAuditSink.write` reads its `entry` argument purely by
`getattr`, never by isinstance-checking an AGT type (that is the whole
point of it satisfying a structural Protocol without importing anything),
so a plain `SimpleNamespace` reproduces the verified `AuditEntry` shape
without needing agentmesh installed or faked.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from waxseal import AuditLog
from waxseal.domain.decision import DECISION_PAYLOAD_TYPE, ModelRef
from waxseal.integrations.agt import PAYLOAD_TYPE, WaxsealAuditSink


def audit_entry(**overrides: object) -> SimpleNamespace:
    """Reproduces the verified AuditEntry shape (agentmesh.governance.audit)."""
    fields: dict[str, object] = dict(
        entry_id="audit_abc123",
        event_type="policy_evaluation",
        agent_did="did:web:agent-1",
        action="read_file",
        resource="/etc/passwd",
        outcome="allow",
        policy_decision="allow",
        matched_rule="rule-42",
        policy_version="v1",
        data={"reason": "matches allow rule"},
        trace_id="trace-1",
        session_id="session-1",
        approver_did=None,
    )
    fields.update(overrides)
    return SimpleNamespace(**fields)


def read_line(trail: Path, line_no: int = 0) -> dict:
    line = trail.read_text().splitlines()[line_no]
    return json.loads(line)


def read_payload(trail: Path, line_no: int = 0) -> dict:
    return json.loads(base64.b64decode(read_line(trail, line_no)["payload_b64"]))


class TestPayloadShape:
    def test_write_produces_agt_event_payload_type(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        WaxsealAuditSink(trail).write(audit_entry())
        assert read_line(trail)["header"]["payload_type"] == PAYLOAD_TYPE

    def test_minimum_fields_all_land(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        WaxsealAuditSink(trail).write(audit_entry())
        payload = read_payload(trail)
        assert payload["agent_did"] == "did:web:agent-1"
        assert payload["action"] == "read_file"
        assert payload["outcome"] == "allow"
        assert payload["policy_decision"] == "allow"
        assert payload["matched_rule"] == "rule-42"
        assert payload["policy_version"] == "v1"
        assert payload["reason"] == "matches allow rule"
        assert payload["entry_id"] == "audit_abc123"
        assert payload["trace_id"] == "trace-1"
        assert payload["session_id"] == "session-1"

    def test_entry_with_no_data_dict_still_serializes(self, tmp_path: Path) -> None:
        # AuditEntry.data defaults to {}, but a non-dict is read defensively.
        trail = tmp_path / "trail.jsonl"
        WaxsealAuditSink(trail).write(audit_entry(data=None))
        payload = read_payload(trail)
        assert payload["reason"] is None
        assert payload["data"] == {}

    def test_write_batch_chains_every_entry(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        sink = WaxsealAuditSink(trail)
        sink.write_batch([audit_entry(entry_id="a"), audit_entry(entry_id="b")])
        result = AuditLog.open(trail).verify(measure_drops=False)
        assert result.ok
        assert result.checked == 2
        assert read_payload(trail, 0)["entry_id"] == "a"
        assert read_payload(trail, 1)["entry_id"] == "b"


class TestRedactionAndClipping:
    def test_secret_in_data_never_reaches_disk(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        secret = "sk-abcdef1234567890abcdef"
        WaxsealAuditSink(trail).write(
            audit_entry(data={"reason": f"blocked header Bearer {secret}"})
        )
        assert secret.encode() not in trail.read_bytes()
        assert AuditLog.open(trail).verify(measure_drops=False).ok

    def test_huge_data_field_is_clipped_with_visible_marker(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        WaxsealAuditSink(trail).write(
            audit_entry(data={"excerpt": "y" * 1_000_000})
        )
        assert len(trail.read_bytes()) < 100_000
        assert "truncated" in read_payload(trail)["data"]["excerpt"]


class TestSanitizeShapes:
    def test_list_values_are_sanitized_recursively(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        secret = "sk-abcdef1234567890abcdef"
        WaxsealAuditSink(trail).write(
            audit_entry(data={"headers": [f"Bearer {secret}", "ok"]})
        )
        assert secret.encode() not in trail.read_bytes()
        assert read_payload(trail)["data"]["headers"] == ["Bearer ***REDACTED***", "ok"]

    def test_arbitrary_object_values_fall_back_to_redacted_repr(self, tmp_path: Path) -> None:
        class Blob:
            def __repr__(self) -> str:
                return "Blob(id=1)"

        trail = tmp_path / "trail.jsonl"
        WaxsealAuditSink(trail).write(audit_entry(data={"raw": Blob()}))
        assert read_payload(trail)["data"]["raw"] == "Blob(id=1)"


class TestDecisionMapping:
    MODEL = ModelRef(name="gpt-guard", version="1.0")

    def test_without_a_configured_model_stays_a_plain_agt_event(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        WaxsealAuditSink(trail).write(audit_entry())
        assert read_line(trail)["header"]["payload_type"] == PAYLOAD_TYPE

    def test_full_shape_with_model_maps_to_decision_record(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        WaxsealAuditSink(trail, model=self.MODEL, system_id="agt-gateway").write(audit_entry())
        line = read_line(trail)
        assert line["header"]["payload_type"] == DECISION_PAYLOAD_TYPE
        payload = read_payload(trail)
        assert payload["decision_id"] == "audit_abc123"
        assert payload["decision_type"] == "policy_evaluation"
        assert payload["system_id"] == "agt-gateway"
        assert payload["model"] == {"name": "gpt-guard", "version": "1.0", "digest": None}
        assert payload["outcome"] == "allow"
        assert payload["rationale"] == "matches allow rule"
        assert payload["policy_version"] == "v1"
        assert payload["trace_id"] == "trace-1"
        assert len(payload["input_commitment"]) == 64
        assert payload["human_oversight"] is None  # AGT did not say (None, never "unrecorded")

    def test_approver_did_becomes_human_oversight(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        WaxsealAuditSink(trail, model=self.MODEL).write(
            audit_entry(event_type="approval_decision", approver_did="did:web:reviewer-1")
        )
        oversight = read_payload(trail)["human_oversight"]
        assert oversight == {
            "mode": "agt_approval", "reviewer_ref": "did:web:reviewer-1", "action": None,
        }

    def test_missing_action_falls_back_to_agt_event(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        WaxsealAuditSink(trail, model=self.MODEL).write(audit_entry(action=None))
        assert read_line(trail)["header"]["payload_type"] == PAYLOAD_TYPE

    def test_missing_outcome_falls_back_to_agt_event(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        WaxsealAuditSink(trail, model=self.MODEL).write(audit_entry(outcome=None))
        assert read_line(trail)["header"]["payload_type"] == PAYLOAD_TYPE

    def test_missing_entry_id_falls_back_to_agt_event(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        WaxsealAuditSink(trail, model=self.MODEL).write(audit_entry(entry_id=None))
        assert read_line(trail)["header"]["payload_type"] == PAYLOAD_TYPE

    def test_decision_record_rejection_falls_back_to_agt_event(self, tmp_path: Path) -> None:
        # A non-string reason survives _sanitize as-is (ints pass through
        # unchanged), then DecisionRecord.__post_init__ rejects it as
        # rationale (must be str or null) — "does not match", not a crash.
        trail = tmp_path / "trail.jsonl"
        WaxsealAuditSink(trail, model=self.MODEL).write(audit_entry(data={"reason": 42}))
        assert read_line(trail)["header"]["payload_type"] == PAYLOAD_TYPE


class TestNeverVetoesAGT:
    def test_open_failure_never_raises_and_labels_the_drop(
        self, tmp_path: Path, capsys, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            AuditLog, "open",
            staticmethod(lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("x"))),
        )
        trail = tmp_path / "trail.jsonl"
        WaxsealAuditSink(trail).write(audit_entry())
        assert "dropped" in capsys.readouterr().err
        drops = tmp_path / "trail.jsonl.drops"
        assert drops.exists()
        assert len(drops.read_text().splitlines()) == 1

    def test_try_append_failure_never_raises_and_labels_the_drop(
        self, tmp_path: Path, capsys
    ) -> None:
        blocked = tmp_path / "blocked"
        blocked.write_text("a file where the trail dir should be")
        WaxsealAuditSink(blocked / "trail.jsonl").write(audit_entry())
        assert "dropped" in capsys.readouterr().err

    def test_malformed_entry_never_raises_and_labels_the_drop(
        self, tmp_path: Path, capsys
    ) -> None:
        class Poison:
            @property
            def data(self) -> dict:
                raise RuntimeError("entry is not what it claims to be")

        trail = tmp_path / "trail.jsonl"
        WaxsealAuditSink(trail).write(Poison())
        assert "dropped" in capsys.readouterr().err
        drops = tmp_path / "trail.jsonl.drops"
        assert drops.exists()
        assert AuditLog.open(trail).verify(measure_drops=False).checked == 0

    def test_write_batch_never_raises_per_entry_failure(self, tmp_path: Path, capsys) -> None:
        blocked = tmp_path / "blocked"
        blocked.write_text("a file where the trail dir should be")
        sink = WaxsealAuditSink(blocked / "trail.jsonl")
        sink.write_batch([audit_entry(), audit_entry()])
        assert "dropped" in capsys.readouterr().err


class TestVerifyIntegrityAndClose:
    def test_verify_integrity_reports_intact(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        sink = WaxsealAuditSink(trail)
        sink.write(audit_entry())
        ok, reason = sink.verify_integrity()
        assert ok is True
        assert reason is None

    def test_verify_integrity_reports_the_open_failure(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            AuditLog, "open",
            staticmethod(lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("boom"))),
        )
        ok, reason = WaxsealAuditSink(tmp_path / "trail.jsonl").verify_integrity()
        assert ok is False
        assert reason is not None and "boom" in reason

    def test_close_is_a_no_op(self, tmp_path: Path) -> None:
        assert WaxsealAuditSink(tmp_path / "trail.jsonl").close() is None


class TestTrailResolution:
    def test_explicit_trail_wins_over_env(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("WAXSEAL_TRAIL", str(tmp_path / "env-trail.jsonl"))
        explicit = tmp_path / "explicit-trail.jsonl"
        WaxsealAuditSink(explicit).write(audit_entry())
        assert explicit.exists()
        assert not (tmp_path / "env-trail.jsonl").exists()

    def test_env_wins_over_default(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        env_trail = tmp_path / "env-trail.jsonl"
        monkeypatch.setenv("WAXSEAL_TRAIL", str(env_trail))
        WaxsealAuditSink().write(audit_entry())
        assert env_trail.exists()

    def test_default_trail_lands_under_home(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("WAXSEAL_TRAIL", raising=False)
        monkeypatch.setenv("HOME", str(tmp_path))
        WaxsealAuditSink().write(audit_entry())
        assert (tmp_path / ".waxseal" / "agt-trail.jsonl").exists()
