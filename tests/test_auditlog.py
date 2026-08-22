"""Tests for the AuditLog facade — the public API."""

import json
from pathlib import Path

import pytest

from waxseal import AuditLog

TS = "2026-08-21T06:00:00+00:00"
PT = "application/vnd.test.event+json"


def open_log(path: Path) -> AuditLog:
    return AuditLog.open(path, now_fn=lambda: TS)


class TestAppendAndVerify:
    def test_append_then_verify_ok(self, tmp_path: Path) -> None:
        log = open_log(tmp_path / "trail.jsonl")
        for i in range(5):
            log.append(payload={"i": i}, payload_type=PT)
        result = log.verify()
        assert result.ok
        assert result.checked == 5

    def test_dict_payload_is_canonical_json(self, tmp_path: Path) -> None:
        path = tmp_path / "trail.jsonl"
        open_log(path).append(payload={"b": 1, "a": 2}, payload_type=PT)
        import base64
        obj = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
        # sorted keys, compact separators, ascii — deterministic across runs
        assert base64.b64decode(obj["payload_b64"]) == b'{"a":2,"b":1}'

    def test_bytes_payload_is_stored_verbatim(self, tmp_path: Path) -> None:
        log = open_log(tmp_path / "trail.jsonl")
        entry = log.append(payload=b"raw-bytes", payload_type="application/octet-stream")
        assert entry.payload == b"raw-bytes"
        assert log.verify().ok

    def test_generic_payload_type_is_rejected(self, tmp_path: Path) -> None:
        # SPEC section 1 (DSSE rule): payload_type must be app-specific.
        log = open_log(tmp_path / "trail.jsonl")
        with pytest.raises(ValueError, match="payload_type"):
            log.append(payload={}, payload_type="application/json")

    def test_reopened_log_continues_the_chain(self, tmp_path: Path) -> None:
        path = tmp_path / "trail.jsonl"
        open_log(path).append(payload={"i": 0}, payload_type=PT)
        log2 = open_log(path)
        entry = log2.append(payload={"i": 1}, payload_type=PT)
        assert entry.header.seq == 1
        assert log2.verify().checked == 2


class TestTamperEndToEnd:
    def test_one_flipped_byte_on_disk_is_detected_at_the_right_seq(
        self, tmp_path: Path
    ) -> None:
        path = tmp_path / "trail.jsonl"
        log = open_log(path)
        for i in range(4):
            log.append(payload={"i": i}, payload_type=PT)
        lines = path.read_text(encoding="utf-8").splitlines()
        obj = json.loads(lines[2])
        obj["header"]["ts"] = "2027-01-01T00:00:00+00:00"
        lines[2] = json.dumps(obj)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        result = open_log(path).verify()
        assert not result.ok
        assert result.broken_seq == 2
        assert result.reason == "entry_hash_mismatch"


class TestDroppedWrites:
    """Chain integrity ≠ trail completeness (CLAUDE.md rule 5)."""

    def test_try_append_failure_increments_dropped_writes(self, tmp_path: Path) -> None:
        log = open_log(tmp_path / "trail.jsonl")
        log.append(payload={"i": 0}, payload_type=PT)
        # Unstorable payload type triggers a failure inside try_append.
        ok = log.try_append(payload=object(), payload_type=PT)  # type: ignore[arg-type]
        assert ok is False
        result = log.verify()
        assert result.ok  # chain is intact...
        assert result.dropped_writes == 1  # ...but the trail is incomplete.
        assert result.drops_source == "process"  # no recorder configured — in-memory only

    def test_dropped_writes_zero_when_measured_and_none_dropped(self, tmp_path: Path) -> None:
        log = open_log(tmp_path / "trail.jsonl")
        log.append(payload={"i": 0}, payload_type=PT)
        result = log.verify()
        assert result.dropped_writes == 0
        assert result.drops_source == "process"

    def test_verify_without_a_writer_reports_none_not_zero(self, tmp_path: Path) -> None:
        # A fresh process cannot know what an earlier process dropped.
        path = tmp_path / "trail.jsonl"
        open_log(path).append(payload={"i": 0}, payload_type=PT)
        fresh = open_log(path)
        result = fresh.verify(measure_drops=False)
        assert result.dropped_writes is None
        assert result.drops_source is None


class TestDropRecorderSidecar:
    """M5: a `.drops` sidecar makes the drop count durable across the
    process restarts a bare in-memory counter cannot survive."""

    def test_two_writer_instances_each_dropping_once_are_both_measured(
        self, tmp_path: Path
    ) -> None:
        # Simulates two separate hook processes writing to the same trail:
        # neither one's in-memory counter can see the other's drop, but a
        # shared sidecar does.
        path = tmp_path / "trail.jsonl"
        first = AuditLog.open(path, now_fn=lambda: TS, record_drops=True)
        first.append(payload={"i": 0}, payload_type=PT)
        first.try_append(payload=object(), payload_type=PT)  # type: ignore[arg-type]

        second = AuditLog.open(path, now_fn=lambda: TS, record_drops=True)
        second.try_append(payload=object(), payload_type=PT)  # type: ignore[arg-type]

        reader = AuditLog.open(path, now_fn=lambda: TS, record_drops=True)
        result = reader.verify()
        assert result.dropped_writes == 2
        assert result.drops_source == "sidecar"

    def test_empty_sidecar_reports_zero_not_none(self, tmp_path: Path) -> None:
        path = tmp_path / "trail.jsonl"
        log = AuditLog.open(path, now_fn=lambda: TS, record_drops=True)
        log.append(payload={"i": 0}, payload_type=PT)  # no drops — sidecar never created
        result = log.verify()
        assert result.dropped_writes == 0  # measured: zero seen...
        assert result.drops_source == "sidecar"  # ...not "never measured"

    def test_deleting_the_sidecar_reads_back_as_measured_zero_not_a_crash(
        self, tmp_path: Path
    ) -> None:
        # An AuditLog with a configured recorder trusts it unconditionally
        # (drops_source stays "sidecar") — it cannot tell "deleted" from
        # "never written", so deletion reads back as a measured 0, not a
        # crash or a silent revert to None. The None-vs-0 distinction lives
        # one layer up, in the CLI's own read_drop_count() sidecar peek
        # (module-level function, tested in tests/adapters/test_drops.py),
        # which DOES see file-absence directly and reports None for it.
        path = tmp_path / "trail.jsonl"
        log = AuditLog.open(path, now_fn=lambda: TS, record_drops=True)
        log.append(payload={"i": 0}, payload_type=PT)
        log.try_append(payload=object(), payload_type=PT)  # type: ignore[arg-type]
        assert log.verify().dropped_writes == 1

        (path.parent / (path.name + ".drops")).unlink()
        result = log.verify()
        assert result.dropped_writes == 0
        assert result.drops_source == "sidecar"

    def test_recorder_never_raises_even_when_the_trail_dir_becomes_unwritable(
        self, tmp_path: Path
    ) -> None:
        import os
        import sys

        if sys.platform == "win32":
            pytest.skip("POSIX permission bits")
        if os.geteuid() == 0:
            pytest.skip("root bypasses permission checks")
        path = tmp_path / "trail.jsonl"
        log = AuditLog.open(path, now_fn=lambda: TS, record_drops=True)
        log.append(payload={"i": 0}, payload_type=PT)
        tmp_path.chmod(0o500)
        try:
            ok = log.try_append(payload=object(), payload_type=PT)  # type: ignore[arg-type]
        finally:
            tmp_path.chmod(0o700)
        assert ok is False  # try_append still fails open, never raises


class TestBackendDispatch:
    def test_unknown_extension_is_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="backend"):
            AuditLog.open(tmp_path / "trail.txt")
