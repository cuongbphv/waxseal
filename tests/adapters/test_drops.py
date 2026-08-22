"""FileDropRecorder: a metadata-only sidecar recording dropped writes.

CLAUDE.md rule 5 in sidecar form: the count is "at least N measured", never
"exactly N" (a recorder that itself fails to write loses no MORE honesty than
it already had — None stays None, and the recorder must never raise back
into the caller's own best-effort try_append)."""

import json
from pathlib import Path

import pytest

from waxseal.adapters.drops import FileDropRecorder, read_drop_count


class TestRecord:
    def test_record_appends_metadata_only_json_line(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        recorder = FileDropRecorder(trail, now_fn=lambda: "2026-08-22T00:00:00+00:00")
        recorder.record(reason="ValueError", payload_type="application/vnd.test+json")
        lines = (tmp_path / "trail.jsonl.drops").read_text().splitlines()
        assert len(lines) == 1
        obj = json.loads(lines[0])
        assert set(obj) == {"payload_type", "reason", "source", "ts", "v"}
        assert obj["reason"] == "ValueError"
        assert obj["payload_type"] == "application/vnd.test+json"
        assert obj["source"] == "library"
        assert obj["v"] == 1

    def test_payload_type_defaults_to_none(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        recorder = FileDropRecorder(trail, now_fn=lambda: "2026-08-22T00:00:00+00:00")
        recorder.record(reason="TypeError")
        obj = json.loads((tmp_path / "trail.jsonl.drops").read_text().splitlines()[0])
        assert obj["payload_type"] is None

    def test_source_is_overridable(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        recorder = FileDropRecorder(trail, source="claude_code_hook")
        recorder.record(reason="OSError")
        obj = json.loads((tmp_path / "trail.jsonl.drops").read_text().splitlines()[0])
        assert obj["source"] == "claude_code_hook"

    def test_never_contains_payload_content(self, tmp_path: Path) -> None:
        # The record is metadata-only by construction (record()'s signature
        # has no field for payload bytes) — this pins that the object shape
        # never grows one by accident.
        trail = tmp_path / "trail.jsonl"
        recorder = FileDropRecorder(trail)
        recorder.record(reason="ValueError", payload_type="application/vnd.test+json")
        obj = json.loads((tmp_path / "trail.jsonl.drops").read_text().splitlines()[0])
        assert "payload" not in obj

    def test_multiple_records_append_in_order(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        recorder = FileDropRecorder(trail)
        for reason in ("ValueError", "TypeError", "OSError"):
            recorder.record(reason=reason)
        lines = (tmp_path / "trail.jsonl.drops").read_text().splitlines()
        assert [json.loads(line)["reason"] for line in lines] == [
            "ValueError", "TypeError", "OSError",
        ]


class TestCount:
    def test_count_matches_number_of_records(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        recorder = FileDropRecorder(trail)
        assert recorder.count() == 0
        recorder.record(reason="ValueError")
        recorder.record(reason="TypeError")
        assert recorder.count() == 2

    def test_count_is_zero_not_none_when_sidecar_absent(self, tmp_path: Path) -> None:
        # count() is a measured "at least 0" for THIS sidecar, distinct from
        # the None a caller reports when there is no recorder at all.
        recorder = FileDropRecorder(tmp_path / "trail.jsonl")
        assert recorder.count() == 0


class TestReadDropCount:
    def test_read_drop_count_matches_file(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        recorder = FileDropRecorder(trail)
        recorder.record(reason="ValueError")
        recorder.record(reason="TypeError")
        assert read_drop_count(trail) == 2

    def test_read_drop_count_is_none_when_sidecar_absent(self, tmp_path: Path) -> None:
        # Module-level reader: None means "never measured" — distinct from
        # FileDropRecorder.count()'s 0, which means "measured, zero seen".
        assert read_drop_count(tmp_path / "trail.jsonl") is None


class TestSidecarPermissions:
    def test_drops_sidecar_is_created_owner_only(self, tmp_path: Path) -> None:
        import os
        import sys

        if sys.platform == "win32":
            pytest.skip("POSIX permission bits")
        old_umask = os.umask(0o022)
        try:
            trail = tmp_path / "trail.jsonl"
            FileDropRecorder(trail).record(reason="ValueError")
            mode = (tmp_path / "trail.jsonl.drops").stat().st_mode
            assert (mode & 0o777) == 0o600
        finally:
            os.umask(old_umask)


class TestNeverRaises:
    def test_record_never_raises_when_now_fn_itself_raises(self, tmp_path: Path) -> None:
        # ports/drops.py's contract is "never raises", full stop — record()
        # is invoked from try_append's own except-block (log.py), and a
        # raising recorder there would turn a handled drop into an unhandled
        # exception. An injected now_fn is exactly as fallible as any other
        # dependency this method touches, so it must be covered by the same
        # guarantee as a failing disk write.
        def broken_now() -> str:
            raise RuntimeError("clock is broken")

        recorder = FileDropRecorder(tmp_path / "trail.jsonl", now_fn=broken_now)
        recorder.record(reason="ValueError")  # must not raise
        assert recorder.count() == 0  # the record could not be written at all

    def test_record_never_raises_when_the_directory_is_unwritable(self, tmp_path: Path) -> None:
        import os
        import sys

        if sys.platform == "win32":
            pytest.skip("POSIX permission bits")
        if os.geteuid() == 0:
            pytest.skip("root bypasses permission checks")
        trail_dir = tmp_path / "readonly"
        trail_dir.mkdir(mode=0o500)
        recorder = FileDropRecorder(trail_dir / "trail.jsonl")
        try:
            recorder.record(reason="ValueError")  # must not raise
        finally:
            trail_dir.chmod(0o700)
