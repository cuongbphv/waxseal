"""Tests for the JSONL backend (SPEC.md section 7)."""

import json
from pathlib import Path

from waxseal.adapters.jsonl import JSONLBackend
from waxseal.domain.fingerprint import fingerprint_v1
from waxseal.domain.hashing import compute_entry_hash, compute_payload_hash
from waxseal.domain.header import GENESIS_PREV_HASH, Entry, EntryHeader


def build_entry(seq: int, prev_hash: str, payload: bytes = b"{}") -> Entry:
    header = EntryHeader(
        seq=seq,
        ts="2026-08-21T06:00:00+00:00",
        hash_version=fingerprint_v1(),
        payload_type="application/vnd.test.event+json",
        payload_hash=compute_payload_hash(payload),
        prev_hash=prev_hash,
    )
    return Entry(header=header, entry_hash=compute_entry_hash(header), payload=payload)


class TestAppend:
    def test_first_append_gets_seq_0_and_genesis_prev(self, tmp_path: Path) -> None:
        backend = JSONLBackend(tmp_path / "trail.jsonl")
        seen: list[tuple[int, str]] = []

        def build(seq: int, prev_hash: str) -> Entry:
            seen.append((seq, prev_hash))
            return build_entry(seq, prev_hash)

        backend.append(build)
        assert seen == [(0, GENESIS_PREV_HASH)]

    def test_second_append_links_to_first(self, tmp_path: Path) -> None:
        backend = JSONLBackend(tmp_path / "trail.jsonl")
        first = backend.append(lambda seq, prev: build_entry(seq, prev))
        seen: list[tuple[int, str]] = []

        def build(seq: int, prev_hash: str) -> Entry:
            seen.append((seq, prev_hash))
            return build_entry(seq, prev_hash)

        backend.append(build)
        assert seen == [(1, first.entry_hash)]

    def test_line_layout_matches_spec(self, tmp_path: Path) -> None:
        path = tmp_path / "trail.jsonl"
        JSONLBackend(path).append(lambda seq, prev: build_entry(seq, prev, b'{"a":1}'))
        line = path.read_text(encoding="utf-8").splitlines()[0]
        obj = json.loads(line)
        assert set(obj) == {"header", "entry_hash", "payload_b64"}
        assert set(obj["header"]) == {
            "seq", "ts", "hash_version", "payload_type", "payload_hash", "prev_hash",
        }
        import base64
        assert base64.b64decode(obj["payload_b64"]) == b'{"a":1}'


class TestRoundTrip:
    def test_entries_round_trip_byte_exact(self, tmp_path: Path) -> None:
        backend = JSONLBackend(tmp_path / "trail.jsonl")
        written = [
            backend.append(lambda seq, prev: build_entry(seq, prev, b'{"vi\xe1\xbb\x87t":1}'))
            for _ in range(3)
        ]
        assert list(backend.entries()) == written

    def test_empty_file_yields_nothing(self, tmp_path: Path) -> None:
        path = tmp_path / "trail.jsonl"
        path.touch()
        assert list(JSONLBackend(path).entries()) == []

    def test_missing_file_yields_nothing(self, tmp_path: Path) -> None:
        assert list(JSONLBackend(tmp_path / "absent.jsonl").entries()) == []


class TestTrailPermissions:
    def test_trail_file_is_created_owner_only(self, tmp_path) -> None:
        # The trail holds prompts, tool output, and file contents at a
        # predictable path (~/.claude/waxseal/...): default-umask 0644 hands
        # every local user the whole audit trail. Only the sealkey was 0600.
        import os
        import sys

        import pytest

        if sys.platform == "win32":
            pytest.skip("POSIX permission bits")
        from waxseal import AuditLog

        old_umask = os.umask(0o022)
        try:
            trail = tmp_path / "trail.jsonl"
            AuditLog.open(trail).append(
                payload={"i": 0}, payload_type="application/vnd.test.event+json"
            )
            assert (trail.stat().st_mode & 0o777) == 0o600
        finally:
            os.umask(old_umask)
