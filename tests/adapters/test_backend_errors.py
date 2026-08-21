"""Error-path tests: backends must refuse entries without payload bytes,
and a failed SQLite append must roll back cleanly."""

from pathlib import Path

import pytest

from tests.adapters.test_jsonl import build_entry
from waxseal import AuditLog
from waxseal.adapters.jsonl import JSONLBackend
from waxseal.adapters.sqlite import SQLiteBackend
from waxseal.domain.header import Entry

PT = "application/vnd.test.event+json"


def build_headerless(seq: int, prev: str) -> Entry:
    entry = build_entry(seq, prev)
    return Entry(header=entry.header, entry_hash=entry.entry_hash, payload=None)


class TestPayloadRequired:
    def test_jsonl_rejects_none_payload(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="payload"):
            JSONLBackend(tmp_path / "t.jsonl").append(build_headerless)

    def test_sqlite_rejects_none_payload_and_rolls_back(self, tmp_path: Path) -> None:
        backend = SQLiteBackend(tmp_path / "t.db")
        with pytest.raises(ValueError, match="payload"):
            backend.append(build_headerless)
        # Rollback left no partial row: the next append still gets seq 0.
        entry = backend.append(lambda seq, prev: build_entry(seq, prev))
        assert entry.header.seq == 0


class TestAppendTypeErrors:
    def test_append_rejects_non_dict_non_bytes_payload(self, tmp_path: Path) -> None:
        log = AuditLog.open(tmp_path / "t.jsonl")
        with pytest.raises(TypeError, match="dict or bytes"):
            log.append(payload=123, payload_type=PT)  # type: ignore[arg-type]
