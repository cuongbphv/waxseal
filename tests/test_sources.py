"""Tests for metadata sources: file/document version chains.

The pattern: each call snapshots a file's content hash into the audit chain,
so document history becomes tamper-evident alongside agent actions.
"""

import hashlib
from pathlib import Path

from waxseal import AuditLog
from waxseal.sources.files import FILE_VERSION_PAYLOAD_TYPE, record_file


def open_log(tmp_path: Path) -> AuditLog:
    return AuditLog.open(tmp_path / "trail.jsonl", now_fn=lambda: "2026-08-21T06:00:00+00:00")


class TestRecordFile:
    def test_payload_carries_content_hash_and_size(self, tmp_path: Path) -> None:
        doc = tmp_path / "spec.md"
        doc.write_bytes(b"# spec v1\n")
        log = open_log(tmp_path)
        entry = record_file(log, doc, doc_id="spec")

        import json

        payload = json.loads(entry.payload)
        assert payload["doc_id"] == "spec"
        assert payload["filename"] == "spec.md"
        assert payload["sha256"] == hashlib.sha256(b"# spec v1\n").hexdigest()
        assert payload["size"] == 10
        assert entry.header.payload_type == FILE_VERSION_PAYLOAD_TYPE

    def test_successive_versions_chain_and_verify(self, tmp_path: Path) -> None:
        doc = tmp_path / "spec.md"
        log = open_log(tmp_path)
        hashes = []
        for content in (b"v1", b"v2", b"v3"):
            doc.write_bytes(content)
            entry = record_file(log, doc, doc_id="spec")
            import json

            hashes.append(json.loads(entry.payload)["sha256"])
        assert len(set(hashes)) == 3
        assert log.verify().checked == 3

    def test_current_file_matches_last_recorded_hash(self, tmp_path: Path) -> None:
        # The audit_trace pattern: link_ok is the chain, content_ok compares
        # the live file against the last recorded hash.
        from waxseal.sources.files import current_matches_last

        doc = tmp_path / "spec.md"
        doc.write_bytes(b"v1")
        log = open_log(tmp_path)
        record_file(log, doc, doc_id="spec")
        assert current_matches_last(log, doc, doc_id="spec") is True

        doc.write_bytes(b"drifted after the fact")
        assert current_matches_last(log, doc, doc_id="spec") is False

    def test_no_recorded_version_returns_none_not_false(self, tmp_path: Path) -> None:
        # None = "never measured", distinct from False = "measured, differs".
        from waxseal.sources.files import current_matches_last

        doc = tmp_path / "spec.md"
        doc.write_bytes(b"v1")
        log = open_log(tmp_path)
        assert current_matches_last(log, doc, doc_id="spec") is None
