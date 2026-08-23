"""File/document version source: make document history tamper-evident.

Each call snapshots a file's content hash into the audit chain. The chain
proves the recorded history; `current_matches_last` compares the live file
against the last recorded hash (drift after the last snapshot is a separate
fact from chain integrity, so it is reported separately).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Final

from waxseal.domain.header import Entry
from waxseal.log import AuditLog

FILE_VERSION_PAYLOAD_TYPE: Final = "application/vnd.waxseal.file-version+json"


def record_file(log: AuditLog, path: Path | str, *, doc_id: str) -> Entry:
    p = Path(path)
    content = p.read_bytes()
    return log.append(
        payload={
            "doc_id": doc_id,
            "filename": p.name,
            "sha256": hashlib.sha256(content).hexdigest(),
            "size": len(content),
        },
        payload_type=FILE_VERSION_PAYLOAD_TYPE,
    )


def current_matches_last(log: AuditLog, path: Path | str, *, doc_id: str) -> bool | None:
    """True/False = measured against the last recorded version.
    None = this doc_id was never recorded — distinct from a mismatch
    (unmeasured is not a verdict, CLAUDE.md rule 5)."""
    last_hash: str | None = None
    for entry in log.entries():
        if entry.header.payload_type != FILE_VERSION_PAYLOAD_TYPE or entry.payload is None:
            continue
        payload = json.loads(entry.payload)
        if payload.get("doc_id") == doc_id:
            last_hash = payload.get("sha256")
    if last_hash is None:
        return None
    return hashlib.sha256(Path(path).read_bytes()).hexdigest() == last_hash
