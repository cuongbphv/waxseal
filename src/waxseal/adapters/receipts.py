"""The `.receipts` sidecar file (SPEC.md section 19), the I/O half.

Same shape and the same discipline as adapters/anchors.py and
adapters/drops.py — one JSON object per line, O_APPEND under the file lock,
mode 0600, named through the same `with_name(name + suffix)` convention — so
an operator who knows one sidecar knows this one. Classifying what a line
MEANS lives in domain/receipts.py; this module only moves bytes, because two
parsers for one format are two chances to disagree about it.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from waxseal.adapters.filelock import file_lock
from waxseal.domain.receipts import (
    ReceiptSidecar,
    build_receipt_record,
    parse_receipt_line,
)
from waxseal.domain.registry import ReceiptFrameRegistry


def receipts_path(trail_path: Path | str) -> Path:
    trail = Path(trail_path).expanduser()
    return trail.with_name(trail.name + ".receipts")


def read_receipts(trail_path: Path | str) -> ReceiptSidecar:
    """Read the sidecar for ``trail_path``, classifying every line.

    Unlike ``read_anchor_records``, this never raises on bad bytes: SPEC.md
    section 19 assigns a verdict to a malformed record (a break) and to an
    unreadable version (unverifiable), so refusing to return would deny the
    caller the very distinction the table exists to make. ``OSError`` still
    propagates: a sidecar this process cannot open at all is an environment
    fact, not a record-level finding.
    """
    path = receipts_path(trail_path)
    if not path.exists():
        return ReceiptSidecar(present=False)
    lines = []
    # Built once outside the loop, mirroring how a VersionRegistry is built
    # once per verify_chain call rather than once per row: a receipt-frame
    # fingerprint check is a lookup against fixed, in-process state, not
    # something that needs re-deriving per line.
    registry = ReceiptFrameRegistry()
    with open(path, encoding="utf-8", errors="replace", newline="") as f:
        # Physical line numbers, blanks included in the count: an operator sent
        # to line N must find the record there.
        for line_no, line in enumerate(f, start=1):
            if line.strip():
                lines.append(parse_receipt_line(line, line_no=line_no, registry=registry))
    return ReceiptSidecar(present=True, lines=tuple(lines))


def append_receipt(
    trail_path: Path | str,
    *,
    seq: int,
    entry_hash: str,
    receipt_seq: int,
    receipt_head: str,
    source: str,
    ts: str,
) -> None:
    """Append one acknowledgment. Append-only, like the trail it corroborates.

    Under the same lock anchors.py takes, for the reason measured there: bare
    O_APPEND interleaves a multi-chunk write, and a torn line makes the reader
    report a break with no attacker present — an accident masquerading as
    tampering.

    `build_receipt_record` stamps this build's current receipt-frame
    fingerprint (waxseal-fg4.9) on every record written here; there is no
    parameter to override it because every writer in this codebase writes
    today's frame, the same reasoning `hash_version` already applies.
    """
    record = build_receipt_record(
        seq=seq,
        entry_hash=entry_hash,
        receipt_seq=receipt_seq,
        receipt_head=receipt_head,
        source=source,
        ts=ts,
    )
    line = json.dumps(record, sort_keys=True, separators=(",", ":"))
    path = receipts_path(trail_path)
    with file_lock(path):
        # 0600 like every other sidecar: as sensitive as the trail it describes.
        fd = os.open(path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8", newline="") as f:
            f.write(line + "\n")
            f.flush()
