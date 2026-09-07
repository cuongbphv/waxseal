from __future__ import annotations

import json
from collections import Counter, deque
from pathlib import Path

from waxseal.cli._anchors import _print_drop_count
from waxseal.domain.header import Entry
from waxseal.log import AuditLog


def _tail(log: AuditLog, n: int) -> int:
    # A bounded deque, not list(log.entries())[-n:]: the slice discarded
    # everything but the last n rows AFTER holding the whole decoded trail in
    # memory at once, so a read-only command's peak allocation grew with the
    # trail it was only printing the end of. Output is byte-identical.
    window: deque[Entry] = deque(maxlen=n)
    for entry in log.entries():
        window.append(entry)
    for entry in window:
        h = entry.header
        print(f"seq={h.seq} ts={h.ts} type={h.payload_type} hash={entry.entry_hash[:12]}")
    return 0


def _head(log: AuditLog) -> int:
    # Anchor this output externally (OpenTimestamps, RFC 3161 TSA, a pushed
    # git commit): a rewritten suffix cannot rewrite an already-anchored head.

    last = None
    for last in log.entries():  # noqa: B007 - want the final element
        pass
    if last is None:
        return 1
    print(json.dumps({"seq": last.header.seq, "entry_hash": last.entry_hash}))
    return 0


def _checkpoint(log: AuditLog) -> int:
    # Same anchoring rationale as `head`, plus a batch root: a membership
    # proof against this root can later prove any one entry was present
    # without needing the whole trail in hand (RFC 6962 section 2.1).

    from waxseal.domain.checkpoint import checkpoint_for

    hashes = log.entry_hashes()
    if not hashes:
        return 1
    cp = checkpoint_for(hashes)
    print(json.dumps({"seq": cp.seq, "entry_hash": cp.entry_hash, "root": cp.root}))
    return 0


def _inspect(log: AuditLog, trail: Path | None) -> int:
    total = 0
    by_fingerprint: Counter[str] = Counter()
    by_type: Counter[str] = Counter()
    for entry in log.entries():
        total += 1
        by_fingerprint[entry.header.hash_version] += 1
        by_type[entry.header.payload_type] += 1
    print(f"entries: {total}")
    for fp, count in by_fingerprint.items():
        print(f"fingerprint {fp[:12]}…: {count}")
    for pt, count in by_type.items():
        print(f"payload_type {pt}: {count}")
    _print_drop_count(trail)
    return 0
