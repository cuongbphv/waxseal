from __future__ import annotations

import json
import sys
from pathlib import Path

from waxseal.domain.segments import SegmentRead
from waxseal.log import AuditLog


def _segments(directory: Path) -> int:
    """`waxseal segments <dir>` (B4): every segment in a per-project trail
    directory, its own chain verdict, and the rotation binding that links it
    to its predecessor (SPEC section 20).

    Read-only against every file it touches, appending nothing (CLAUDE.md's
    CLI contract). Exit codes come from `Verdict.to_exit_code()` via
    `Verdict.join`, never from comparing exit codes: 2 (unverifiable) is the
    larger code but the weaker finding, so an unknown fingerprint in one
    segment must never mask a real break in another.
    """
    from waxseal.domain.segments import (
        SEGMENT_MISSING,
        SEGMENT_OK,
        verify_segments,
    )
    from waxseal.sources.rotation import discover_segments

    paths = discover_segments(directory)
    if not paths:
        if not directory.is_dir():
            print(f"error: no such segment directory: {directory}", file=sys.stderr)
        else:
            # Never rendered as "checked, all intact": an unrotated single
            # trail was not checked here at all (rule 5).
            print(
                f"error: no sealed segments in {directory} — a trail that has "
                "not rotated yet is verified with `waxseal verify <trail>`",
                file=sys.stderr,
            )
        return 3

    result = verify_segments([_read_segment(p) for p in paths])
    for state in result.segments:
        detail = ""
        if state.reason is not None:
            detail = f" — {state.reason}"
            if state.broken_seq is not None:
                detail += f" at seq={state.broken_seq}"
        if state.state == SEGMENT_MISSING:
            # Named by a surviving binding and not present. Positive evidence
            # it existed, so it aggregates as a break (owner decision,
            # 31/08/2026) — but it is never printed as tampering.
            detail = " — segment_missing: named by a surviving rotation binding, not present"
        print(f"  {state.identity}: {state.state}{detail}")

    checked = [s for s in result.segments if s.state != SEGMENT_MISSING]
    print(
        f"{len(checked)} segment(s) in {directory}: {result.verdict.value} "
        f"(segments are linked by rotation bindings, never by prev_hash)"
    )
    if result.verdict.value != SEGMENT_OK:
        print(
            "which segment was altered, and which is a legitimate archival "
            "move, is an operator's decision (CLAUDE.md rule 4: verify "
            "reports, never repairs)"
        )
    return result.verdict.to_exit_code()


def _read_segment(path: Path) -> SegmentRead:
    """One segment read off disk for `verify_segments` to judge.

    A segment whose stored lines will not parse is reported with
    ``chain=None`` -- "nothing was compared" -- rather than raising: a torn
    first line is exactly what a crash mid-rotation leaves behind, and a
    read-only command must print a state for it, not a traceback.
    """
    from waxseal.domain.segments import segment_identity

    identity = segment_identity(path.name)
    log = AuditLog.open(path)
    try:
        result, entries = log._verify_and_entries()
    except (ValueError, KeyError, TypeError, OSError):
        return SegmentRead(identity=identity, chain=None)
    genesis_payload_type: str | None = None
    genesis_payload: object | None = None
    if entries:
        genesis_payload_type = entries[0].header.payload_type
        genesis_payload = _decode_payload(entries[0].payload)
    return SegmentRead(
        identity=identity,
        chain=result,
        entry_hashes=tuple(entry.entry_hash for entry in entries),
        genesis_payload_type=genesis_payload_type,
        genesis_payload=genesis_payload,
    )


def _decode_payload(payload: bytes | None) -> object | None:
    """The seq-0 payload as JSON, or None when it is absent or will not
    decode. None is the caller's "unreadable" input, which becomes
    `rotation_binding_unreadable` -- unverifiable, never tampered."""
    if payload is None:
        return None

    try:
        decoded: object = json.loads(payload)
    except ValueError:
        return None
    return decoded


def _is_hex(value: str) -> bool:
    # bytes.fromhex tolerates whitespace, which a root never contains, so a
    # "root" with spaces smuggled past the length check must not reach the
    # proof as if it were well-formed.
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return " " not in value
