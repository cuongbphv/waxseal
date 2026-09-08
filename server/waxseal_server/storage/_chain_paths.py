"""Segment discovery for a hosted chain directory.

`ChainStore` stays the public facade; this module is the path arithmetic that
used to live beside it. A hosted chain ROTATES, so a "trail path" is a group
of files, not a fixed name — see `ChainStore` for why the write path still
owns the lock order.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

from waxseal.domain.segments import SEGMENT_SUFFIX, segment_identity
from waxseal.sources.rotation import discover_segments

TRAIL_NAME: Final = "trail.jsonl"
RECEIPT_LOG_NAME: Final = "receipts.jsonl"

#: The segment stem every chain's trail rotates under. Segment zero of a chain
#: is the unnumbered `trail.jsonl` itself: rotation never renames, so the file
#: an existing deployment already has stays exactly where it is and becomes the
#: segment "before 0" (`sources/rotation.py`).
_TRAIL_STEM: Final = TRAIL_NAME.removesuffix(SEGMENT_SUFFIX)


def segments_in(directory: Path) -> list[Path]:
    """This trail's segments in `directory`, oldest first.

    `discover_segments` reports nothing for a stem with no NUMBERED
    segment, which is every chain that has not rotated yet — so the
    unrotated single file is the fallback, never a special case elsewhere.
    The filter keeps the receipt log and any other stem out.
    """
    found = [
        path
        for path in discover_segments(directory)
        if segment_identity(path.name).partition(".")[0] == _TRAIL_STEM
    ]
    if found:
        return found
    base = directory / TRAIL_NAME
    return [base] if base.exists() else []
