"""lp64v1 canonical encoding and entry hashing (SPEC.md sections 2-3).

Pure functions, no I/O. The frame layout is frozen by SPEC.md and the golden
vectors — a change here that alters any produced hash is a spec break, not a
refactor.
"""

from __future__ import annotations

import hashlib
import struct
from typing import Final

from waxseal.domain.header import EntryHeader

FRAME_PREFIX: Final = b"waxseal-v1\n"
# Sentinel distinct from the empty string: lp("") is a zero length prefix,
# lp(NULL) is length 6 + these bytes. Absent and empty must never hash alike.
NULL_SENTINEL: Final = b"\x00NULL\x00"


class _Null:
    """Marker for an absent field value (not representable as any string)."""

    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return "NULL"


NULL: Final = _Null()


def lp(value: str | _Null) -> bytes:
    """Length-prefix one field: 8-byte big-endian length + UTF-8 bytes."""
    enc = NULL_SENTINEL if isinstance(value, _Null) else value.encode("utf-8")
    return struct.pack(">Q", len(enc)) + enc


def header_frame(header: EntryHeader) -> bytes:
    """Canonical bytes for the v1 header: PAE-style prefix + field count + fields."""
    return (
        FRAME_PREFIX
        + struct.pack(">Q", 6)
        + lp(str(header.seq))
        + lp(header.ts)
        + lp(header.hash_version)
        + lp(header.payload_type)
        + lp(header.payload_hash)
        + lp(header.prev_hash)
    )


def compute_entry_hash(header: EntryHeader) -> str:
    return hashlib.sha256(header_frame(header)).hexdigest()


def compute_payload_hash(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()
