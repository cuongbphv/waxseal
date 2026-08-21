"""Entry envelope model (SPEC.md section 1).

The chain hashes only ``EntryHeader``; payload is arbitrary bytes referenced by
``payload_hash``. Both classes are frozen — an entry is immutable by construction.
"""

from __future__ import annotations

from dataclasses import dataclass

GENESIS_PREV_HASH = "0" * 64


@dataclass(frozen=True, slots=True)
class EntryHeader:
    seq: int
    ts: str
    hash_version: str
    payload_type: str
    payload_hash: str
    prev_hash: str


@dataclass(frozen=True, slots=True)
class Entry:
    header: EntryHeader
    entry_hash: str
    # None = payload bytes not available to this reader (header-only source),
    # which skips the payload check — distinct from b"" (an empty payload).
    payload: bytes | None
