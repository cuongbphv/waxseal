"""Entry envelope model (SPEC.md section 1).

The chain hashes only ``EntryHeader``; payload is arbitrary bytes referenced by
``payload_hash``. Both classes are frozen, so an entry is immutable by construction.

``header_to_obj``/``header_from_obj`` are the single owner of the header's
JSON shape. Every wire format that carries a header, the storage envelope in
``adapters/_envelope.py`` and the proof bundle in ``domain/export.py``, goes
through them, because the last time this mapping was copy-pasted the two
copies could silently disagree about stored bytes (see _envelope's own note).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

GENESIS_PREV_HASH = "0" * 64

HEADER_FIELDS = ("seq", "ts", "hash_version", "payload_type", "payload_hash", "prev_hash")


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
    # which skips the payload check. That is distinct from b"" (an empty payload).
    payload: bytes | None


def header_to_obj(header: EntryHeader) -> dict[str, Any]:
    """The header's canonical JSON shape (SPEC.md section 7)."""
    return {
        "seq": header.seq,
        "ts": header.ts,
        "hash_version": header.hash_version,
        "payload_type": header.payload_type,
        "payload_hash": header.payload_hash,
        "prev_hash": header.prev_hash,
    }


def header_from_obj(obj: Any) -> EntryHeader:
    """Rebuild a header from ``header_to_obj``'s shape.

    Every field is coerced rather than trusted: these bytes come off disk or
    off the wire, where the threat model says an attacker may have written
    them. Anything that cannot be coerced raises ValueError, a single
    catchable type, so a caller can report "malformed" instead of dying.
    """
    if not isinstance(obj, dict):
        raise ValueError("header must be a JSON object")
    missing = [field for field in HEADER_FIELDS if field not in obj]
    if missing:
        raise ValueError(f"header is missing {missing}")
    try:
        seq = int(obj["seq"])
    except (TypeError, ValueError) as e:
        raise ValueError("header seq must be an integer") from e
    return EntryHeader(
        seq=seq,
        ts=str(obj["ts"]),
        hash_version=str(obj["hash_version"]),
        payload_type=str(obj["payload_type"]),
        payload_hash=str(obj["payload_hash"]),
        prev_hash=str(obj["prev_hash"]),
    )
