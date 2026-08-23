"""Shared entry-envelope serialization (SPEC.md section 7).

jsonl.py and s3.py both store one JSON object per entry with the identical
shape ({header, entry_hash, payload_b64}) — this was independently
copy-pasted in both, so a schema fix applied to one and not the other would
silently desync the two backends' stored bytes. This module is the single
source of truth for that shape; sqlite.py and postgres.py reuse
``entry_from_fields`` to reconstruct an ``Entry`` from their row columns.

The header half of that shape is owned one layer down, by
``domain.header.header_to_obj``/``header_from_obj``, because the proof bundle
in ``domain/export.py`` carries the same header on a different wire and the
copy-paste hazard above applies across formats too.
"""

from __future__ import annotations

import base64
from typing import Any

from waxseal.domain.header import Entry, EntryHeader, header_from_obj, header_to_obj


def to_obj(entry: Entry, *, backend: str) -> dict[str, Any]:
    """Serialize an Entry to the JSON-envelope dict SPEC.md section 7 defines.

    ``backend`` names the caller in the error message when ``entry.payload``
    is None: object-per-entry backends store payload bytes, so a header-only
    Entry (``payload=None`` means "not available to this reader") must never
    reach here.
    """
    if entry.payload is None:
        raise ValueError(f"{backend} backend stores payload bytes; payload must not be None")
    return {
        "header": header_to_obj(entry.header),
        "entry_hash": entry.entry_hash,
        "payload_b64": base64.b64encode(entry.payload).decode("ascii"),
    }


def from_obj(obj: dict[str, Any]) -> Entry:
    """Reconstruct an Entry from the JSON-envelope dict ``to_obj`` produces."""
    return Entry(
        header=header_from_obj(obj["header"]),
        entry_hash=str(obj["entry_hash"]),
        payload=base64.b64decode(str(obj["payload_b64"])),
    )


def entry_from_fields(
    *,
    seq: int,
    ts: str,
    hash_version: str,
    payload_type: str,
    payload_hash: str,
    prev_hash: str,
    entry_hash: str,
    payload: bytes,
) -> Entry:
    """Reconstruct an Entry from flat row fields (SQL backends' column order)."""
    return Entry(
        header=EntryHeader(
            seq=seq,
            ts=ts,
            hash_version=hash_version,
            payload_type=payload_type,
            payload_hash=payload_hash,
            prev_hash=prev_hash,
        ),
        entry_hash=entry_hash,
        payload=payload,
    )
