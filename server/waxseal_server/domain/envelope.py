"""Parsing the entry envelope SPEC.md section 7 defines.

Pure: this decides whether a body is well formed and rebuilds the `Entry` it
describes. It consults nothing about the chain, so every rejection here is a 400
and never a 409.

The server never re-derives `entry_hash` (REMOTE.md section 3). An envelope
whose `entry_hash` does not match its own header is accepted and stored exactly
as sent — repairing that field would launder a broken chain into one that
verifies, destroying the only signal the client has.
"""

from __future__ import annotations

import base64
import binascii
from typing import Any, Final

from waxseal import Entry, EntryHeader
from waxseal_server.domain.errors import MalformedEnvelope
from waxseal_server.domain.identifiers import require_hex64

HEADER_FIELDS: Final = (
    "seq",
    "ts",
    "hash_version",
    "payload_type",
    "payload_hash",
    "prev_hash",
)


def parse_envelope(envelope: Any) -> Entry:
    if not isinstance(envelope, dict):
        raise MalformedEnvelope(f"envelope must be a JSON object, got {type(envelope).__name__}")
    header = envelope.get("header")
    if not isinstance(header, dict):
        raise MalformedEnvelope("envelope.header must be a JSON object")
    missing = [name for name in HEADER_FIELDS if name not in header]
    if missing:
        raise MalformedEnvelope(f"envelope.header is missing {', '.join(missing)}")

    seq = header["seq"]
    # bool is an int in Python; a JSON `true` for seq is malformed, not seq 1.
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
        raise MalformedEnvelope(f"header.seq must be a non-negative integer, got {seq!r}")
    for name in ("ts", "payload_type"):
        if not isinstance(header[name], str):
            raise MalformedEnvelope(f"header.{name} must be a string, got {header[name]!r}")
    for name in ("hash_version", "payload_hash", "prev_hash"):
        require_hex64(header[name], f"header.{name}")

    if "entry_hash" not in envelope:
        raise MalformedEnvelope("envelope is missing entry_hash")
    entry_hash = require_hex64(envelope["entry_hash"], "entry_hash")

    payload_b64 = envelope.get("payload_b64")
    if not isinstance(payload_b64, str):
        raise MalformedEnvelope("envelope.payload_b64 must be a base64 string")
    try:
        # validate=True: without it, base64 silently discards characters outside
        # the alphabet, so a corrupted body would decode to plausible bytes.
        payload = base64.b64decode(payload_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise MalformedEnvelope(f"envelope.payload_b64 is not valid base64: {exc}") from exc

    return Entry(
        header=EntryHeader(
            seq=seq,
            ts=header["ts"],
            hash_version=header["hash_version"],
            payload_type=header["payload_type"],
            payload_hash=header["payload_hash"],
            prev_hash=header["prev_hash"],
        ),
        entry_hash=entry_hash,
        payload=payload,
    )
