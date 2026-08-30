"""The canonical encoding (lp64) and entry hashing (SPEC.md sections 2-3).

There is exactly one encoding. Not a default among several, not a current one
beside a legacy one. There is one. A row is hashed under lp64 and its `hash_version`
says so; a row whose fingerprint this build does not implement is reported
unverifiable by name and is never recomputed under an encoding it was not
signed with (`VersionRegistry.encoder_for`).

Pure functions, no I/O. The frame layout is frozen by SPEC.md and the golden
vectors, so a change here that alters any produced hash is a spec break, not a
refactor.
"""

from __future__ import annotations

import hashlib
import struct
from collections.abc import Callable
from typing import Final

from waxseal.domain.header import EntryHeader

FRAME_PREFIX: Final = b"waxseal-lp64\n"
ENCODING: Final = "lp64"


class _Null:
    """Marker for an absent field value.

    "Absent" is a claim about the data, not about how the data is spelled.
    lp64 renders it with a leading type tag, so absent and every possible
    string differ in their first encoded byte. See `lp`.
    """

    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return "NULL"


NULL: Final = _Null()


class LpEncodingError(ValueError):
    """A Python `str` `lp()` cannot encode: valid str, no UTF-8 form.

    Python `str` permits lone (unpaired) UTF-16 surrogates (`"\\ud800"`);
    UTF-8 has no representation for them. `lp()` raises this, chained from the
    stdlib `UnicodeEncodeError`, instead of letting that bare, unlabelled
    error leak past the domain boundary (gap G4; CLAUDE.md rule 6/9: a
    failure must be labelled, never left to leak the wrong error type).
    """


def lp(value: str | _Null) -> bytes:
    """Length-prefix one field: 8-byte big-endian length + tagged bytes.

    The type tag sits INSIDE the length-prefixed region (`0x00` for absent,
    `0x01` before a string's UTF-8 bytes), so an absent field and any string
    whatsoever differ in their first encoded byte. Injectivity is
    unconditional: no side condition, no invariant to maintain, no input to
    reject.

    An earlier design (`lp64v1`, never carried past 0.1.3) encoded absent as a
    six-byte sentinel that was itself valid UTF-8, so exactly one string
    collided with it. That is finding F1, and the tag above is what makes the
    collision unconstructible rather than merely unlikely.

    Raises `LpEncodingError` for a string with no UTF-8 representation (a
    lone UTF-16 surrogate) rather than letting `str.encode` raise its bare,
    unlabelled `UnicodeEncodeError`.
    """
    if isinstance(value, _Null):
        enc = b"\x00"
    else:
        try:
            enc = b"\x01" + value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise LpEncodingError(
                f"lp() cannot encode {value!r}: not representable in UTF-8"
            ) from exc
    return struct.pack(">Q", len(enc)) + enc


def header_frame(header: EntryHeader) -> bytes:
    """Canonical bytes for a header: PAE-style prefix + field count + fields.

    The prefix domain-separates this frame from anything else that might be
    hashed, so a frame can never be mistaken for another structure's bytes
    regardless of field content.
    """
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


def compute_entry_hash(
    header: EntryHeader, *, frame: Callable[[EntryHeader], bytes] = header_frame
) -> str:
    """Hash `header`, by default under the encoding this build implements.

    `frame` stays a parameter even with a single encoding: a verifier resolves
    it through `VersionRegistry.encoder_for(header.hash_version)` so that a row
    is always recomputed under the encoding it was actually signed with, and a
    fingerprint this build cannot reproduce resolves to None rather than being
    silently recomputed under the wrong one.
    """
    return hashlib.sha256(frame(header)).hexdigest()


def compute_payload_hash(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()
