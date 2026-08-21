"""Schema fingerprint: the automatic version identity (SPEC.md section 4).

``hash_version`` is never a manual string. It is the SHA-256 of a canonical
descriptor of (algorithm, encoding, field names). Widening or reordering the
field set changes the fingerprint automatically — the migration-060 /
beads-v1.2.2 failure class (silent schema change under a stable version id)
is unrepresentable.

FROZEN PATH (CLAUDE.md): the canonical descriptor form here may never change
for a released fingerprint. New schemas append new descriptors.
"""

from __future__ import annotations

import hashlib
import struct
from typing import Final

DESCRIPTOR_PREFIX: Final = b"waxseal-descriptor-v1\n"
ALGORITHM: Final = "sha256"
ENCODING: Final = "lp64v1"

HEADER_V1_FIELDS: Final[tuple[str, ...]] = (
    "seq",
    "ts",
    "hash_version",
    "payload_type",
    "payload_hash",
    "prev_hash",
)


def _lp(value: str) -> bytes:
    enc = value.encode("utf-8")
    return struct.pack(">Q", len(enc)) + enc


def fingerprint_for(fields: tuple[str, ...]) -> str:
    """Fingerprint of a header schema with the v1 algorithm and encoding."""
    components = (ALGORITHM, ENCODING, *fields)
    frame = DESCRIPTOR_PREFIX + struct.pack(">Q", len(components))
    for component in components:
        frame += _lp(component)
    return hashlib.sha256(frame).hexdigest()


def fingerprint_v1() -> str:
    return fingerprint_for(HEADER_V1_FIELDS)
