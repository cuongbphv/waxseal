"""Schema fingerprint: the automatic version identity (SPEC.md section 4).

``hash_version`` is NEVER a manual string. It is the SHA-256 of a canonical
descriptor of (algorithm, encoding, field names). Widening or reordering the
field set — or changing the encoding — changes the fingerprint automatically.
The migration-060 / beads-v1.2.2 failure class (a silent schema change hiding
behind a stable version id) is unrepresentable.

There is one encoding and therefore one descriptor form here. That is a
property of today, not a promise: the point of putting the encoding INSIDE the
descriptor is that a future one gets a different fingerprint for free, with no
migration and no in-place edit of what a released fingerprint means.

FROZEN PATH (CLAUDE.md): the canonical descriptor form here may never change
for a released fingerprint. New schemas append new descriptors.
"""

from __future__ import annotations

import hashlib
import struct
from typing import Final

from waxseal.domain.hashing import ENCODING

DESCRIPTOR_PREFIX: Final = b"waxseal-descriptor-v1\n"
ALGORITHM: Final = "sha256"

HEADER_FIELDS: Final[tuple[str, ...]] = (
    "seq",
    "ts",
    "hash_version",
    "payload_type",
    "payload_hash",
    "prev_hash",
)


def _lp(value: str) -> bytes:
    """Descriptor-frame length prefix.

    Deliberately its own two lines rather than a call into
    ``domain.hashing.lp``: the descriptor frame and the header frame are
    different frames, and coupling them would mean a change to how entries are
    encoded silently restructured how identities are computed.
    """
    enc = value.encode("utf-8")
    return struct.pack(">Q", len(enc)) + enc


def fingerprint_for(fields: tuple[str, ...]) -> str:
    """Fingerprint of a header schema under this build's algorithm and encoding."""
    components = (ALGORITHM, ENCODING, *fields)
    frame = DESCRIPTOR_PREFIX + struct.pack(">Q", len(components))
    for component in components:
        frame += _lp(component)
    return hashlib.sha256(frame).hexdigest()


def fingerprint() -> str:
    """The fingerprint of the header schema this build writes."""
    return fingerprint_for(HEADER_FIELDS)
