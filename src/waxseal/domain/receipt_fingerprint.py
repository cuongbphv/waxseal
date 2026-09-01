"""Receipt-frame schema fingerprint (SPEC.md section 19, waxseal-fg4.9).

`RECEIPT_FRAME_PREFIX = b"waxseal-receipt-v1\\n"` (server/waxseal_server/domain/
receipts.py, SPEC.md section 19) names the receipt_head hash's FRAME SHAPE —
the same role `DESCRIPTOR_PREFIX` plays in `domain/fingerprint.py`. It stays a
literal on purpose (owner decision, waxseal-fg4.9). What must not stay a
hand-written literal is the IDENTITY a verifier checks a receipt record's
frame against: that is this module's job, mirroring `domain/fingerprint.py`
for a second frame rather than editing the first one.

This is a DELIBERATELY SEPARATE mechanism from `domain/fingerprint.py`, not a
generalization of it: `domain/fingerprint.py` is a frozen path (CLAUDE.md),
and its own docstring says new schemas append new descriptors rather than
reusing its canonical form. Coupling the two frames here would mean a change
to how receipt records are described could silently restructure how header
identities are computed — the exact risk `domain/fingerprint.py`'s `_lp`
already keeps separate from `domain.hashing.lp`. Own prefix, own `_lp`, own
fingerprint function; only `ALGORITHM`'s name and `domain.hashing.ENCODING`
are shared, because they are facts about this build, not about either frame's
canonical form.

The three fields below are exactly SPEC.md section 19's receipt_head inputs,
in the order the frame hashes them:

    receipt_head = SHA-256(RECEIPT_FRAME_PREFIX || u64be(3)
        || lp(str(receipt_seq)) || lp(prev_receipt_head) || lp(entry_hash))

Widening or reordering that input set changes this fingerprint automatically,
the same migration-060 / beads-v1.2.2 protection `hash_version` already gives
the header frame.
"""

from __future__ import annotations

import hashlib
import struct
from typing import Final

from waxseal.domain.hashing import ENCODING

RECEIPT_DESCRIPTOR_PREFIX: Final = b"waxseal-receipt-descriptor-v1\n"
ALGORITHM: Final = "sha256"

RECEIPT_FRAME_FIELDS: Final[tuple[str, ...]] = (
    "receipt_seq",
    "prev_receipt_head",
    "entry_hash",
)


def _lp(value: str) -> bytes:
    """Receipt-descriptor-frame length prefix.

    Its own two lines rather than a call into `domain.hashing.lp` or
    `domain.fingerprint`'s private helper, for the same reason
    `domain/fingerprint.py` gives for not reusing `domain.hashing.lp`: three
    frames (header bytes, header descriptor, receipt descriptor) that must
    never be able to drift into each other by sharing a helper.
    """
    enc = value.encode("utf-8")
    return struct.pack(">Q", len(enc)) + enc


def receipt_fingerprint_for(fields: tuple[str, ...]) -> str:
    """Fingerprint of a receipt-frame field set under this build's algorithm
    and encoding."""
    components = (ALGORITHM, ENCODING, *fields)
    frame = RECEIPT_DESCRIPTOR_PREFIX + struct.pack(">Q", len(components))
    for component in components:
        frame += _lp(component)
    return hashlib.sha256(frame).hexdigest()


def receipt_fingerprint() -> str:
    """The fingerprint of the receipt frame this build reads and writes."""
    return receipt_fingerprint_for(RECEIPT_FRAME_FIELDS)
