"""OpenTimestamps: the digest a calendar commits to, and receipt framing.

An OpenTimestamps calendar eventually folds the digest it was given into a
Bitcoin block, which puts the time claim under an administrative authority
nobody involved controls, the strongest separation available to this library.

Deliberately absent: a proof parser
-----------------------------------
The bytes a calendar returns are a serialized attestation-op tree whose format
the OpenTimestamps project owns. A partial reimplementation here would
manufacture "malformed" verdicts on proofs that are perfectly valid, which is
the failure class this library exists to prevent, so the proof stays opaque
and LABELLED as opaque (CLAUDE.md rule 6), never silently treated as checked.

A receipt this library stores is also PENDING: the calendar has accepted the
digest but the Bitcoin attestation does not exist until the block confirms.
Completing and verifying it is `ots upgrade` / `ots verify` from the
opentimestamps-client, and every output line that mentions one must say so.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from typing import Final

# The calendar's own media type, sent on the digest submission. Client
# implementations do not set a request Content-Type, so neither does this one.
OTS_ACCEPT: Final = "application/vnd.opentimestamps.v1"

# Receipt framing, matching domain/rfc3161.py: the prefix is how a reader
# dispatches on receipt type instead of guessing from the bytes.
RECEIPT_PREFIX: Final = "ots:"

# What an `ots:` receipt means when a verifier meets one. Not "checked" and not
# "broken": a third format, and the exit-code mapping has to keep it distinct.
PENDING_NOTE: Final = (
    "pending OpenTimestamps proof — opaque to this library by design, NOT checked here; "
    "complete and verify it with `ots upgrade` / `ots verify`"
)


def ots_digest(message: bytes) -> bytes:
    """The 32 bytes submitted to a calendar's ``/digest`` endpoint."""
    return hashlib.sha256(message).digest()


def encode_receipt(proof: bytes) -> str:
    """Wrap a calendar's pending proof for storage in an anchor record."""
    return RECEIPT_PREFIX + base64.b64encode(proof).decode("ascii")


def decode_receipt(receipt: str) -> bytes | None:
    """The proof bytes inside an ``ots:`` receipt, or None when the string is
    not one. Callers use this to EXTRACT a proof for external tooling, never to
    judge it; see the module docstring."""
    if not receipt.startswith(RECEIPT_PREFIX):
        return None
    try:
        return base64.b64decode(receipt[len(RECEIPT_PREFIX) :], validate=True)
    except (binascii.Error, ValueError):
        return None
