"""Forward-secure sealing: key-evolving HMAC over entry hashes.

Construction (Bellare–Yee 1997/2003; Schneier–Kelsey 1999): the epoch key
evolves one-way per entry, A_{j+1} = SHA-256(A_j), and the previous key is
discarded. A seal is HMAC-SHA256(A_j, framed entry_hash). An attacker who
compromises the machine at epoch t holds only A_t and cannot forge seals for
epochs < t — so a rewritten chain suffix (which a keyless hash chain cannot
detect) fails seal verification at the rewritten entry.

Verification holds A_0 and walks the epochs forward. Unknown attestation
schemes are unverifiable-by-name, never tampering (RFC 6962 principle),
and still advance the epoch clock so later seals verify.

Honest limits (see DESIGN.md §6): Python cannot guarantee memory zeroization
of old keys, and entries written AFTER compromise carry no guarantee under
any scheme. Forward security here is about pre-compromise history.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Final

FS_HMAC_SCHEME: Final = "fs-hmac-sha256-v1"
SEAL_FRAME_PREFIX: Final = b"waxseal-seal-v1\n"


@dataclass(frozen=True, slots=True)
class Attestation:
    seq: int
    entry_hash: str
    scheme: str
    value: str  # hex MAC for fs-hmac; hex signature for signer schemes
    key_id: str | None = None


@dataclass(frozen=True, slots=True)
class AttestResult:
    ok: bool
    checked: int
    broken_seq: int | None
    reason: str | None
    unverifiable: tuple[int, ...]


def generate_key() -> bytes:
    return secrets.token_bytes(32)


def evolve_key(key: bytes) -> bytes:
    return hashlib.sha256(key).digest()


def seal_entry(epoch_key: bytes, entry_hash: str) -> str:
    return hmac.new(
        epoch_key, SEAL_FRAME_PREFIX + entry_hash.encode("ascii"), hashlib.sha256
    ).hexdigest()


def verify_seals(attestations: Iterable[Attestation], initial_key: bytes) -> AttestResult:
    checked = 0
    unverifiable: list[int] = []
    key = initial_key
    for position, att in enumerate(attestations):
        if att.seq != position:
            # journald CVE-2023-31439 lesson: seq↔epoch binding must hold in
            # BOTH directions — a seal claiming another position is a break.
            return AttestResult(
                ok=False,
                checked=checked,
                broken_seq=att.seq,
                reason="seal_sequence_mismatch",
                unverifiable=tuple(unverifiable),
            )
        if att.scheme == FS_HMAC_SCHEME:
            try:
                expected = seal_entry(key, att.entry_hash)
            except UnicodeEncodeError:
                # Attacker-writable sidecar: a non-ASCII "hash" must be a
                # verdict, not a crash that denies the audit.
                return AttestResult(
                    ok=False,
                    checked=checked,
                    broken_seq=att.seq,
                    reason="malformed_attestation",
                    unverifiable=tuple(unverifiable),
                )
            if not hmac.compare_digest(expected, att.value):
                return AttestResult(
                    ok=False,
                    checked=checked,
                    broken_seq=att.seq,
                    reason="seal_mismatch",
                    unverifiable=tuple(unverifiable),
                )
            checked += 1
        else:
            unverifiable.append(att.seq)
        # The epoch clock is positional: it advances through opaque rows too,
        # otherwise one foreign attestation would desync every later seal.
        key = evolve_key(key)
    return AttestResult(
        ok=True,
        checked=checked,
        broken_seq=None,
        reason=None,
        unverifiable=tuple(unverifiable),
    )
