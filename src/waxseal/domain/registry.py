"""Append-only version registry (SPEC.md section 4, CLAUDE.md rule 2).

Maps schema fingerprint -> header field tuple. There is deliberately no
removal or mutation API: a released fingerprint's meaning can never change.
New schemas are appended under their own (automatically different) fingerprint.

`ReceiptFrameRegistry` at the bottom of this file is the same doctrine
applied to the receipt frame (SPEC.md section 19, waxseal-fg4.9) -- a
separate, append-only registry, not a second use of `VersionRegistry`, for
the reason `domain/receipt_fingerprint.py` gives.
"""

from __future__ import annotations

import hashlib
import struct
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final

from waxseal.domain.fingerprint import (
    ALGORITHM,
    DESCRIPTOR_PREFIX,
    HEADER_FIELDS,
    fingerprint,
    fingerprint_for,
)
from waxseal.domain.hashing import ENCODING, header_frame
from waxseal.domain.header import EntryHeader
from waxseal.domain.receipt_fingerprint import (
    RECEIPT_FRAME_FIELDS,
    receipt_fingerprint,
    receipt_fingerprint_for,
)
from waxseal.domain.verdict import Verdict

# Which frame function implements each named encoding a released fingerprint
# can carry -- the single place a stored identity is resolved to the code that
# can reproduce it. One entry today; a future encoding is one more entry here,
# never a branch added at a call site.
_ENCODERS: dict[str, Callable[[EntryHeader], bytes]] = {
    ENCODING: header_frame,
}


class VersionRegistry:
    def __init__(self) -> None:
        self._schemas: dict[str, tuple[str, ...]] = {fingerprint(): HEADER_FIELDS}
        # Which encoding a KNOWN, recomputable fingerprint uses. Kept beside
        # _schemas rather than derived from it because a field tuple does not
        # determine an encoding -- two fingerprints could share a field tuple
        # and differ only in how it is encoded.
        self._encoding: dict[str, str] = {fingerprint(): ENCODING}

    def knows(self, fingerprint_: str) -> bool:
        return fingerprint_ in self._schemas

    def fields(self, fingerprint_: str) -> tuple[str, ...]:
        return self._schemas[fingerprint_]

    def encoder_for(self, fingerprint_: str) -> Callable[[EntryHeader], bytes] | None:
        """The header-frame function this build would use to recompute a row
        stamped with `fingerprint_`, or None if this build cannot recompute it
        at all -- which must be treated as unverifiable, never broken.

        None for: an unknown fingerprint, OR a fingerprint registered via
        register() with a field tuple different from HEADER_FIELDS (this
        build's hasher only implements that shape). Recomputing such a row
        under the wrong frame would report it tampered for the crime of having
        an identity this build does not implement -- the migration-060 /
        beads-v1.2.2 failure class exactly.
        """
        if self._schemas.get(fingerprint_) != HEADER_FIELDS:
            return None
        return _ENCODERS[self._encoding[fingerprint_]]

    def recomputable(self, fingerprint_: str) -> bool:
        """True only when this build's hasher reproduces the schema for
        `fingerprint_` -- defined as encoder_for(...) is not None, rather than
        a separately-maintained condition, so the two can never disagree about
        which fingerprints are usable."""
        return self.encoder_for(fingerprint_) is not None

    def register(self, fields: tuple[str, ...]) -> str:
        """Append a schema; returns its fingerprint. Idempotent for identical
        field tuples, since the fingerprint construction makes a conflicting
        re-registration impossible (same fields ⇒ same fingerprint)."""
        fp = fingerprint_for(fields)
        self._schemas.setdefault(fp, fields)
        return fp


# --------------------------------------------------- on-chain cross-check
#
# An on-chain fingerprint registry moves the version identity out from under
# whoever controls the trail: the descriptor is published once, append-only,
# and the contract itself computes `fp = sha256(desc)`, so poisoning an entry
# requires a SHA-256 collision or control of the chain rather than write
# access to a file. What it does NOT do is give this build permission to
# recompute a row it has no encoder for. Agreement about a NAME is not the
# same as owning the code that reproduces the hash (RFC 6962 section 4.6),
# and the two are kept apart in `RegistryFinding` below.


def descriptor_frame(fields: tuple[str, ...]) -> bytes:
    """The canonical descriptor BYTES for a header schema.

    `domain/fingerprint.py` is a frozen path and exposes only the digest,
    never the bytes it digested. Publishing a descriptor to a contract needs
    the bytes, so they are re-derived here rather than by editing the frozen
    module. That is a second implementation of one canonical form, which is
    exactly the drift risk CLAUDE.md rule 2 exists about, so
    tests/domain/test_registry_crosscheck.py asserts
    `sha256(descriptor_frame(f)) == fingerprint_for(f)` for several field
    tuples: the two cannot disagree without turning that test red. The
    alternative, importing `fingerprint._lp`, reaches into a frozen module's
    private surface, which is worse.
    """
    components = (ALGORITHM, ENCODING, *fields)
    frame = DESCRIPTOR_PREFIX + struct.pack(">Q", len(components))
    for component in components:
        raw = component.encode("utf-8")
        frame += struct.pack(">Q", len(raw)) + raw
    return frame


def decode_descriptor(raw: bytes) -> tuple[str, ...] | None:
    """Render a descriptor read off the chain, or None if this build cannot.

    Best-effort and REPORTING ONLY: no verdict is ever derived from what this
    returns. The verdict comes from SHA-256 alone, which is the same thing
    the contract computes, so an operator reading "could not decode" still
    gets a decided agree/disagree. Returning None rather than raising because
    the bytes come from a public contract anyone can write to; a build that
    cannot read a descriptor must say so, not crash the verify that asked.
    """
    if not raw.startswith(DESCRIPTOR_PREFIX):
        return None
    pos = len(DESCRIPTOR_PREFIX)
    if len(raw) < pos + 8:
        return None
    (count,) = struct.unpack_from(">Q", raw, pos)
    pos += 8
    components: list[str] = []
    for _ in range(count):
        if len(raw) < pos + 8:
            return None
        (size,) = struct.unpack_from(">Q", raw, pos)
        pos += 8
        if len(raw) < pos + size:
            return None
        try:
            components.append(raw[pos : pos + size].decode("utf-8"))
        except UnicodeDecodeError:
            return None
        pos += size
    if pos != len(raw):
        # Trailing bytes mean this is not the frame it claimed to be, and a
        # partial read of an unknown structure is the shape of thing that
        # gets rendered to an operator as fact.
        return None
    return tuple(components)


REGISTRY_AGREES: Final = "agrees"
REGISTRY_DISAGREES: Final = "disagrees"
REGISTRY_UNREACHABLE: Final = "unreachable"

REGISTRY_DISAGREEMENT: Final = "registry_disagreement"
REGISTRY_ABSENT_OR_UNREACHABLE: Final = "registry_absent_or_unreachable"


@dataclass(frozen=True, slots=True)
class RegistryFinding:
    """One fingerprint's cross-check against an on-chain registry.

    `locally_known` and `locally_recomputable` are carried separately and
    both are carried even when the descriptors agree, because they answer
    different questions and a caller that collapses them writes the
    migration-060 bug again: knowing what a fingerprint is NAMED never
    licenses recomputing a row under this build's encoder.
    """

    fingerprint: str
    status: str
    reason: str | None = None
    locally_known: bool = False
    locally_recomputable: bool = False
    onchain_descriptor: tuple[str, ...] | None = None
    onchain_descriptor_hex: str | None = None

    def to_verdict(self) -> Verdict:
        """OK or UNVERIFIABLE. Never BROKEN, and not by anyone's care: the
        range of `_REGISTRY_STATUS` does not contain BROKEN at all.

        Two registries disagreeing about one fingerprint is two authorities
        in conflict. This process cannot adjudicate which is the real one —
        it has no standing to — and reporting "tampered" for a conflict it
        cannot settle is the single lie a tamper-evidence mechanism must
        never tell. Exit 2, always.
        """
        try:
            return _REGISTRY_STATUS[self.status]
        except KeyError:
            raise ValueError(f"not a registry status: {self.status!r}") from None


_REGISTRY_STATUS: Final[dict[str, Verdict]] = {
    REGISTRY_AGREES: Verdict.OK,
    REGISTRY_DISAGREES: Verdict.UNVERIFIABLE,
    REGISTRY_UNREACHABLE: Verdict.UNVERIFIABLE,
}


class RegistryCrossCheck:
    """Compares fingerprints this build holds against an on-chain registry."""

    def __init__(self, registry: VersionRegistry) -> None:
        self._registry = registry

    def check(self, fingerprint_: str, onchain_descriptor: bytes | None) -> RegistryFinding:
        """Cross-check one fingerprint against what the chain returned.

        `onchain_descriptor is None` covers both "the registry holds nothing
        for this fingerprint" and "the registry could not be read": neither
        measured anything about agreement, and the caller that owns the
        network puts the distinction in the reason it passes on. Agreement is
        decided by SHA-256, the same computation the contract performs, so
        the answer does not depend on this build being able to PARSE the
        descriptor it was given.
        """
        known = self._registry.knows(fingerprint_)
        recomputable = self._registry.recomputable(fingerprint_)
        if onchain_descriptor is None:
            return RegistryFinding(
                fingerprint=fingerprint_,
                status=REGISTRY_UNREACHABLE,
                reason=REGISTRY_ABSENT_OR_UNREACHABLE,
                locally_known=known,
                locally_recomputable=recomputable,
            )
        agrees = hashlib.sha256(onchain_descriptor).hexdigest() == fingerprint_
        return RegistryFinding(
            fingerprint=fingerprint_,
            status=REGISTRY_AGREES if agrees else REGISTRY_DISAGREES,
            reason=None if agrees else REGISTRY_DISAGREEMENT,
            locally_known=known,
            locally_recomputable=recomputable,
            onchain_descriptor=decode_descriptor(onchain_descriptor),
            onchain_descriptor_hex=onchain_descriptor.hex(),
        )


# ------------------------------------------------- receipt-frame registry (waxseal-fg4.9)
#
# Append-only, like VersionRegistry above, but a separate mechanism rather
# than a reuse of it (domain/receipt_fingerprint.py explains why): the
# receipt_head hash is computed server-side (REMOTE.md section 10), so this
# build never recomputes one and has no `encoder_for`/`recomputable` concept
# to offer here. What it offers is exactly what `VersionRegistry.knows` offers
# for `hash_version` -- recognizing a declared identity, or not -- which is
# the one fact `domain/receipts.py` needs to keep an unrecognized receipt
# frame unverifiable (exit 2) instead of either trusting it blindly or
# calling it a break.


class ReceiptFrameRegistry:
    def __init__(self) -> None:
        self._schemas: dict[str, tuple[str, ...]] = {
            receipt_fingerprint(): RECEIPT_FRAME_FIELDS
        }

    def knows(self, fingerprint_: str) -> bool:
        return fingerprint_ in self._schemas

    def fields(self, fingerprint_: str) -> tuple[str, ...]:
        return self._schemas[fingerprint_]

    def register(self, fields: tuple[str, ...]) -> str:
        """Append a receipt-frame field set; returns its fingerprint.
        Idempotent for identical field tuples (CLAUDE.md rule 2: same fields
        ⇒ same fingerprint ⇒ setdefault is a no-op, never a conflicting
        re-registration)."""
        fp = receipt_fingerprint_for(fields)
        self._schemas.setdefault(fp, fields)
        return fp
