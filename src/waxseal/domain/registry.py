"""Append-only version registry (SPEC.md section 4, CLAUDE.md rule 2).

Maps schema fingerprint -> header field tuple. There is deliberately no
removal or mutation API: a released fingerprint's meaning can never change.
New schemas are appended under their own (automatically different) fingerprint.
"""

from __future__ import annotations

from collections.abc import Callable

from waxseal.domain.fingerprint import HEADER_FIELDS, fingerprint, fingerprint_for
from waxseal.domain.hashing import ENCODING, header_frame
from waxseal.domain.header import EntryHeader

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
