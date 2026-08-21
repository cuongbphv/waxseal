"""Append-only version registry (SPEC.md section 4, CLAUDE.md rule 2).

Maps schema fingerprint -> header field tuple. There is deliberately no
removal or mutation API: a released fingerprint's meaning can never change.
New schemas are appended under their own (automatically different) fingerprint.
"""

from __future__ import annotations

from waxseal.domain.fingerprint import HEADER_V1_FIELDS, fingerprint_for, fingerprint_v1


class VersionRegistry:
    def __init__(self) -> None:
        self._schemas: dict[str, tuple[str, ...]] = {fingerprint_v1(): HEADER_V1_FIELDS}

    def knows(self, fingerprint: str) -> bool:
        return fingerprint in self._schemas

    def fields(self, fingerprint: str) -> tuple[str, ...]:
        return self._schemas[fingerprint]

    def recomputable(self, fingerprint: str) -> bool:
        """True only when this build's hasher reproduces the schema — i.e. the
        registered field tuple is exactly the v1 frame compute_entry_hash
        implements. A registered-but-different schema must degrade to
        unverifiable like an unknown one: recomputing it under the v1 frame
        would misreport every such row as tampered (the migration-060 /
        beads-v1.2.2 failure class, reachable through register())."""
        return self._schemas.get(fingerprint) == HEADER_V1_FIELDS

    def register(self, fields: tuple[str, ...]) -> str:
        """Append a schema; returns its fingerprint. Idempotent for identical
        field tuples — the fingerprint construction makes a conflicting
        re-registration impossible (same fields ⇒ same fingerprint)."""
        fingerprint = fingerprint_for(fields)
        self._schemas.setdefault(fingerprint, fields)
        return fingerprint
