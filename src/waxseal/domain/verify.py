"""Chain verification (SPEC.md section 5).

Reports, never repairs (CLAUDE.md rule 4). Returns the FIRST break; which row
is the tamper is a decision only an operator can make.

The one lie a tamper-evidence mechanism must never tell is "intact" about a row
it cannot reproduce: rows with an unknown fingerprint are reported as
unverifiable-by-name, never recomputed under a schema they were not signed
with, and never treated as tampering (the migration-060 / beads-v1.2.2 lesson).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from waxseal.domain.hashing import compute_entry_hash, compute_payload_hash
from waxseal.domain.header import GENESIS_PREV_HASH, Entry
from waxseal.domain.registry import VersionRegistry


@dataclass(frozen=True, slots=True)
class VerifyResult:
    ok: bool
    checked: int
    broken_seq: int | None
    reason: str | None
    unverifiable: tuple[int, ...]
    # None = not measured (CLAUDE.md rule 5) — a verifier walking storage
    # cannot see writes that were dropped before they reached storage.
    dropped_writes: int | None


def verify_chain(entries: Iterable[Entry], registry: VersionRegistry) -> VerifyResult:
    checked = 0
    unverifiable: list[int] = []
    expected_prev = GENESIS_PREV_HASH

    def broken(seq: int, reason: str) -> VerifyResult:
        return VerifyResult(
            ok=False,
            checked=checked,
            broken_seq=seq,
            reason=reason,
            unverifiable=tuple(unverifiable),
            dropped_writes=None,
        )

    for expected_seq, entry in enumerate(entries):  # noqa: B007 - seq must equal position
        header = entry.header
        if header.seq != expected_seq:
            return broken(header.seq, "seq_gap")
        if header.prev_hash != expected_prev:
            return broken(header.seq, "prev_hash_mismatch")

        if not registry.recomputable(header.hash_version):
            # Unverifiable by name (unknown OR registered under a frame this
            # build cannot hash): its stored entry_hash still anchors the next
            # row, so the chain stays linked through it.
            unverifiable.append(header.seq)
        else:
            if compute_entry_hash(header) != entry.entry_hash:
                return broken(header.seq, "entry_hash_mismatch")
            if (
                entry.payload is not None
                and compute_payload_hash(entry.payload) != header.payload_hash
            ):
                return broken(header.seq, "payload_hash_mismatch")
            checked += 1

        expected_prev = entry.entry_hash

    return VerifyResult(
        ok=True,
        checked=checked,
        broken_seq=None,
        reason=None,
        unverifiable=tuple(unverifiable),
        dropped_writes=None,
    )
