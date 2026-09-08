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

from waxseal.domain.hashing import LpEncodingError, compute_entry_hash, compute_payload_hash
from waxseal.domain.header import GENESIS_PREV_HASH, Entry
from waxseal.domain.registry import VersionRegistry


@dataclass(frozen=True, slots=True)
class VerifyResult:
    ok: bool
    checked: int
    broken_seq: int | None
    reason: str | None
    unverifiable: tuple[int, ...]
    # None = not measured (CLAUDE.md rule 5): a verifier walking storage
    # cannot see writes that were dropped before they reached storage.
    dropped_writes: int | None
    # Trailing default: every existing construction/replace() site keeps
    # working unchanged. None = dropped_writes is also None (never
    # measured); "process" = an in-memory counter, reset on every AuditLog.open;
    # "sidecar" = a DropRecorder's own sidecar, durable across process restarts.
    drops_source: str | None = None


def verify_chain(entries: Iterable[Entry], registry: VersionRegistry) -> VerifyResult:
    """Walk ``entries`` once. Reports the first break; never rewrites a row.
    Unknown fingerprints collect as unverifiable, never as tampered.
    """
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
            # encoder is guaranteed non-None here: this branch is only
            # reached when registry.recomputable(header.hash_version) is
            # True, and encoder_for/recomputable agree on that set by
            # construction (domain/registry.py, waxseal-7tk.7.3) -- dispatch
            # by fingerprint rather than assuming the v1 frame, so a row
            # stamped with a different (but recomputable) encoding is hashed
            # under the frame it was actually signed with.
            encoder = registry.encoder_for(header.hash_version)
            assert encoder is not None  # type-narrowing; recomputable() already proved this
            try:
                recomputed = compute_entry_hash(header, frame=encoder)
            except LpEncodingError:
                # waxseal-lmv (never-raise fuzzing sweep): a header field can
                # be a `str` no UTF-8 form exists for (a lone UTF-16
                # surrogate -- json.loads('"\ud800"') produces exactly this,
                # so an attacker-writable JSONL trail can carry it). `lp()`
                # already labels that as LpEncodingError instead of a bare
                # UnicodeEncodeError (gap G4, test_properties.py), but this
                # call left it uncaught, so a recomputable row's verifier
                # crashed instead of reporting a verdict -- the "NEVER a
                # crash" promise CLAUDE.md's Locked Design section makes for
                # exactly this case. A header this build cannot even encode
                # can never reproduce the stored hash, so this is the
                # existing entry_hash_mismatch finding (CLAUDE.md rules 4/5/6),
                # not a new incident class.
                return broken(header.seq, "entry_hash_mismatch")
            if recomputed != entry.entry_hash:
                return broken(header.seq, "entry_hash_mismatch")
            if (
                entry.payload is not None
                and compute_payload_hash(entry.payload) != header.payload_hash
            ):
                return broken(header.seq, "payload_hash_mismatch")
            checked += 1

        # Deliberately OUTSIDE the if/else above, not a formatting accident.
        # Counter-example (rows 5/6/7, tests/domain/test_knowledge_monotonicity.py):
        # row 5 known, row 6 unverifiable, row 7 known with prev_hash = row 6's
        # stored entry_hash. Move this line into the `else` branch and row 6 no
        # longer advances expected_prev, so row 7's genuine link is compared
        # against row 5's hash instead and mismatches. A registry that simply
        # knows fewer fingerprints (a schema-version rollback) manufactures a
        # false `prev_hash_mismatch`/broken verdict from a row nothing tampered
        # with. That is the migration-060 / beads-v1.2.2 failure class recreated
        # inside this function (SPEC.md §5: unverifiable rows "still participate
        # as prev_hash input for the next row").
        expected_prev = entry.entry_hash

    return VerifyResult(
        ok=True,
        checked=checked,
        broken_seq=None,
        reason=None,
        unverifiable=tuple(unverifiable),
        dropped_writes=None,
    )
