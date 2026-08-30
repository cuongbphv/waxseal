"""Theorem 5.7 / knowledge monotonicity (waxseal-7tk.6.1, plan doc W7 item 1).

If R' subset-of R and R verified a chain ok, R' must NEVER report `broken` --
it may only turn more rows `unverifiable` (it recognizes fewer fingerprints).
This is the exact failure class the whole library exists to prevent: a
schema-version rollback (beads v1.2.2) or a widened field set under a stable
name (migration 060) must never manufacture a false tampering alarm.

`verify_chain` (domain/verify.py) makes this true with one placement choice:
`expected_prev = entry.entry_hash` sits OUTSIDE the if/else that decides
whether a row is checked or marked unverifiable, so even a row this build
cannot recompute still anchors the NEXT row's expected prev_hash. Shrinking
the registry then only ever adds unverifiable rows, never breaks linkage.

This file does not edit verify.py (frozen for this bead; the clarifying
comment at verify.py:76 is a separate, later bead, W7.2). It (1) proves the
real verify_chain honors the property across every subset of a known
registry, and (2) proves the test is not vacuously passing by demonstrating,
against a local reimplementation with the bug reintroduced, that the same
construction DOES manufacture a false `broken` verdict.
"""

from __future__ import annotations

import itertools
from collections.abc import Iterable
from dataclasses import replace

from tests.domain.test_verify import build_chain
from waxseal.domain.fingerprint import HEADER_FIELDS, fingerprint
from waxseal.domain.hashing import compute_entry_hash, compute_payload_hash
from waxseal.domain.header import GENESIS_PREV_HASH, Entry
from waxseal.domain.registry import VersionRegistry
from waxseal.domain.verify import VerifyResult, verify_chain

# Two widened field sets, registered on top of the always-present v1 schema
# (VersionRegistry.__init__ seeds v1 unconditionally -- there is no removal
# API, CLAUDE.md rule 2 -- so v1 is present in every subset by construction;
# only these two are actually optional knowledge).
FIELDS_FP2 = (*HEADER_FIELDS, "actor")
FIELDS_FP3 = (*HEADER_FIELDS, "actor", "note")


def _full_registry() -> tuple[VersionRegistry, str, str]:
    reg = VersionRegistry()
    fp2 = reg.register(FIELDS_FP2)
    fp3 = reg.register(FIELDS_FP3)
    return reg, fp2, fp3


def _relink_from(chain: list[Entry], start_idx: int, prev_hash: str) -> None:
    """Recompute prev_hash + entry_hash forward from start_idx, in place.
    Rewriting one row's header (e.g. to point at a foreign row's stored
    hash) changes that row's own entry_hash, which invalidates every
    downstream row's prev_hash link unless the whole suffix is re-chained --
    this is the real cost an attacker (or a test fixture) pays for editing
    row content anywhere but the tail.
    """
    prev = prev_hash
    for i in range(start_idx, len(chain)):
        header = replace(chain[i].header, prev_hash=prev)
        entry_hash = compute_entry_hash(header)
        chain[i] = replace(chain[i], header=header, entry_hash=entry_hash)
        prev = entry_hash


def _chain_with_two_foreign_rows(fp2: str, fp3: str) -> list[Entry]:
    """A 7-entry chain (seq 0..6) with rows 2 and 5 written under fingerprints
    registered but not recomputable by this build (VersionRegistry.recomputable
    only ever matches HEADER_FIELDS exactly -- a registered-but-different
    schema degrades to unverifiable just like an unknown one). This mirrors
    TestRegisteredButNotRecomputable in test_verify.py and the plan doc's
    counter-example shape: a known row, then a foreign row, then a known row
    again, twice over.
    """
    chain = build_chain(7)

    foreign2_header = replace(chain[2].header, hash_version=fp2)
    foreign2_hash = "f" * 64  # a hash only the writer's own frame could produce
    chain[2] = replace(chain[2], header=foreign2_header, entry_hash=foreign2_hash)
    _relink_from(chain, 3, foreign2_hash)

    foreign5_header = replace(chain[5].header, hash_version=fp3)
    foreign5_hash = "a" * 64
    chain[5] = replace(chain[5], header=foreign5_header, entry_hash=foreign5_hash)
    _relink_from(chain, 6, foreign5_hash)

    return chain


class TestRollbackKnowledgeMonotonicity:
    """R' subset-of R, R verified ok => R' never reports broken."""

    def test_full_registry_baseline_is_ok(self) -> None:
        reg, fp2, fp3 = _full_registry()
        chain = _chain_with_two_foreign_rows(fp2, fp3)
        result = verify_chain(chain, reg)
        assert result.ok
        assert result.broken_seq is None
        assert result.unverifiable == (2, 5)
        assert result.checked == 5

    def test_every_subset_of_known_fingerprints_stays_unbroken(self) -> None:
        reg, fp2, fp3 = _full_registry()
        chain = _chain_with_two_foreign_rows(fp2, fp3)

        # Baseline: R itself must verify ok before rollback subsets are even
        # meaningful to test against it.
        baseline = verify_chain(chain, reg)
        assert baseline.ok
        assert baseline.broken_seq is None

        fingerprints = (fingerprint(), fp2, fp3)
        fields_by_fingerprint = {
            fingerprint(): HEADER_FIELDS,
            fp2: FIELDS_FP2,
            fp3: FIELDS_FP3,
        }

        total_subsets = 0
        for size in range(len(fingerprints) + 1):
            for subset in itertools.combinations(fingerprints, size):
                total_subsets += 1
                contracted = VersionRegistry()
                for fp in subset:
                    contracted.register(fields_by_fingerprint[fp])

                result = verify_chain(chain, contracted)

                assert result.broken_seq is None, (
                    f"registry co lai thanh {subset} sinh ra broken "
                    f"({result.reason} tai seq {result.broken_seq}) - "
                    "vi pham knowledge monotonicity"
                )

        # C(3,0)+C(3,1)+C(3,2)+C(3,3) = 1+3+3+1 = 8: every subset of the
        # 3 known fingerprints (v1 is unremovable in practice, per the
        # comment on FIELDS_FP2/FIELDS_FP3 above, but is still enumerated
        # here for completeness of "toan bo tap con").
        assert total_subsets == 8


# --- Falsifiability receipt ---------------------------------------------
#
# CLAUDE.md rule 9 / the concurrency test's own falsifiability receipt is the
# template: a test that can never fail proves nothing. This section does NOT
# touch src/waxseal/domain/verify.py (frozen for this bead). It reimplements
# the verify loop LOCALLY with the one-line regression the plan doc names:
# `expected_prev = entry.entry_hash` moved INTO the `else` (checked) branch,
# instead of sitting outside the if/else as the real code has it.
#
# Concrete counter-example (plan doc W7 item 1, matching
# _chain_with_two_foreign_rows above): row 2 is foreign (registered but not
# recomputable), so it takes the "unverifiable" branch. Under the buggy
# variant, `expected_prev` is NOT updated to row 2's stored entry_hash.
# Row 3's real prev_hash correctly points at row 2's stored hash, so it now
# mismatches whatever row 1 left behind in `expected_prev` -- a false
# `prev_hash_mismatch`. This is exactly migration-060 / beads-v1.2.2: an
# unrecognized-but-legitimate row manufactures a tampering alarm purely
# because the verifier knows less, not because anything was tampered.


def _verify_chain_with_prev_anchor_bug(
    entries: Iterable[Entry], registry: VersionRegistry
) -> VerifyResult:
    """LOCAL, test-only copy of verify_chain's loop with the regression the
    falsifiability receipt exists to catch: `expected_prev` is advanced only
    inside the "recomputable" branch, so an unverifiable row no longer anchors
    the next row's expected prev_hash. Never import this into production code;
    it exists solely to prove the rollback-matrix test above is not vacuous.
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

    for expected_seq, entry in enumerate(entries):
        header = entry.header
        if header.seq != expected_seq:
            return broken(header.seq, "seq_gap")
        if header.prev_hash != expected_prev:
            return broken(header.seq, "prev_hash_mismatch")

        if not registry.recomputable(header.hash_version):
            unverifiable.append(header.seq)
            # BUG under test: no `expected_prev` update here (real code has
            # it after this whole if/else, unconditionally).
        else:
            if compute_entry_hash(header) != entry.entry_hash:
                return broken(header.seq, "entry_hash_mismatch")
            if (
                entry.payload is not None
                and compute_payload_hash(entry.payload) != header.payload_hash
            ):
                return broken(header.seq, "payload_hash_mismatch")
            checked += 1
            expected_prev = entry.entry_hash  # moved INSIDE the else branch

    return VerifyResult(
        ok=True,
        checked=checked,
        broken_seq=None,
        reason=None,
        unverifiable=tuple(unverifiable),
        dropped_writes=None,
    )


class TestFalsifiabilityReceipt:
    """Demonstrates the rollback-matrix test above is falsifiable: the exact
    same chain/registry construction that the real verify_chain reports ok
    for is reported broken by the buggy variant. These assertions describe
    the BROKEN variant's (bad) behavior and are expected to pass -- they are
    not a regression test on production code, they are the receipt that the
    real test could have caught a real regression.
    """

    def test_real_verify_chain_is_unbroken_on_this_construction(self) -> None:
        # Re-establish the baseline the receipt is contrasted against, so
        # this test is self-contained even if read in isolation.
        reg, fp2, fp3 = _full_registry()
        chain = _chain_with_two_foreign_rows(fp2, fp3)
        result = verify_chain(chain, reg)
        assert result.ok
        assert result.broken_seq is None

    def test_buggy_prev_anchor_placement_manufactures_false_broken(self) -> None:
        reg, fp2, fp3 = _full_registry()
        chain = _chain_with_two_foreign_rows(fp2, fp3)

        result = _verify_chain_with_prev_anchor_bug(chain, reg)

        # The buggy variant DOES invent a broken verdict from the very first
        # foreign row (seq 2) onward: row 3's genuine prev_hash link is
        # rejected because expected_prev was frozen at row 1's hash.
        assert result.broken_seq == 3
        assert result.reason == "prev_hash_mismatch"
        assert not result.ok

    def test_buggy_variant_breaks_at_least_one_subset_in_the_matrix(self) -> None:
        # Same combinatorial sweep as the real test, run against the buggy
        # variant: at least one subset (here, every subset, since the bug
        # fires independent of registry contents once a foreign row exists)
        # must produce broken_seq is not None -- proving the matrix test
        # would have failed had verify.py carried this regression.
        reg, fp2, fp3 = _full_registry()
        chain = _chain_with_two_foreign_rows(fp2, fp3)

        fingerprints = (fingerprint(), fp2, fp3)
        fields_by_fingerprint = {
            fingerprint(): HEADER_FIELDS,
            fp2: FIELDS_FP2,
            fp3: FIELDS_FP3,
        }

        saw_broken = False
        for size in range(len(fingerprints) + 1):
            for subset in itertools.combinations(fingerprints, size):
                contracted = VersionRegistry()
                for fp in subset:
                    contracted.register(fields_by_fingerprint[fp])
                result = _verify_chain_with_prev_anchor_bug(chain, contracted)
                if result.broken_seq is not None:
                    saw_broken = True

        assert saw_broken, (
            "falsifiability receipt is vacuous: the buggy variant never "
            "produced a broken verdict across the matrix"
        )
