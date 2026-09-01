"""Witness cross-check (domain/witnessing.py).

A pin catches a server that rewrites history for THIS client. It cannot catch
split-view: a server that serves one history to the auditor and another to the
operator, consistently, forever. Neither client can see the other's, so no
amount of local checking distinguishes the two worlds — the observation has to
leave the client (Mazières & Shasha's fork consistency argument, and the same
reason certificate transparency needs gossip).

A witness is that outside observation. The client publishes its head to a
service under a different authority and later asks what that service saw. Three
outcomes, and the third is the one implementations get wrong:

- consistent: the local trail extends every checkpoint the witness holds;
- inconsistent: it does not — evidence of a rewrite or a split view;
- unreachable: nothing was learned. Never a pass. A witness that is down
  measures nothing, and "no bad news" from a service that answered no
  questions is not evidence of anything.
"""

from __future__ import annotations

from waxseal.domain.checkpoint import Checkpoint, checkpoint_for
from waxseal.domain.witnessing import (
    WITNESS_CONSISTENT,
    WITNESS_INCONSISTENT,
    WITNESS_UNREACHABLE,
    WitnessObservation,
    check_witnessed,
    unreachable_witness,
)

HASHES = [f"{i:064x}" for i in range(1, 6)]


def seen(*sizes: int, unreadable: int = 0) -> WitnessObservation:
    return WitnessObservation(
        checkpoints=tuple(checkpoint_for(HASHES[:n]) for n in sizes), unreadable=unreadable
    )


class TestConsistent:
    def test_trail_that_extends_every_witnessed_checkpoint(self) -> None:
        verdict = check_witnessed(HASHES, seen(2, 3), name="w1")
        assert verdict.status == WITNESS_CONSISTENT
        assert verdict.checked == 2
        assert verdict.reason is None
        assert verdict.broken_seq is None

    def test_trail_exactly_at_the_witnessed_head(self) -> None:
        assert check_witnessed(HASHES, seen(5), name="w1").status == WITNESS_CONSISTENT

    def test_the_witness_name_travels_with_the_verdict(self) -> None:
        assert check_witnessed(HASHES, seen(1), name="notary-eu").name == "notary-eu"


class TestNothingWitnessed:
    def test_an_empty_witness_is_not_a_pass(self) -> None:
        # It answered, and it had nothing. That is zero coverage, and the
        # verdict has to be readable as zero coverage rather than as "fine".
        verdict = check_witnessed(HASHES, seen(), name="w1")
        assert verdict.checked == 0
        assert verdict.reason == "no_checkpoints_witnessed"


class TestInconsistent:
    def test_rewritten_history_is_caught(self) -> None:
        forged = ["f" * 64, *HASHES[1:]]
        verdict = check_witnessed(forged, seen(3), name="w1")
        assert verdict.status == WITNESS_INCONSISTENT
        assert verdict.broken_seq == 2
        assert verdict.reason == "anchor_root_mismatch"

    def test_a_trail_behind_what_the_witness_saw_is_caught(self) -> None:
        # The witness holds a checkpoint at seq 4; the trail now ends at 1.
        # Someone rolled it back, or is serving a shorter view of it.
        verdict = check_witnessed(HASHES[:2], seen(5), name="w1")
        assert verdict.status == WITNESS_INCONSISTENT
        assert verdict.reason == "anchor_beyond_head"

    def test_the_first_disagreement_is_reported(self) -> None:
        forged = [*HASHES[:3], "f" * 64, HASHES[4]]
        verdict = check_witnessed(forged, seen(2, 4, 5), name="w1")
        assert verdict.broken_seq == 3
        # Rows verified before the disagreement are still reported as such.
        assert verdict.checked == 1

    def test_inconsistency_wins_over_partial_coverage(self) -> None:
        forged = ["f" * 64, *HASHES[1:]]
        verdict = check_witnessed(forged, seen(1, 2), name="w1")
        assert verdict.status == WITNESS_INCONSISTENT


class TestUnreachable:
    def test_carries_no_coverage(self) -> None:
        verdict = unreachable_witness("w1", reason="connection refused")
        assert verdict.status == WITNESS_UNREACHABLE
        assert verdict.checked == 0
        assert verdict.reason == "connection refused"

    def test_is_distinguishable_from_consistent(self) -> None:
        # Ternary Evidence Principle regression guard (CLAUDE.md item 5): the
        # two Final string literals are provably distinct today, which is
        # exactly why mypy flags the comparison as non-overlapping -- the
        # assertion exists to catch a future edit that collapses them onto
        # the same string, not to model runtime uncertainty.
        assert WITNESS_UNREACHABLE != WITNESS_CONSISTENT  # type: ignore[comparison-overlap]


class TestUnreadableCheckpoints:
    def test_are_counted_not_silently_dropped(self) -> None:
        # A witness may hold records this build cannot read. Dropping them
        # without saying so would report the coverage of the ones it could.
        verdict = check_witnessed(HASHES, seen(2, unreadable=3), name="w1")
        assert verdict.status == WITNESS_CONSISTENT
        assert verdict.checked == 1
        assert verdict.unreadable == 3

    def test_survive_an_inconsistent_verdict(self) -> None:
        forged = ["f" * 64, *HASHES[1:]]
        verdict = check_witnessed(forged, seen(2, unreadable=1), name="w1")
        assert verdict.status == WITNESS_INCONSISTENT
        assert verdict.unreadable == 1


class TestFailClosed:
    def test_never_raises_on_hostile_checkpoints(self) -> None:
        hostile = WitnessObservation(
            checkpoints=(Checkpoint(seq=-1, entry_hash="", root=""),), unreadable=0
        )
        verdict = check_witnessed(HASHES, hostile, name="w1")
        assert verdict.status == WITNESS_INCONSISTENT
        assert verdict.reason == "malformed_checkpoint"

    def test_empty_local_trail_against_a_witness_is_inconsistent(self) -> None:
        verdict = check_witnessed([], seen(1), name="w1")
        assert verdict.status == WITNESS_INCONSISTENT
