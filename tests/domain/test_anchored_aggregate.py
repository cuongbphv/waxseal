"""Binding the FssAgg accumulator into what an external witness attests.

SPEC's aggregate section names a residual risk it cannot close on its own: an
attacker who truncates the trail AND replays an older `.sealagg` produces a
state that verifies, because every artifact they left behind agrees with every
other one. Nothing local can see it — the evidence and the thing it attests
are under the same authority.

An external anchor breaks that symmetry, but only if the anchored bytes
actually mention the aggregate. These tests cover the two halves of doing that
safely:

- what is anchored is a COMMITMENT to the accumulator, never the accumulator.
  Publishing mu at every checkpoint would hand a truncating attacker the exact
  intermediate values SPEC forbids persisting, at checkpoint granularity —
  reopening the hole at the cost of closing it.
- a checkpoint with no aggregate still produces the v1 frame, byte for byte.
  Anything else would silently invalidate every anchor taken before today.
"""

from __future__ import annotations

import hashlib
import struct

import pytest

from waxseal.domain.checkpoint import (
    CHECKPOINT_FRAME_PREFIX,
    CHECKPOINT_FRAME_PREFIX_V2,
    Checkpoint,
    checkpoint_for,
    checkpoint_frame,
    verify_checkpoint,
)
from waxseal.domain.hashing import lp
from waxseal.domain.sealing import (
    AGG_COMMIT_FRAME_PREFIX,
    FS_HMAC_AGG_SCHEME,
    FS_HMAC_SCHEME,
    Attestation,
    aggregate_commit,
    aggregate_step,
    evolve_key,
    generate_key,
    seal_entry,
    verify_anchored_aggregate,
)

HASHES = [f"{i:064x}" for i in range(1, 6)]
KEY = b"\x11" * 32


def sealed(n: int, *, scheme: str = FS_HMAC_AGG_SCHEME) -> list[Attestation]:
    """``n`` attestations sealed under the evolving key from ``KEY``."""
    out = []
    key = KEY
    for i in range(n):
        out.append(
            Attestation(
                seq=i,
                entry_hash=HASHES[i],
                scheme=scheme,
                value=seal_entry(key, HASHES[i]),
            )
        )
        key = evolve_key(key)
    return out


def fold(atts: list[Attestation], *, upto: int, agg_start: int = 0) -> str:
    key = KEY
    running = "0" * 64
    for position, att in enumerate(atts):
        if position >= upto:
            break
        if position >= agg_start and att.scheme == FS_HMAC_AGG_SCHEME:
            running = aggregate_step(key, running, att.value)
        key = evolve_key(key)
    return running


class TestAggregateCommit:
    def test_is_a_sha256_over_the_framed_epoch_and_value(self) -> None:
        agg = "ab" * 32
        expected = hashlib.sha256(
            AGG_COMMIT_FRAME_PREFIX + struct.pack(">Q", 2) + lp("3") + lp(agg)
        ).hexdigest()
        assert aggregate_commit(3, agg) == expected

    def test_hides_the_accumulator(self) -> None:
        # The point of committing rather than publishing: an attacker reading
        # the anchor stream must not come away with a value they can fold.
        agg = aggregate_step(KEY, "0" * 64, "beef" * 16)
        assert agg not in aggregate_commit(1, agg)

    def test_epoch_is_bound_not_just_the_value(self) -> None:
        agg = "cd" * 32
        assert aggregate_commit(3, agg) != aggregate_commit(4, agg)

    def test_distinct_values_commit_differently(self) -> None:
        assert aggregate_commit(1, "aa" * 32) != aggregate_commit(1, "bb" * 32)

    def test_rejects_a_non_hex_aggregate(self) -> None:
        # A caller passing something that is not an accumulator is a bug here,
        # not attacker input — this function is only ever called on values the
        # library itself produced.
        with pytest.raises(ValueError):
            aggregate_commit(1, "not hex")


class TestCheckpointV1Compatibility:
    def test_frame_without_an_aggregate_is_unchanged(self) -> None:
        cp = Checkpoint(seq=2, entry_hash=HASHES[2], root=HASHES[0])
        expected = (
            CHECKPOINT_FRAME_PREFIX
            + struct.pack(">Q", 3)
            + lp("2")
            + lp(HASHES[2])
            + lp(HASHES[0])
        )
        assert checkpoint_frame(cp) == expected

    def test_checkpoint_for_still_defaults_to_v1(self) -> None:
        cp = checkpoint_for(HASHES[:3])
        assert cp.agg_commit is None
        assert cp.agg_epoch is None
        assert checkpoint_frame(cp).startswith(CHECKPOINT_FRAME_PREFIX)

    def test_verify_checkpoint_ignores_the_aggregate_fields(self) -> None:
        # Checking the aggregate needs a key; verify_checkpoint has none and
        # must not pretend the chain-shape check covered it.
        cp = checkpoint_for(HASHES[:3], agg_commit="ab" * 32, agg_epoch=3)
        assert verify_checkpoint(HASHES, cp) is None


class TestCheckpointV2:
    def test_frame_layout(self) -> None:
        cp = Checkpoint(
            seq=2, entry_hash=HASHES[2], root=HASHES[0], agg_commit="ab" * 32, agg_epoch=3
        )
        expected = (
            CHECKPOINT_FRAME_PREFIX_V2
            + struct.pack(">Q", 5)
            + lp("2")
            + lp(HASHES[2])
            + lp(HASHES[0])
            + lp("3")
            + lp("ab" * 32)
        )
        assert checkpoint_frame(cp) == expected

    def test_v2_and_v1_frames_can_never_collide(self) -> None:
        # PAE framing does the work: a different prefix and a different field
        # count, so no v2 frame can be read as a v1 frame of other content.
        v1 = checkpoint_frame(Checkpoint(seq=1, entry_hash=HASHES[1], root=HASHES[0]))
        v2 = checkpoint_frame(
            Checkpoint(
                seq=1, entry_hash=HASHES[1], root=HASHES[0], agg_commit="ab" * 32, agg_epoch=1
            )
        )
        assert v1 != v2
        assert not v2.startswith(CHECKPOINT_FRAME_PREFIX)

    def test_changing_the_commit_changes_the_frame(self) -> None:
        base = dict(seq=1, entry_hash=HASHES[1], root=HASHES[0], agg_epoch=1)
        a = checkpoint_frame(Checkpoint(**base, agg_commit="aa" * 32))  # type: ignore[arg-type]
        b = checkpoint_frame(Checkpoint(**base, agg_commit="bb" * 32))  # type: ignore[arg-type]
        assert a != b

    @pytest.mark.parametrize(
        "commit,epoch", [("ab" * 32, None), (None, 3)]
    )
    def test_half_a_binding_is_refused(self, commit: str | None, epoch: int | None) -> None:
        # Either field alone would produce a frame that claims an aggregate
        # nobody can check, or an epoch that commits to nothing. Refused at
        # CONSTRUCTION, not at framing: the sinks serialize a checkpoint to
        # JSON without ever calling checkpoint_frame, so a guard living only
        # in the frame let a half binding onto the wire as "agg_epoch": null.
        with pytest.raises(ValueError, match="both"):
            Checkpoint(
                seq=1, entry_hash=HASHES[1], root=HASHES[0], agg_commit=commit, agg_epoch=epoch
            )

    def test_checkpoint_for_carries_the_binding(self) -> None:
        cp = checkpoint_for(HASHES[:4], agg_commit="ab" * 32, agg_epoch=4)
        assert (cp.seq, cp.agg_epoch, cp.agg_commit) == (3, 4, "ab" * 32)


class TestVerifyAnchoredAggregate:
    def test_accepts_the_commitment_it_was_anchored_with(self) -> None:
        atts = sealed(5)
        commit = aggregate_commit(3, fold(atts, upto=3))
        assert (
            verify_anchored_aggregate(
                atts, KEY, agg_start=0, anchored_epoch=3, anchored_commit=commit
            )
            is None
        )

    def test_accepts_an_anchor_taken_before_the_trail_grew(self) -> None:
        # The whole point of an anchor: it describes a past state. Rows added
        # since are not a discrepancy — unlike verify_aggregate, which checks
        # the CURRENT sidecar and does treat later aggregate rows as a gap.
        atts = sealed(5)
        commit = aggregate_commit(2, fold(atts, upto=2))
        assert (
            verify_anchored_aggregate(
                atts, KEY, agg_start=0, anchored_epoch=2, anchored_commit=commit
            )
            is None
        )

    def test_catches_a_replayed_aggregate_over_a_truncated_trail(self) -> None:
        # The residual risk this feature exists for. The attacker truncates
        # the trail to 2 rows and restores the `.sealagg` from when there were
        # 2 rows; everything local agrees. The anchor, taken at epoch 5 and
        # held elsewhere, still says five rows were folded.
        full = sealed(5)
        anchored = aggregate_commit(5, fold(full, upto=5))
        truncated = full[:2]

        reason = verify_anchored_aggregate(
            truncated, KEY, agg_start=0, anchored_epoch=5, anchored_commit=anchored
        )
        assert reason == "anchored_aggregate_epoch_mismatch"

    def test_catches_a_rewritten_row_inside_the_anchored_prefix(self) -> None:
        atts = sealed(4)
        anchored = aggregate_commit(4, fold(atts, upto=4))
        forged = [*atts[:2], Attestation(seq=2, entry_hash=HASHES[2], scheme=FS_HMAC_AGG_SCHEME,
                                         value="ff" * 32), atts[3]]
        assert (
            verify_anchored_aggregate(
                forged, KEY, agg_start=0, anchored_epoch=4, anchored_commit=anchored
            )
            == "anchored_aggregate_mismatch"
        )

    def test_catches_a_forged_commitment(self) -> None:
        atts = sealed(3)
        assert (
            verify_anchored_aggregate(
                atts, KEY, agg_start=0, anchored_epoch=3, anchored_commit="ab" * 32
            )
            == "anchored_aggregate_mismatch"
        )

    def test_wrong_key_does_not_verify(self) -> None:
        atts = sealed(3)
        commit = aggregate_commit(3, fold(atts, upto=3))
        assert (
            verify_anchored_aggregate(
                atts, generate_key(), agg_start=0, anchored_epoch=3, anchored_commit=commit
            )
            == "anchored_aggregate_mismatch"
        )

    def test_honours_a_mid_trail_agg_start(self) -> None:
        plain = sealed(2, scheme=FS_HMAC_SCHEME)
        rest = sealed(5)[2:]
        atts = [*plain, *rest]
        commit = aggregate_commit(5, fold(atts, upto=5, agg_start=2))
        assert (
            verify_anchored_aggregate(
                atts, KEY, agg_start=2, anchored_epoch=5, anchored_commit=commit
            )
            is None
        )

    @pytest.mark.parametrize(
        "agg_start,epoch", [(-1, 3), (4, 3)]
    )
    def test_impossible_bounds_are_malformed(self, agg_start: int, epoch: int) -> None:
        assert (
            verify_anchored_aggregate(
                sealed(5), KEY, agg_start=agg_start, anchored_epoch=epoch,
                anchored_commit="ab" * 32,
            )
            == "malformed_anchored_aggregate"
        )

    def test_non_hex_commitment_is_malformed_not_a_mismatch(self) -> None:
        assert (
            verify_anchored_aggregate(
                sealed(3), KEY, agg_start=0, anchored_epoch=3, anchored_commit="zz"
            )
            == "malformed_anchored_aggregate"
        )

    def test_unfoldable_attestation_value_is_malformed(self) -> None:
        # The attestation sidecar is attacker-writable; a value the fold
        # cannot even run over is a verdict, never a traceback.
        atts = [Attestation(seq=0, entry_hash=HASHES[0], scheme=FS_HMAC_AGG_SCHEME, value="\udc80")]
        assert (
            verify_anchored_aggregate(
                atts, KEY, agg_start=0, anchored_epoch=1, anchored_commit="ab" * 32
            )
            == "malformed_anchored_aggregate"
        )

    def test_never_raises_on_hostile_input(self) -> None:
        atts = [Attestation(seq=0, entry_hash="", scheme="who-knows", value="")]
        assert verify_anchored_aggregate(
            atts, KEY, agg_start=0, anchored_epoch=1, anchored_commit=""
        ) is not None

    def test_zero_epoch_commits_to_the_genesis_accumulator(self) -> None:
        atts = sealed(3)
        assert (
            verify_anchored_aggregate(
                atts, KEY, agg_start=0, anchored_epoch=0,
                anchored_commit=aggregate_commit(0, "0" * 64),
            )
            is None
        )
