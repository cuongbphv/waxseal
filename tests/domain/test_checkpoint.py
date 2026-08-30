"""Checkpoints: a bytes-only snapshot an external anchor sink can witness.

The frame is pinned byte-exact (like header_frame/SEAL_FRAME_PREFIX): any
change to field order or the prefix constant changes what an already-issued
anchor receipt is proving, which is exactly the migration-060 failure class
CLAUDE.md exists to make unrepresentable.
"""

from __future__ import annotations

import hashlib
import struct

import pytest

from waxseal.domain.anchoring import batch_root
from waxseal.domain.checkpoint import (
    CHECKPOINT_FRAME_PREFIX,
    Checkpoint,
    checkpoint_for,
    checkpoint_frame,
    verify_checkpoint,
)


def entry_hashes(n: int) -> list[str]:
    return [hashlib.sha256(f"entry-{i}".encode()).hexdigest() for i in range(n)]


class TestCheckpointFrame:
    def test_frame_is_pinned_byte_exact(self) -> None:
        cp = Checkpoint(seq=2, entry_hash="ab" * 32, root="cd" * 32)

        def lp(s: str) -> bytes:
            # SPEC section 2 (lp64), re-derived here rather than imported so a
            # framing change fails loudly instead of tracking the code.
            enc = b"\x01" + s.encode("utf-8")
            return struct.pack(">Q", len(enc)) + enc

        expected = (
            CHECKPOINT_FRAME_PREFIX
            + struct.pack(">Q", 3)
            + lp("2")
            + lp("ab" * 32)
            + lp("cd" * 32)
        )
        assert checkpoint_frame(cp) == expected

    def test_frame_prefix_is_exactly_this_constant(self) -> None:
        # Pinned literal, not derived from the constant itself — a change to
        # the constant must be a visible diff in this test.
        assert CHECKPOINT_FRAME_PREFIX == b"waxseal-checkpoint-v1\n"

    def test_different_seq_gives_different_frame(self) -> None:
        a = Checkpoint(seq=1, entry_hash="aa" * 32, root="bb" * 32)
        b = Checkpoint(seq=2, entry_hash="aa" * 32, root="bb" * 32)
        assert checkpoint_frame(a) != checkpoint_frame(b)


class TestCheckpointFor:
    def test_checkpoints_the_current_tip_and_root(self) -> None:
        hashes = entry_hashes(5)
        cp = checkpoint_for(hashes)
        assert cp == Checkpoint(seq=4, entry_hash=hashes[-1], root=batch_root(hashes))

    def test_single_entry_trail(self) -> None:
        hashes = entry_hashes(1)
        cp = checkpoint_for(hashes)
        assert cp.seq == 0
        assert cp.entry_hash == hashes[0]
        assert cp.root == batch_root(hashes)

    def test_empty_trail_raises(self) -> None:
        with pytest.raises(ValueError, match="empty"):
            checkpoint_for([])


class TestVerifyCheckpoint:
    def test_fresh_checkpoint_verifies(self) -> None:
        hashes = entry_hashes(6)
        cp = checkpoint_for(hashes)
        assert verify_checkpoint(hashes, cp) is None

    def test_checkpoint_still_verifies_after_the_trail_grows(self) -> None:
        # A checkpoint pins a PREFIX of the trail — later appends must not
        # invalidate an earlier anchor (append-only, CLAUDE.md).
        hashes = entry_hashes(6)
        cp = checkpoint_for(hashes)
        grown = entry_hashes(6) + entry_hashes(10)[6:]
        assert verify_checkpoint(grown, cp) is None

    def test_seq_beyond_current_head_is_anchor_beyond_head(self) -> None:
        hashes = entry_hashes(6)
        cp = checkpoint_for(hashes)
        assert verify_checkpoint(hashes[:4], cp) == "anchor_beyond_head"

    def test_negative_seq_is_malformed(self) -> None:
        cp = Checkpoint(seq=-1, entry_hash="aa" * 32, root="bb" * 32)
        assert verify_checkpoint(entry_hashes(3), cp) == "malformed_checkpoint"

    def test_rewritten_entry_at_the_checkpointed_seq_is_entry_hash_mismatch(self) -> None:
        hashes = entry_hashes(6)
        cp = checkpoint_for(hashes)
        tampered = list(hashes)
        tampered[cp.seq] = hashlib.sha256(b"forged").hexdigest()
        assert verify_checkpoint(tampered, cp) == "anchor_entry_hash_mismatch"

    def test_reordered_prefix_is_root_mismatch_even_with_same_tip(self) -> None:
        # Swap two entries ahead of the tip: the tip hash at `seq` is
        # untouched, so only the batch root catches the reorder.
        hashes = entry_hashes(6)
        cp = checkpoint_for(hashes)
        swapped = list(hashes)
        swapped[1], swapped[2] = swapped[2], swapped[1]
        assert verify_checkpoint(swapped, cp) == "anchor_root_mismatch"

    def test_non_hex_entry_hash_earlier_in_the_trail_is_root_mismatch_not_a_crash(
        self,
    ) -> None:
        # waxseal-lmv (never-raise fuzzing sweep): the local trail file is
        # attacker-writable by the same threat model as the sidecar
        # (CLAUDE.md) -- a corrupted `entry_hash` field elsewhere in the
        # prefix must not crash this function's own documented "fails closed
        # and never raises" promise. `batch_root` calls `bytes.fromhex` with
        # no guard, and a non-hex entry earlier in the prefix let ValueError
        # escape uncaught before this fix, even though the checkpointed TIP
        # itself matches. Root cannot be recomputed -> cannot be confirmed to
        # match -> the existing anchor_root_mismatch reason (same vocabulary
        # domain.anchoring's bad-hex-returns-False convention already uses),
        # not a crash.
        hashes = entry_hashes(2)
        cp = checkpoint_for(hashes)
        corrupted = [hashes[0], hashes[1]]
        corrupted[0] = "not-hex-at-all"
        assert verify_checkpoint(corrupted, cp) == "anchor_root_mismatch"


class TestSinkReceiptLivesInDomain:
    """SinkReceipt is the AnchorSink Protocol's return envelope, so the
    ports layer must be able to name it — and ports import domain at most
    (the layer DAG). Living in adapters made the Protocol's annotation a
    lie (`str | None` while Rfc3161AnchorSink returns SinkReceipt)."""

    def test_importable_from_domain_checkpoint(self) -> None:
        from waxseal.domain.checkpoint import SinkReceipt

        r = SinkReceipt("receipt-bytes-as-str")
        assert r.receipt == "receipt-bytes-as-str"
        assert r.nonce is None

    def test_ports_annotation_names_it(self) -> None:
        import typing

        from waxseal.domain.checkpoint import SinkReceipt
        from waxseal.ports.anchor import AnchorSink

        hints = typing.get_type_hints(AnchorSink.anchor)
        assert SinkReceipt in typing.get_args(hints["return"])
