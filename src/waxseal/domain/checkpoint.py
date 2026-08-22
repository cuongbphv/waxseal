"""Checkpoints: a bytes-only snapshot an external anchor sink can witness.

A checkpoint pins ``(seq, entry_hash, root)`` at one moment. ``seq``/``entry_hash``
are the ordinary chain tip; ``root`` is the RFC 6962 batch root over every entry
hash the trail has produced so far (``domain.anchoring.batch_root``). The tip
alone is already tamper-evident against edits BEHIND it via ``prev_hash`` — the
root is what lets a THIRD PARTY (a file sidecar, a signed release, another
host) witness the whole trail without holding a copy of it, closing the
whole-trail-rewrite gap a hash chain cannot resist on its own (DESIGN.md's
anchoring rationale).

The frame carries no timestamp: it must be exactly reproducible from the
trail's own entry hashes alone, and the "when" comes from whatever anchors it
(a block time, an RFC 3161 token, a commit) — baking a clock reading in here
would make the frame depend on something the trail itself can't reproduce.
"""

from __future__ import annotations

import struct
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

from waxseal.domain.anchoring import batch_root
from waxseal.domain.hashing import lp

CHECKPOINT_FRAME_PREFIX: Final = b"waxseal-checkpoint-v1\n"


@dataclass(frozen=True, slots=True)
class Checkpoint:
    seq: int
    entry_hash: str
    root: str


def checkpoint_frame(checkpoint: Checkpoint) -> bytes:
    """Canonical bytes for a checkpoint: PAE-style prefix + field count + fields."""
    return (
        CHECKPOINT_FRAME_PREFIX
        + struct.pack(">Q", 3)
        + lp(str(checkpoint.seq))
        + lp(checkpoint.entry_hash)
        + lp(checkpoint.root)
    )


def checkpoint_for(entry_hashes: Sequence[str]) -> Checkpoint:
    """Checkpoint over ``entry_hashes`` (write order, index 0 is seq 0).

    Raises ValueError on an empty trail: there is no tip to pin, and silently
    returning some placeholder would be a checkpoint over nothing that a
    caller could still anchor by mistake.
    """
    if not entry_hashes:
        raise ValueError("cannot checkpoint an empty trail")
    return Checkpoint(
        seq=len(entry_hashes) - 1,
        entry_hash=entry_hashes[-1],
        root=batch_root(entry_hashes),
    )


def verify_checkpoint(entry_hashes: Sequence[str], checkpoint: Checkpoint) -> str | None:
    """Check ``checkpoint`` against the CURRENT trail's entry hashes.

    Fails closed and never raises (CLAUDE.md rule 5: unverifiable is not the
    same lie as tampered, but a checkpoint check has only one honest trail to
    compare against, so any mismatch here is reported, not swallowed).
    Returns ``None`` when it verifies, else one of:

    - ``malformed_checkpoint``: seq is negative (not a valid index).
    - ``anchor_beyond_head``: the checkpoint claims a seq the trail has not
      reached yet (the trail was truncated after the checkpoint was taken).
    - ``anchor_entry_hash_mismatch``: the trail's hash at that seq no longer
      matches what was anchored (the tip entry was rewritten).
    - ``anchor_root_mismatch``: the tip still matches but the batch root over
      the checkpointed prefix does not (an earlier entry was rewritten or
      reordered without disturbing the chain of prev_hash links).
    """
    if checkpoint.seq < 0:
        return "malformed_checkpoint"
    if checkpoint.seq >= len(entry_hashes):
        return "anchor_beyond_head"
    if entry_hashes[checkpoint.seq] != checkpoint.entry_hash:
        return "anchor_entry_hash_mismatch"
    if batch_root(entry_hashes[: checkpoint.seq + 1]) != checkpoint.root:
        return "anchor_root_mismatch"
    return None
