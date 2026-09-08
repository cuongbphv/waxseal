"""Checkpoints: a bytes-only snapshot an external anchor sink can witness.

A checkpoint pins ``(seq, entry_hash, root)`` at one moment. ``seq``/``entry_hash``
are the ordinary chain tip; ``root`` is the RFC 6962 batch root over every entry
hash the trail has produced so far (``domain.anchoring.batch_root``). The tip
alone is already tamper-evident against edits BEHIND it via ``prev_hash``, but the
root is what lets a THIRD PARTY (a file sidecar, a signed release, another
host) witness the whole trail without holding a copy of it, closing the
whole-trail-rewrite gap a hash chain cannot resist on its own (DESIGN.md's
anchoring rationale).

The frame carries no timestamp: it must be exactly reproducible from the
trail's own entry hashes alone, and the "when" comes from whatever anchors it
(a block time, an RFC 3161 token, a commit), and baking a clock reading in here
would make the frame depend on something the trail itself can't reproduce.

A checkpoint may also carry a forward-secure aggregate binding, which selects
the aggregate-bound frame shape. The reason the binding belongs in the FRAME
and not merely alongside it in the sidecar record: a signing or timestamping
sink attests ``sha256(checkpoint_frame(cp))`` and nothing else, so a binding
that lived only in the surrounding JSON would be witnessed by no one, which
is precisely the class of sink the binding exists to reach.
"""

from __future__ import annotations

import struct
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

from waxseal.domain.anchoring import batch_root
from waxseal.domain.hashing import lp

# The two prefixes are parallel frame SHAPES picked by content — bare, and
# aggregate-bound — not an old-then-new version pair. The `-v1`/`-v2` inside
# the bytes reads like one, and the repository owner himself misread the old
# `_V2` name that way; a version reading invites "migrate the old one away",
# which is the migration-060 reflex this library exists to block. Neither
# shape is superseded and neither will be.
#
# The BYTES are frozen: they are already inside externally issued RFC 3161
# receipts, so moving them would orphan real evidence. A separate prefix AND
# a different field count make cross-shape confusion unrepresentable under
# PAE framing rather than merely unlikely — no aggregate-bound frame can be
# parsed as a bare frame over different content.
CHECKPOINT_FRAME_PREFIX_BARE: Final = b"waxseal-checkpoint-v1\n"
CHECKPOINT_FRAME_PREFIX_AGG_BOUND: Final = b"waxseal-checkpoint-v2\n"

# Pre-0.1.5 names, kept because they may be referenced outside this repo
# (SPEC.md section 9 names the first one in prose). Aliases of the very same
# objects, never re-declared literals, so they cannot drift apart.
CHECKPOINT_FRAME_PREFIX: Final = CHECKPOINT_FRAME_PREFIX_BARE
CHECKPOINT_FRAME_PREFIX_V2: Final = CHECKPOINT_FRAME_PREFIX_AGG_BOUND


@dataclass(frozen=True, slots=True)
class SinkReceipt:
    """A receipt plus the request material the record must keep beside it.

    An RFC 3161 nonce is checked against the response at anchor time, and
    without storing it a later verify has nothing to compare: a token swapped
    in from a DIFFERENT request over the same imprint passed re-verify (the
    gap SPEC.md section 17 used to state). An external sink that needs a
    request value re-checked later returns one of these instead of a bare
    string; ``RecordingAnchorSink`` files the extra field, and every other
    caller (AuditLog discards the return) is unaffected.

    Lives in domain because it is the ``AnchorSink`` Protocol's return
    envelope and ports import domain at most (the layer DAG); in adapters it
    left the Protocol annotating a return type its own implementations no
    longer matched.
    """

    receipt: str
    nonce: int | None = None


@dataclass(frozen=True, slots=True)
class Checkpoint:
    """A trail state an external witness can attest.

    ``agg_commit``/``agg_epoch`` are the optional forward-secure aggregate
    binding: a commitment to the FssAgg accumulator after ``agg_epoch`` rows.
    Both present or both absent, enforced here so a half binding cannot be
    constructed at all: the guard used to live in ``checkpoint_frame``, but
    the anchor sinks serialize a checkpoint straight to JSON without framing
    it, so half a binding reached the wire as ``"agg_epoch": null``, a claim
    committing to nothing, which is the shape of thing this library exists
    not to publish. The commitment, never the accumulator itself: publishing
    intermediate accumulator values is exactly what the aggregate scheme
    forbids, because a truncating attacker who copies one can restore it over
    a shortened trail.

    A checkpoint with neither field is byte-identical to what this library has
    always produced, so anchors taken before the binding existed keep
    verifying.
    """

    seq: int
    entry_hash: str
    root: str
    agg_commit: str | None = None
    agg_epoch: int | None = None

    def __post_init__(self) -> None:
        if (self.agg_commit is None) != (self.agg_epoch is None):
            raise ValueError(
                "an aggregate binding needs both agg_commit and agg_epoch, or neither; "
                f"got agg_commit={self.agg_commit!r}, agg_epoch={self.agg_epoch!r}"
            )


def checkpoint_frame(checkpoint: Checkpoint) -> bytes:
    """Canonical bytes for a checkpoint: PAE-style prefix + field count + fields.

    The shape follows the CONTENT: the bare frame when there is no aggregate
    binding, the aggregate-bound frame when there is. There is no version
    parameter to pass, and neither shape supersedes the other. Half a binding
    cannot arrive here, since ``Checkpoint`` refuses to hold one, so an epoch
    committing to nothing can never become a frame a witness attests and
    nobody can check.
    """
    if checkpoint.agg_commit is None:
        return (
            CHECKPOINT_FRAME_PREFIX_BARE
            + struct.pack(">Q", 3)
            + lp(str(checkpoint.seq))
            + lp(checkpoint.entry_hash)
            + lp(checkpoint.root)
        )
    return (
        CHECKPOINT_FRAME_PREFIX_AGG_BOUND
        + struct.pack(">Q", 5)
        + lp(str(checkpoint.seq))
        + lp(checkpoint.entry_hash)
        + lp(checkpoint.root)
        + lp(str(checkpoint.agg_epoch))
        + lp(str(checkpoint.agg_commit))
    )


def checkpoint_for(
    entry_hashes: Sequence[str],
    *,
    agg_commit: str | None = None,
    agg_epoch: int | None = None,
    root: str | None = None,
) -> Checkpoint:
    """Checkpoint over ``entry_hashes`` (write order, index 0 is seq 0).

    ``root`` is the RFC 6962 batch root already computed for this exact
    sequence (the incremental tree AuditLog keeps across appends). Omitted,
    it is recomputed with ``batch_root``. Passing a root of a different
    prefix would be a checkpoint that ``verify_checkpoint`` later rejects —
    this function does not re-check, because that would pay the O(n) the
    caller already avoided.

    Raises ValueError on an empty trail: there is no tip to pin, and silently
    returning some placeholder would be a checkpoint over nothing that a
    caller could still anchor by mistake.
    """
    if not entry_hashes:
        raise ValueError("cannot checkpoint an empty trail")
    return Checkpoint(
        seq=len(entry_hashes) - 1,
        entry_hash=entry_hashes[-1],
        root=batch_root(entry_hashes) if root is None else root,
        agg_commit=agg_commit,
        agg_epoch=agg_epoch,
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
    try:
        root = batch_root(entry_hashes[: checkpoint.seq + 1])
    except ValueError:
        # waxseal-lmv (never-raise fuzzing sweep): `batch_root` decodes every
        # hash as hex with no guard, and the local trail is attacker-writable
        # by the same threat model as the sidecar (CLAUDE.md) -- a corrupted
        # `entry_hash` field earlier in the prefix (not necessarily at the
        # checkpointed tip, which already passed the check above) let
        # ValueError escape uncaught, breaking this function's own
        # documented "fails closed and never raises" promise. The root
        # cannot be recomputed, so it cannot be confirmed to match: the
        # existing anchor_root_mismatch reason already covers "does not
        # check out" (same as domain.anchoring's bad-hex-returns-False
        # convention), not a new incident class (CLAUDE.md rules 4/5/6).
        return "anchor_root_mismatch"
    if root != checkpoint.root:
        return "anchor_root_mismatch"
    return None
