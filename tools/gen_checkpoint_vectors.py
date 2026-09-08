"""Independent cross-check for the checkpoint frame and aggregate-commitment vectors.

Like tools/gen_rfc3161_vectors.py, this deliberately does NOT import waxseal.
It builds the frames straight from SPEC.md's prose — section 6 for
``waxseal-checkpoint-v1\\n``, section 15 for ``waxseal-checkpoint-v2\\n`` and
``waxseal-aggcommit-v1\\n`` — using hashlib and struct only, so a bug shared
between ``domain.checkpoint``/``domain.sealing`` and their own round-trip tests
cannot hide here.

What is independently derived: the lp64v1 length-prefix encoding (SPEC section
2: 8-byte big-endian length + UTF-8 bytes), the PAE-style frames (prefix +
u64be field count + lp fields), and the SHA-256 commitment. The INPUT values
(seq, entry_hash, root, agg, epoch) are fixed test constants — 64-hex strings
derived from labelled SHA-256 preimages so the file is reproducible from this
script alone, with no dependence on any waxseal-produced trail.

Run modes:

    uv run python tools/gen_checkpoint_vectors.py          # verify vs the JSON
    uv run python tools/gen_checkpoint_vectors.py --write  # first generation only

--write refuses to overwrite an existing file: tests/vectors/ is write-once
(CLAUDE.md rule 3). Verification exits nonzero and prints the first mismatch.
"""

from __future__ import annotations

import hashlib
import json
import struct
import sys
from pathlib import Path

VECTORS = Path(__file__).parent.parent / "tests" / "vectors" / "checkpoint.json"

CHECKPOINT_V1_PREFIX = b"waxseal-checkpoint-v1\n"
CHECKPOINT_V2_PREFIX = b"waxseal-checkpoint-v2\n"
AGG_COMMIT_PREFIX = b"waxseal-aggcommit-v1\n"

# SPEC section 11: the aggregate accumulator starts at 64 zeros.
AGG_GENESIS = "0" * 64


def lp(value: str | None) -> bytes:
    """SPEC section 2 (lp64): 8-byte big-endian length prefix over a tagged
    payload -- 0x00 for absent, 0x01 before a string's UTF-8 bytes."""
    enc = b"\x00" if value is None else b"\x01" + value.encode("utf-8")
    return struct.pack(">Q", len(enc)) + enc


def checkpoint_frame(
    seq: int,
    entry_hash: str,
    root: str,
    agg_epoch: int | None,
    agg_commit: str | None,
) -> bytes:
    """SPEC sections 6 and 15: v1 when there is no binding, v2 when there is."""
    if agg_commit is None:
        return (
            CHECKPOINT_V1_PREFIX + struct.pack(">Q", 3) + lp(str(seq)) + lp(entry_hash) + lp(root)
        )
    return (
        CHECKPOINT_V2_PREFIX
        + struct.pack(">Q", 5)
        + lp(str(seq))
        + lp(entry_hash)
        + lp(root)
        + lp(str(agg_epoch))
        + lp(str(agg_commit))
    )


def aggregate_commit(epoch: int, agg: str) -> str:
    """SPEC section 15: SHA-256( PREFIX || u64be(2) || lp(str(epoch)) || lp(agg) )."""
    frame = AGG_COMMIT_PREFIX + struct.pack(">Q", 2) + lp(str(epoch)) + lp(agg)
    return hashlib.sha256(frame).hexdigest()


def fixed_hex(label: str) -> str:
    """A reproducible 64-hex test constant: sha256 of a labelled preimage."""
    return hashlib.sha256(f"waxseal checkpoint vector: {label}".encode()).hexdigest()


def build_vectors() -> dict:
    agg_epoch1 = fixed_hex("agg after 1 fold")
    agg_large = fixed_hex("agg after many folds")

    aggregate_commits = [
        # epoch 0 over the genesis accumulator: the smallest publishable claim.
        {
            "agg": AGG_GENESIS,
            "commit": aggregate_commit(0, AGG_GENESIS),
            "epoch": 0,
            "name": "epoch0-genesis-accumulator",
        },
        {
            "agg": agg_epoch1,
            "commit": aggregate_commit(1, agg_epoch1),
            "epoch": 1,
            "name": "epoch1",
        },
        # str(epoch) encoding has no u64 ceiling; pin a large decimal rendering.
        {
            "agg": agg_large,
            "commit": aggregate_commit(9223372036854775807, agg_large),
            "epoch": 9223372036854775807,
            "name": "epoch-large-int64",
        },
    ]

    def frame_vector(
        name: str,
        seq: int,
        entry_hash: str,
        root: str,
        agg_epoch: int | None,
        agg_commit: str | None,
        **extra: object,
    ) -> dict:
        frame = checkpoint_frame(seq, entry_hash, root, agg_epoch, agg_commit)
        return {
            "agg_commit": agg_commit,
            "agg_epoch": agg_epoch,
            "entry_hash": entry_hash,
            # frame_sha256 is what a signing/timestamping sink attests.
            "frame_hex": frame.hex(),
            "frame_sha256": hashlib.sha256(frame).hexdigest(),
            "name": name,
            "root": root,
            "seq": seq,
            **extra,
        }

    # The end-to-end binding case: the agg_commit embedded in the v2 frame is
    # this script's own aggregate_commit over (source_epoch, source_agg), so
    # the consuming test can prove waxseal derives the SAME commitment AND the
    # same frame around it.
    bound_epoch = 2
    bound_agg = fixed_hex("agg after 2 folds")
    bound_commit = aggregate_commit(bound_epoch, bound_agg)

    checkpoint_frames = [
        # No binding -> byte-identical v1 output (SPEC section 15's
        # compatibility guarantee: anchors taken before the binding existed
        # keep verifying).
        frame_vector(
            "v1-compat-no-binding-seq0",
            0,
            fixed_hex("entry hash at seq 0"),
            fixed_hex("root over seqs 0..0"),
            None,
            None,
        ),
        frame_vector(
            "v1-compat-no-binding-large-seq",
            9223372036854775807,
            fixed_hex("entry hash at large seq"),
            fixed_hex("root at large seq"),
            None,
            None,
        ),
        frame_vector(
            "v2-binding-seq0-epoch1",
            0,
            fixed_hex("entry hash at seq 0"),
            fixed_hex("root over seqs 0..0"),
            1,
            fixed_hex("an opaque anchored commitment"),
        ),
        frame_vector(
            "v2-binding-large-seq-and-epoch",
            9223372036854775807,
            fixed_hex("entry hash at large seq"),
            fixed_hex("root at large seq"),
            9223372036854775807,
            fixed_hex("an opaque anchored commitment at large epoch"),
        ),
        frame_vector(
            "v2-binding-commit-derived-from-aggcommit-frame",
            1,
            fixed_hex("entry hash at seq 1"),
            fixed_hex("root over seqs 0..1"),
            bound_epoch,
            bound_commit,
            source_agg=bound_agg,
            source_epoch=bound_epoch,
        ),
    ]

    return {
        "_comment": (
            "Golden vectors for SPEC.md sections 6 and 15: waxseal-checkpoint-v1/v2 "
            "frames and the waxseal-aggcommit-v1 commitment. Generated by "
            "tools/gen_checkpoint_vectors.py from the SPEC prose alone (no waxseal "
            "imports). Write-once: never edit or delete entries (CLAUDE.md rule 3)."
        ),
        "aggregate_commits": aggregate_commits,
        "checkpoint_frames": checkpoint_frames,
    }


def check_vectors() -> list[str]:
    doc = json.loads(VECTORS.read_text(encoding="utf-8"))
    built = build_vectors()
    failures = []
    if doc["aggregate_commits"] != built["aggregate_commits"]:
        failures.append("aggregate_commits no longer reproduce from the SPEC prose")
    for on_disk, rebuilt in zip(doc["checkpoint_frames"], built["checkpoint_frames"], strict=True):
        if on_disk != rebuilt:
            failures.append(
                f"{on_disk['name']}: expected {on_disk['frame_hex']}, built {rebuilt['frame_hex']}"
            )
    return failures


def write_vectors() -> int:
    if VECTORS.exists():
        # tests/vectors/ is write-once. Regenerating over a frozen file is the
        # exact mistake the frozen-hash test exists to catch; refuse it here too.
        print(f"refusing to overwrite {VECTORS} (frozen vectors are write-once)")
        return 1
    VECTORS.write_text(
        json.dumps(build_vectors(), indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"wrote {VECTORS}")
    return 0


def main() -> int:
    if "--write" in sys.argv[1:]:
        return write_vectors()
    failures = check_vectors()
    for line in failures:
        print(line)
    if failures:
        return 1
    print("all checkpoint/aggcommit vectors reproduce from the SPEC text")
    return 0


if __name__ == "__main__":
    sys.exit(main())
