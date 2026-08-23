"""Golden vectors for the checkpoint frames (v1/v2) and the aggregate commitment.

SPEC.md section 15 defines two hashed byte frames this suite pins:

- ``waxseal-checkpoint-v2\\n`` — the checkpoint frame carrying the forward-secure
  aggregate binding (and, when the binding is absent, the byte-identical
  ``waxseal-checkpoint-v1\\n`` frame from section 6 that every existing anchor
  already attests);
- ``waxseal-aggcommit-v1\\n`` — the publishable commitment
  ``sha256(prefix || u64be(2) || lp(str(epoch)) || lp(agg))``.

The vectors in tests/vectors/checkpoint.json are produced by
tools/gen_checkpoint_vectors.py, which implements the SPEC prose directly with
hashlib/struct only and imports nothing from waxseal — so a bug shared between
``domain.checkpoint``/``domain.sealing`` and a test that merely round-trips
them cannot hide here. If waxseal and the vectors disagree, that IS the
finding: stop and report, never regenerate.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from waxseal.domain.checkpoint import (
    CHECKPOINT_FRAME_PREFIX,
    CHECKPOINT_FRAME_PREFIX_V2,
    Checkpoint,
    checkpoint_frame,
)
from waxseal.domain.sealing import aggregate_commit

VECTORS_PATH = Path(__file__).parent.parent / "vectors" / "checkpoint.json"

# Write-once guard, same discipline as tests/vectors/vectors.json and
# rfc3161.json (CLAUDE.md rule 3): an anchor witness attested
# sha256(checkpoint_frame(cp)) at a moment in time, and it is only evidence as
# long as the frame we would build today is still byte-for-byte the frame it
# signed. A mismatch here means STOP — the framing code (or an edit to the
# vector file) is the bug, never the frozen hash.
FROZEN_VECTORS_SHA256 = "d2bb512e32efaa6df51916091eca4181ec084775e043fd270147f518832d11eb"


def vectors() -> dict:
    return json.loads(VECTORS_PATH.read_text(encoding="utf-8"))


class TestVectorsAreFrozen:
    def test_the_vector_file_has_not_changed(self) -> None:
        actual = hashlib.sha256(VECTORS_PATH.read_bytes()).hexdigest()
        assert actual == FROZEN_VECTORS_SHA256, (
            "tests/vectors/checkpoint.json changed. Frozen vectors are "
            "write-once (CLAUDE.md rule 3): add a new vector file, never edit "
            "this one. If this failed after a framing change, the framing "
            "code is the bug."
        )


class TestCheckpointFrames:
    @pytest.mark.parametrize(
        "vector", vectors()["checkpoint_frames"], ids=lambda v: v["name"]
    )
    def test_matches_the_independently_derived_bytes(self, vector: dict) -> None:
        cp = Checkpoint(
            seq=vector["seq"],
            entry_hash=vector["entry_hash"],
            root=vector["root"],
            agg_commit=vector["agg_commit"],
            agg_epoch=vector["agg_epoch"],
        )
        frame = checkpoint_frame(cp)
        assert frame.hex() == vector["frame_hex"]
        assert hashlib.sha256(frame).hexdigest() == vector["frame_sha256"]

    @pytest.mark.parametrize(
        "vector", vectors()["checkpoint_frames"], ids=lambda v: v["name"]
    )
    def test_the_prefix_matches_the_binding(self, vector: dict) -> None:
        # SPEC section 15: no binding -> byte-identical v1 output (every anchor
        # taken before the binding existed keeps verifying); a binding -> the
        # v2 prefix AND a different field count, so v1/v2 confusion is
        # unrepresentable.
        frame = bytes.fromhex(vector["frame_hex"])
        if vector["agg_commit"] is None:
            assert frame.startswith(CHECKPOINT_FRAME_PREFIX)
        else:
            assert frame.startswith(CHECKPOINT_FRAME_PREFIX_V2)


class TestAggregateCommits:
    @pytest.mark.parametrize(
        "vector", vectors()["aggregate_commits"], ids=lambda v: v["name"]
    )
    def test_matches_the_independently_derived_commitment(self, vector: dict) -> None:
        assert aggregate_commit(vector["epoch"], vector["agg"]) == vector["commit"]


class TestBindingEndToEnd:
    def test_a_commit_embedded_in_a_v2_frame_is_the_commit_waxseal_computes(
        self,
    ) -> None:
        # The vector generator derived this frame's agg_commit from its own
        # aggregate_commit implementation over (source_epoch, source_agg).
        # waxseal must arrive at the same commitment AND the same frame, or
        # the binding a witness attests is not the binding verify checks.
        vector = next(
            v
            for v in vectors()["checkpoint_frames"]
            if "source_agg" in v
        )
        commit = aggregate_commit(vector["source_epoch"], vector["source_agg"])
        assert commit == vector["agg_commit"]
        cp = Checkpoint(
            seq=vector["seq"],
            entry_hash=vector["entry_hash"],
            root=vector["root"],
            agg_commit=commit,
            agg_epoch=vector["agg_epoch"],
        )
        assert checkpoint_frame(cp).hex() == vector["frame_hex"]
