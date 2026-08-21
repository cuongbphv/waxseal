"""Golden vector tests (SPEC.md section 8, CLAUDE.md rule 3).

vectors.json was produced by tools/gen_vectors.py — an independent
implementation of the SPEC prose that does not import waxseal. If the
library disagrees with a vector, the LIBRARY (or the SPEC) drifted: STOP.
Editing a frozen vector to make tests pass is the one forbidden move.
"""

import hashlib
import json
from pathlib import Path

from waxseal.domain.fingerprint import fingerprint_v1
from waxseal.domain.hashing import NULL, compute_entry_hash, lp
from waxseal.domain.header import EntryHeader

VECTORS_PATH = Path(__file__).parent / "vectors" / "vectors.json"

# Write-once guard: the sha256 of vectors.json at freeze time (2026-08-21).
# A mismatch means someone edited frozen vectors — that is the alarm firing,
# not a value to update casually. New vectors belong in a NEW file.
FROZEN_VECTORS_SHA256 = "938c90a1648f7d269bcbcd09c30c150157f4212e9af87fc8c339529fff3f7c40"


def load() -> dict:
    return json.loads(VECTORS_PATH.read_text(encoding="utf-8"))


class TestVectorFileIsFrozen:
    def test_vectors_file_hash_matches_freeze(self) -> None:
        actual = hashlib.sha256(VECTORS_PATH.read_bytes()).hexdigest()
        assert actual == FROZEN_VECTORS_SHA256, (
            "tests/vectors/vectors.json changed. Frozen vectors are write-once "
            "(CLAUDE.md rule 3): revert the edit; add new vectors in a new file."
        )


class TestLibraryReproducesVectors:
    def test_descriptor_fingerprint(self) -> None:
        assert fingerprint_v1() == load()["descriptor_fingerprint"]

    def test_lp_examples(self) -> None:
        for example in load()["lp_examples"]:
            assert lp(example["input"]).hex() == example["hex"]

    def test_null_sentinel(self) -> None:
        assert lp(NULL).hex() == load()["null_sentinel_lp_hex"]

    def test_every_entry_hash(self) -> None:
        for vector in load()["entries"]:
            header = EntryHeader(**vector["header"])
            assert compute_entry_hash(header) == vector["entry_hash"], (
                f"entry_hash drift at seq={header.seq}"
            )

    def test_payload_hashes_match_payloads(self) -> None:
        for vector in load()["entries"]:
            payload = vector["payload_utf8"].encode("utf-8")
            assert hashlib.sha256(payload).hexdigest() == vector["header"]["payload_hash"]
