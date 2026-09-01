"""Golden vector tests (SPEC.md section 8, CLAUDE.md rule 3).

vectors.json was produced by tools/gen_vectors.py — an independent
implementation of the SPEC prose that does not import waxseal. If the
library disagrees with a vector, the LIBRARY (or the SPEC) drifted: STOP.
Editing a frozen vector to make tests pass is the one forbidden move.
"""

import hashlib
import json
from pathlib import Path
from typing import Any

from waxseal.domain.fingerprint import fingerprint
from waxseal.domain.hashing import ENCODING, NULL, compute_entry_hash, lp
from waxseal.domain.header import EntryHeader

VECTORS_PATH = Path(__file__).parent / "vectors" / "vectors.json"

# Write-once guard: the sha256 of vectors.json at freeze time. A mismatch
# means someone edited frozen vectors — that is the alarm firing, not a value
# to update casually. New vectors belong in a NEW file.
#
# Re-frozen for 0.1.4, which collapsed waxseal to a single canonical encoding
# (lp64) and retired lp64v1 before any trail written under it existed outside
# development. That re-freeze was an explicit owner decision, taken with the
# knowledge that it is exactly the move rule 3 exists to prevent by default;
# it is not a precedent. From here the rule reads as written.
FROZEN_VECTORS_SHA256 = "45506728e1aae7e3c30dbd419078305c522985a32b478c130c3a6ca5d30429c6"


def load() -> dict[str, Any]:
    result: dict[str, Any] = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
    return result


class TestVectorFileIsFrozen:
    def test_vectors_file_hash_matches_freeze(self) -> None:
        actual = hashlib.sha256(VECTORS_PATH.read_bytes()).hexdigest()
        assert actual == FROZEN_VECTORS_SHA256, (
            "tests/vectors/vectors.json changed. Frozen vectors are write-once "
            "(CLAUDE.md rule 3): revert the edit; add new vectors in a new file."
        )


class TestLibraryReproducesVectors:
    def test_descriptor_fingerprint(self) -> None:
        assert fingerprint() == load()["descriptor_fingerprint"]

    def test_encoding_name(self) -> None:
        assert load()["encoding"] == ENCODING

    def test_lp_examples(self) -> None:
        for example in load()["lp_examples"]:
            assert lp(example["input"]).hex() == example["hex"]

    def test_absent_field(self) -> None:
        assert lp(NULL).hex() == load()["null_lp_hex"]

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
