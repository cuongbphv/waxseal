"""The Python side and the Solidity side must be joined, not merely parallel.

The incident (waxseal-fg4.37): `domain/bond.py` and `CheckpointCodec.sol` each
implemented the checkpoint signing digest and they signed DIFFERENT bytes --
different prefix, different body, different trail-id type -- while every gate
stayed green. Nothing caught it because `tools/gen_contract_vectors.py`
RESTATED the signing prefix and the digest instead of importing them, so
`--check` compared the generator against the Solidity it was written beside: a
closed loop with the Python implementation outside it.

These tests open the loop and keep it open. The digest vectors are asserted
against the SHIPPED `domain.bond.checkpoint_signing_digest`, so a change there
moves the committed vector and `forge test` goes red on a stale Solidity
constant; and the generator is parsed to prove it still imports rather than
restates, because "restated the constant" is the exact shape of the original
drift and an absence is not a guarantee it will not come back.

Parsed with `ast`, not grepped: the modules here name the superseded bytes in
their prose on purpose (CLAUDE.md rule 9 -- comments carry the incident), so a
text scan would hit the warning rather than the mistake. The precedent is
`tests/domain/test_abi.py::TestNoKeccakSmuggledIn`, which went to the AST for
the same reason.
"""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path

import pytest

from waxseal.domain.bond import checkpoint_signing_digest, trail_id_for
from waxseal.domain.checkpoint import Checkpoint, checkpoint_frame

_REPO = Path(__file__).resolve().parents[2]
_GENERATOR = _REPO / "tools" / "gen_contract_vectors.py"
_VECTORS = _REPO / "contracts" / "vectors"


def _generator_tree() -> ast.Module:
    return ast.parse(_GENERATOR.read_text(encoding="utf-8"))


def _checkpoint_vectors() -> list[dict[str, object]]:
    vectors: list[dict[str, object]] = []
    for path in sorted(_VECTORS.glob("checkpoint-*.json")):
        vectors.extend(json.loads(path.read_text(encoding="utf-8")))
    return vectors


class TestGeneratorImportsTheDigest:
    """The structural half of the fix. Without it, (a) drifts again."""

    def test_the_digest_is_imported_from_domain_bond(self) -> None:
        imported = {
            alias.asname or alias.name
            for node in ast.walk(_generator_tree())
            if isinstance(node, ast.ImportFrom) and node.module == "waxseal.domain.bond"
            for alias in node.names
        }
        assert {"checkpoint_signing_digest", "trail_id_for"} <= imported

    @pytest.mark.parametrize("name", ["SIGNING_PREFIX", "LEDGER_CHECKPOINT_SIG_PREFIX"])
    def test_the_generator_defines_no_signing_prefix_of_its_own(self, name: str) -> None:
        # The literal that drifted. A generator holding its own copy compares
        # Solidity against itself and never touches domain/bond.py.
        assigned = {
            target.id
            for node in ast.walk(_generator_tree())
            if isinstance(node, ast.Assign)
            for target in node.targets
            if isinstance(target, ast.Name)
        }
        assert name not in assigned

    def test_the_generator_defines_no_digest_function_of_its_own(self) -> None:
        defined = {
            node.name for node in ast.walk(_generator_tree()) if isinstance(node, ast.FunctionDef)
        }
        assert "signing_digest" not in defined
        assert "trail_id_for" not in defined


class TestVectorsComeFromThePythonFunction:
    """The joined vector: one artifact both languages are checked against.

    `forge test` asserts `CheckpointCodec.signingDigest` reproduces
    `signingDigest`; these assert `domain.bond.checkpoint_signing_digest`
    reproduces the same field. Neither side can move alone.
    """

    def test_there_are_checkpoint_vectors_to_check(self) -> None:
        assert _checkpoint_vectors()

    def test_every_signing_digest_is_the_shipped_python_digest(self) -> None:
        for vector in _checkpoint_vectors():
            checkpoint = Checkpoint(
                seq=int(str(vector["seq"])),
                entry_hash=str(vector["entryHash"])[2:],
                root=str(vector["root"])[2:],
            )
            digest = checkpoint_signing_digest(str(vector["chainId"]), checkpoint)
            assert "0x" + digest.hex() == vector["signingDigest"], vector["name"]

    def test_every_trail_id_is_the_pinned_mapping_of_its_chain_id(self) -> None:
        # The mapping is pinned, not implicit: the contracts key by bytes32 and
        # the trail has a human-readable name, so the vector carries BOTH and
        # the reduction between them is under test.
        for vector in _checkpoint_vectors():
            expected = trail_id_for(str(vector["chainId"]))
            assert "0x" + expected.hex() == vector["trailId"], vector["name"]

    def test_every_frame_is_the_shipped_checkpoint_frame(self) -> None:
        # `checkpoint_frame` is frozen -- these bytes are inside externally
        # issued RFC 3161 receipts -- so this vector must never move. It is
        # here so that a digest re-freeze cannot quietly take the frame with it.
        for vector in _checkpoint_vectors():
            checkpoint = Checkpoint(
                seq=int(str(vector["seq"])),
                entry_hash=str(vector["entryHash"])[2:],
                root=str(vector["root"])[2:],
            )
            frame = checkpoint_frame(checkpoint)
            assert "0x" + frame.hex() == vector["frame"], vector["name"]
            assert "0x" + hashlib.sha256(frame).hexdigest() == vector["frameHash"], vector["name"]
