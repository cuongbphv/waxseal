"""Batch roots and membership proofs against pinned RFC 6962 vectors.

Known-answer hashes are pinned from the reference test data published in
transparency-dev/merkle (testonly/constants.go) — an implementation
independent of waxseal, satisfying the cross-check rule for frozen hashes.
Once present these vectors are write-once (CLAUDE.md rule 3).
"""

from __future__ import annotations

import hashlib

import pytest

from waxseal.domain.anchoring import (
    batch_root,
    membership_proof,
    verify_membership,
)

# Reference leaf inputs, as hex.
RFC_LEAVES = [
    "",
    "00",
    "10",
    "2021",
    "3031",
    "40414243",
    "5051525354555657",
    "606162636465666768696a6b6c6d6e6f",
]

# Reference roots, indexed by batch size 0..8.
RFC_ROOTS = [
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
    "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
    "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
    "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
    "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
    "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
    "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
]

# Reference internal node hashes of the 8-leaf tree, used to pin two
# membership proofs byte-for-byte (level_index naming).
NODE_0_1 = "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7"
NODE_1_1 = "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e"
NODE_2_1 = "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4"
NODE_0_6 = "b08693ec2e721597130641e8211e7eedccb4c26413963eee6c1e2ed16ffb1a5f"
NODE_1_2 = "0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a"
NODE_2_0 = "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7"


def entry_hashes(n: int) -> list[str]:
    """n distinct 32-byte values shaped like Entry.entry_hash."""
    return [hashlib.sha256(f"entry-{i}".encode()).hexdigest() for i in range(n)]


class TestKnownAnswerVectors:
    @pytest.mark.parametrize("size", range(len(RFC_ROOTS)))
    def test_root_matches_reference(self, size: int) -> None:
        assert batch_root(RFC_LEAVES[:size]) == RFC_ROOTS[size]

    def test_proof_for_first_leaf_of_eight(self) -> None:
        assert membership_proof(RFC_LEAVES, 0) == (NODE_0_1, NODE_1_1, NODE_2_1)

    def test_proof_for_last_leaf_of_eight(self) -> None:
        assert membership_proof(RFC_LEAVES, 7) == (NODE_0_6, NODE_1_2, NODE_2_0)

    def test_single_leaf_proof_is_empty(self) -> None:
        assert membership_proof(RFC_LEAVES[:1], 0) == ()
        assert verify_membership(RFC_LEAVES[0], 0, 1, (), RFC_ROOTS[1])


class TestRoundTrip:
    @pytest.mark.parametrize("size", range(1, 66))
    def test_every_index_verifies(self, size: int) -> None:
        hashes = entry_hashes(size)
        root = batch_root(hashes)
        for index in range(size):
            proof = membership_proof(hashes, index)
            assert verify_membership(hashes[index], index, size, proof, root), (
                f"size={size} index={index}"
            )

    def test_reference_vectors_round_trip(self) -> None:
        for index in range(len(RFC_LEAVES)):
            proof = membership_proof(RFC_LEAVES, index)
            assert verify_membership(
                RFC_LEAVES[index], index, len(RFC_LEAVES), proof, RFC_ROOTS[8]
            )


class TestTamperRejection:
    def test_modified_entry_fails(self) -> None:
        hashes = entry_hashes(8)
        root = batch_root(hashes)
        proof = membership_proof(hashes, 3)
        other = hashlib.sha256(b"tampered").hexdigest()
        assert not verify_membership(other, 3, 8, proof, root)

    def test_wrong_index_fails(self) -> None:
        hashes = entry_hashes(8)
        root = batch_root(hashes)
        proof = membership_proof(hashes, 3)
        assert not verify_membership(hashes[3], 4, 8, proof, root)

    def test_wrong_root_fails(self) -> None:
        hashes = entry_hashes(8)
        proof = membership_proof(hashes, 3)
        assert not verify_membership(hashes[3], 3, 8, proof, batch_root(entry_hashes(9)))

    def test_truncated_proof_fails(self) -> None:
        hashes = entry_hashes(8)
        root = batch_root(hashes)
        proof = membership_proof(hashes, 3)
        assert not verify_membership(hashes[3], 3, 8, proof[:-1], root)

    def test_extended_proof_fails(self) -> None:
        hashes = entry_hashes(8)
        root = batch_root(hashes)
        proof = membership_proof(hashes, 3)
        padded = (*proof, hashlib.sha256(b"extra").hexdigest())
        assert not verify_membership(hashes[3], 3, 8, padded, root)

    def test_inner_node_cannot_pose_as_leaf(self) -> None:
        # The 0x00/0x01 prefixes exist so a "leaf" equal to two child hashes
        # concatenated cannot reproduce their parent (CVE-2012-2459 class).
        hashes = entry_hashes(2)
        root = batch_root(hashes)
        forged = (
            hashlib.sha256(b"\x00" + bytes.fromhex(hashes[0])).hexdigest()
            + hashlib.sha256(b"\x00" + bytes.fromhex(hashes[1])).hexdigest()
        )
        assert batch_root([forged]) != root


class TestInvalidInputs:
    def test_verify_fails_closed_out_of_range(self) -> None:
        hashes = entry_hashes(4)
        root = batch_root(hashes)
        proof = membership_proof(hashes, 0)
        assert not verify_membership(hashes[0], 4, 4, proof, root)
        assert not verify_membership(hashes[0], -1, 4, proof, root)
        assert not verify_membership(hashes[0], 0, 0, (), root)

    def test_verify_fails_closed_on_malformed_hex(self) -> None:
        hashes = entry_hashes(4)
        root = batch_root(hashes)
        proof = membership_proof(hashes, 0)
        assert not verify_membership("zz-not-hex", 0, 4, proof, root)
        assert not verify_membership(hashes[0], 0, 4, ("zz-not-hex",) * 2, root)

    def test_proof_index_out_of_range_raises(self) -> None:
        hashes = entry_hashes(4)
        with pytest.raises(IndexError):
            membership_proof(hashes, 4)
        with pytest.raises(IndexError):
            membership_proof(hashes, -1)
        with pytest.raises(IndexError):
            membership_proof([], 0)

    def test_root_rejects_malformed_hex(self) -> None:
        with pytest.raises(ValueError):
            batch_root(["zz-not-hex"])
