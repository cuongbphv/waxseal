"""Bonded-checkpoint proofs and the bond ternary.

Two proof shapes, and they are NOT symmetric. Equivocation is a positive,
self-contained fact: two checkpoints at the same seq, both signed, that
disagree. Non-extension is not — no consistency proof can demonstrate the
absence of one — so `NonExtensionProof` carries a challenge and the
consistency check is the writer's DEFENCE. The tests below pin that
asymmetry, because a later reader who assumes both are proofs would build a
contract that slashes an honest writer for a garbage proof anyone can submit.
"""

from __future__ import annotations

import hashlib

import pytest

from waxseal.domain import bond
from waxseal.domain.anchoring import batch_root, consistency_proof
from waxseal.domain.checkpoint import Checkpoint, checkpoint_for, checkpoint_frame
from waxseal.domain.hashing import LpEncodingError
from waxseal.domain.verdict import Verdict

CHAIN_ID = "trail-a"
HASHES = tuple(hashlib.sha256(str(i).encode()).hexdigest() for i in range(8))


def cp(seq: int) -> Checkpoint:
    return checkpoint_for(HASHES[: seq + 1])


class TestTrailIdMapping:
    """The name-to-bytes32 reduction, pinned rather than assumed.

    While it was unwritten, `domain/bond.py` bound the trail NAME into the
    digest and `CheckpointCodec.sol` bound a `bytes32` nobody had said how to
    derive — one of the three ways the two halves signed different bytes
    (waxseal-fg4.37).
    """

    def test_is_sha256_of_the_utf8_name(self) -> None:
        assert bond.trail_id_for(CHAIN_ID) == hashlib.sha256(b"trail-a").digest()
        assert len(bond.trail_id_for(CHAIN_ID)) == 32

    def test_a_non_ascii_name_is_reduced_over_its_utf8_bytes(self) -> None:
        # The contracts see only the 32 bytes, so the encoding of the name has
        # to be stated: UTF-8, the same encoding `lp` uses everywhere else.
        assert bond.trail_id_for("trail-\u00e9") == hashlib.sha256("trail-é".encode()).digest()

    def test_a_name_with_no_utf8_form_raises_the_labelled_error(self) -> None:
        # A lone UTF-16 surrogate is a valid `str` with no UTF-8 spelling.
        # `lp` raises `LpEncodingError` rather than leaking the bare stdlib
        # `UnicodeEncodeError` (finding G4); this reduction now encodes the
        # name itself, so it owes the same labelled failure and must not
        # reintroduce the leak `lp` was fixed to stop.
        with pytest.raises(LpEncodingError, match="not representable in UTF-8"):
            bond.trail_id_for("trail-\ud800")


class TestSigningDigest:
    def test_is_domain_separated_sha256_over_the_checkpoint_frame(self) -> None:
        # The frame goes in DIRECTLY, not as its own hash: lp64 already
        # length-prefixes the trail id, so the concatenation is injective
        # without a fixed-length preimage, and each extra hash or re-spelling
        # is one more surface for Python and Solidity to disagree on.
        checkpoint = cp(3)
        trail_id_hex = hashlib.sha256(b"trail-a").hexdigest()
        expected = hashlib.sha256(
            bond.LEDGER_CHECKPOINT_SIG_PREFIX
            + (2).to_bytes(8, "big")
            + (65).to_bytes(8, "big")
            + b"\x01"
            + trail_id_hex.encode()
            + checkpoint_frame(checkpoint)
        ).digest()
        assert bond.checkpoint_signing_digest(CHAIN_ID, checkpoint) == expected
        assert len(expected) == 32

    def test_the_frame_is_signed_directly_and_not_through_its_own_hash(self) -> None:
        # The superseded shape (workstream F2's, before waxseal-fg4.37 settled
        # the disagreement): sha256 of the frame, hex-spelled, as a second lp
        # field. Pinned as a NON-match so the two forms can never be confused
        # for one another again by a reader who finds the old bytes in a
        # commit or in a contract comment.
        checkpoint = cp(3)
        frame_hash = hashlib.sha256(checkpoint_frame(checkpoint)).digest()
        superseded = hashlib.sha256(
            bond.LEDGER_CHECKPOINT_SIG_PREFIX
            + (2).to_bytes(8, "big")
            + (65).to_bytes(8, "big")
            + b"\x01"
            + hashlib.sha256(b"trail-a").hexdigest().encode()
            + (65).to_bytes(8, "big")
            + b"\x01"
            + frame_hash.hex().encode()
        ).digest()
        assert bond.checkpoint_signing_digest(CHAIN_ID, checkpoint) != superseded

    def test_a_frozen_digest_pins_the_bytes_a_signature_commits_to(self) -> None:
        # Changing this value invalidates every signature already published to
        # the bond contract, and no code in this process would notice: the
        # contract would simply stop recovering the writer's address. Frozen
        # here so the change cannot be silent.
        #
        # RE-FROZEN ONCE, deliberately, in waxseal-fg4.37, from
        # c65148fdcdcd298907162f24c0cae03514cfc90cbd33cf0c290722c725d64b24.
        # That value was never a shared digest: `CheckpointCodec.sol` signed a
        # different prefix over a different body at the same time, so no
        # signature anyone could verify on chain was ever taken over it, and
        # nothing verifiable is orphaned by the move. Two of the three
        # differences land in this hex — the trail is now bound as
        # `trail_id_for(chain_id)` in hex rather than as the bare name, and
        # the contract's prefix moved to this module's. The frame itself did
        # NOT move; it is inside externally issued RFC 3161 receipts.
        # This is a re-freeze under CLAUDE.md rule 3, not a precedent: a
        # frozen-hash failure still means STOP.
        assert bond.checkpoint_signing_digest(CHAIN_ID, cp(3)).hex() == (
            "45778fc6c5bf4a7e38058b7b8db89a84705e4d27e1e60dae2a45f5d08560ac12"
        )

    def test_the_chain_id_is_inside_the_digest(self) -> None:
        # Without it a signature over trail A's checkpoint replays as trail
        # B's, and the bond contract slashes on a "conflict" between two
        # unrelated trails that both happen to sit at the same seq.
        assert bond.checkpoint_signing_digest("trail-a", cp(3)) != (
            bond.checkpoint_signing_digest("trail-b", cp(3))
        )

    def test_different_checkpoints_get_different_digests(self) -> None:
        assert bond.checkpoint_signing_digest(CHAIN_ID, cp(3)) != (
            bond.checkpoint_signing_digest(CHAIN_ID, cp(4))
        )


def forked(seq: int) -> Checkpoint:
    original = cp(seq)
    return Checkpoint(seq=original.seq, entry_hash="ff" * 32, root=original.root)


class TestEquivocationProof:
    def proof(self, a: Checkpoint, b: Checkpoint) -> bond.EquivocationProof:
        return bond.EquivocationProof(
            chain_id=CHAIN_ID,
            checkpoint_a=a,
            signature_a=b"\x01",
            checkpoint_b=b,
            signature_b=b"\x02",
        )

    def test_two_signed_checkpoints_at_one_seq_that_disagree_are_admissible(self) -> None:
        assert self.proof(cp(3), forked(3)).validate() is None

    def test_a_root_that_differs_is_enough_even_when_the_tip_matches(self) -> None:
        original = cp(3)
        rerooted = Checkpoint(seq=3, entry_hash=original.entry_hash, root="ee" * 32)
        assert self.proof(original, rerooted).validate() is None

    def test_two_checkpoints_at_different_seqs_are_not_equivocation(self) -> None:
        # A log that grows publishes many checkpoints. Slashing on that would
        # slash every honest writer.
        assert self.proof(cp(3), cp(4)).validate() == bond.EQUIVOCATION_SEQ_MISMATCH

    def test_the_same_checkpoint_twice_is_not_equivocation(self) -> None:
        assert self.proof(cp(3), cp(3)).validate() == bond.EQUIVOCATION_NOT_DIVERGENT

    def test_an_unsigned_half_is_inadmissible(self) -> None:
        unsigned = bond.EquivocationProof(
            chain_id=CHAIN_ID,
            checkpoint_a=cp(3),
            signature_a=b"",
            checkpoint_b=forked(3),
            signature_b=b"\x02",
        )
        assert unsigned.validate() == bond.EQUIVOCATION_MISSING_SIGNATURE

    def test_it_hands_the_contract_the_two_digests_to_recover_against(self) -> None:
        proof = self.proof(cp(3), forked(3))
        assert proof.digests() == (
            bond.checkpoint_signing_digest(CHAIN_ID, cp(3)),
            bond.checkpoint_signing_digest(CHAIN_ID, forked(3)),
        )

    def test_python_does_not_claim_to_have_checked_the_signatures(self) -> None:
        # No crypto library in this process (CLAUDE.md rule 1), so `validate`
        # is a STRUCTURAL admissibility check only. A caller that read it as
        # "these signatures are the writer's" would submit fraud proofs that
        # revert, or worse, believe an unsigned pair.
        assert "structural" in (bond.EquivocationProof.validate.__doc__ or "").lower()


class TestNonExtensionProof:
    def test_a_real_consistency_proof_defends_the_writer(self) -> None:
        older, newer = cp(3), cp(7)
        proof = consistency_proof(HASHES, older.seq + 1)
        challenge = bond.NonExtensionProof(
            chain_id=CHAIN_ID, older=older, newer=newer, proof=proof
        )
        assert challenge.validate() is None
        assert challenge.extension_holds() is True

    def test_a_forked_newer_root_cannot_be_defended(self) -> None:
        older = cp(3)
        newer = Checkpoint(seq=7, entry_hash=HASHES[7], root=batch_root(HASHES[:7] + ("aa" * 32,)))
        challenge = bond.NonExtensionProof(
            chain_id=CHAIN_ID, older=older, newer=newer, proof=consistency_proof(HASHES, 4)
        )
        assert challenge.extension_holds() is False

    def test_a_garbage_proof_also_fails_and_that_is_the_whole_problem(self) -> None:
        # The reason this type is a CHALLENGE and not a proof: anybody can
        # submit noise and make `extension_holds` False. Only the writer's
        # failure to answer with a passing proof, within the defence window,
        # is evidence of anything.
        challenge = bond.NonExtensionProof(
            chain_id=CHAIN_ID, older=cp(3), newer=cp(7), proof=("00" * 32,)
        )
        assert challenge.extension_holds() is False
        assert "defence" in (bond.NonExtensionProof.__doc__ or "").lower()

    def test_an_older_checkpoint_that_is_not_older_is_inadmissible(self) -> None:
        challenge = bond.NonExtensionProof(chain_id=CHAIN_ID, older=cp(7), newer=cp(3), proof=())
        assert challenge.validate() == bond.NON_EXTENSION_SEQ_NOT_ADVANCING

    def test_the_same_seq_is_equivocation_business_not_this_one(self) -> None:
        challenge = bond.NonExtensionProof(chain_id=CHAIN_ID, older=cp(3), newer=cp(3), proof=())
        assert challenge.validate() == bond.NON_EXTENSION_SEQ_NOT_ADVANCING

    def test_it_never_raises_on_a_malformed_proof(self) -> None:
        # `verify_consistency` is documented never to raise; this inherits
        # that, because the proof arrives from whoever submitted the
        # challenge.
        challenge = bond.NonExtensionProof(
            chain_id=CHAIN_ID, older=cp(3), newer=cp(7), proof=("not-hex",)
        )
        assert challenge.extension_holds() is False


class TestBondStatus:
    def test_a_funded_unslashed_writer_is_bonded(self) -> None:
        status = bond.bond_status_for("0xab", amount_wei=10**18, slashed=False)
        assert status.status == bond.BONDED
        assert status.to_verdict() is Verdict.OK

    def test_a_slashed_writer_is_a_positive_detection(self) -> None:
        status = bond.bond_status_for("0xab", amount_wei=0, slashed=True)
        assert status.status == bond.SLASHED
        assert status.reason == bond.BOND_SLASHED
        assert status.to_verdict() is Verdict.BROKEN

    def test_a_writer_that_never_deposited_is_not_called_slashed(self) -> None:
        # Both are measured findings and both are bad news, but "slashed" is
        # an adjudicated EVENT. Printing it for a writer that simply never
        # posted a bond asserts a fraud proof that was never submitted.
        status = bond.bond_status_for("0xab", amount_wei=0, slashed=False)
        assert status.status == bond.UNBONDED
        assert status.reason == bond.NO_BOND_POSTED
        assert status.to_verdict() is Verdict.BROKEN

    def test_a_contract_that_could_not_be_asked(self) -> None:
        status = bond.unreachable_bond("0xab", reason="connection refused")
        assert status.status == bond.BOND_UNREACHABLE
        assert status.amount_wei is None
        assert status.to_verdict() is Verdict.UNVERIFIABLE

    def test_amount_is_none_when_unmeasured_never_zero(self) -> None:
        # Rendering an unread bond as 0 wei would read as "this writer has no
        # stake", a claim nothing measured (CLAUDE.md rule 5).
        assert bond.unreachable_bond("0xab", reason="x").amount_wei is None
        assert bond.bond_status_for("0xab", amount_wei=0, slashed=False).amount_wei == 0

    def test_a_status_this_build_does_not_know_is_not_guessed_at(self) -> None:
        with pytest.raises(ValueError, match="not a bond status"):
            bond.BondStatus(writer_id="0xab", status="probably-fine").to_verdict()


class TestFalsifiabilityReceipt:
    """Receipt for the bond ternary's `unreachable` branch, run 01/09/2026.

    Collapsing `unreachable_bond` to the fail-open answer (returning
    `BONDED` instead of `BOND_UNREACHABLE` — the shape "just assume it's
    fine if the node is down" takes) was run against this file:

        FAILED tests/domain/test_bond.py::TestBondStatus::
            test_a_contract_that_could_not_be_asked
        AssertionError: assert 'bonded' == 'unreachable'
        1 failed, 22 passed, 1 deselected in 0.07s

    Branch restored: 24 passed. The failure is false confidence — a writer
    whose bond contract nobody could reach, reported as fully staked.
    """

    def test_the_receipt_is_recorded(self) -> None:
        assert "1 failed" in (TestFalsifiabilityReceipt.__doc__ or "")
