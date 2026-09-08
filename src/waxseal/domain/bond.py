"""Bonded checkpoints: what a writer can be slashed for (pure; no I/O).

The bonded equivocation contract is the pure half of a shipped construction:
`domain/bond.py` shapes the proofs, `BondedCheckpoints.sol` slashes on them,
and `waxseal bond deposit` / `bond prove` is the CLI. It does not make a
writer honest. It makes ONE specific dishonesty expensive: signing two
different checkpoints at the same position. That fact is self-contained -
anyone holding both signed checkpoints can present them, and no further
context is needed to see the contradiction - which is what makes it
enforceable by a contract with no view of the log.

The other fault the contract is asked about, a writer whose new tree does
not extend its old one, is NOT self-contained, and the asymmetry is easy to
miss:

  * Equivocation is PROVEN by exhibiting the pair. `EquivocationProof`.
  * Non-extension cannot be proven by exhibiting a CONSISTENCY proof. An RFC
    9162 consistency proof establishes that a tree DOES extend another; there
    is no proof of the negative that way, because a submitter who wants the
    check to fail need only submit noise. `NonExtensionChallenge` is
    therefore a CHALLENGE, and `extension_holds()` is the writer's DEFENCE.
    Only the expiry of the defence window without a passing proof is
    slashable, and that window is why the contract's `withdraw()` must be
    delayed by at least delta.
  * It CAN be proven by exhibiting a divergent leaf: one index at which two
    signed roots each prove a different entry. `NonExtensionProof`, and what
    the deployed `proveNonExtension` accepts. The two ideas shared the name
    `NonExtensionProof` through 0.1.5, which left `submit_fraud_proof`
    raising on one of its own argument types; they are now two names.

Signature verification is not here and cannot be: waxseal imports no crypto
library (CLAUDE.md rule 1). `validate()` decides STRUCTURAL admissibility —
is this pair even the shape of a fraud? — and the two `ecrecover` calls that
decide whose signatures they are belong to the contract. A caller that reads
`validate() is None` as "the writer signed these" has been told otherwise
here and in the method's own docstring.

The signing digest is SHA-256, not keccak256: the EVM has a SHA-256
precompile (0x02), the rest of this codebase is SHA-256 throughout, and
Python cannot compute keccak256 at all without a dependency this project
does not take.
"""

from __future__ import annotations

import hashlib
import struct
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

from waxseal.domain.anchoring import verify_consistency, verify_membership
from waxseal.domain.checkpoint import Checkpoint, checkpoint_frame
from waxseal.domain.hashing import LpEncodingError, lp
from waxseal.domain.verdict import Verdict

# THE one signing prefix. `CheckpointCodec.sol` holds the same literal because
# Solidity cannot import Python, and `tools/gen_contract_vectors.py` imports
# THIS name rather than restating it — the generator's own copy is what let
# the two sides sign different bytes through every green gate
# (waxseal-fg4.37). The vector the generator writes is computed by the
# function below, so a change here moves the vector and the stale Solidity
# constant fails `forge test`.
LEDGER_CHECKPOINT_SIG_PREFIX: Final = b"waxseal-ledger-checkpoint-sig-v1\n"


def trail_id_for(chain_id: str) -> bytes:
    """The 32-byte trail id the contracts key by, from the trail's name.

    PINNED, not implicit. The Python side names a trail with a string; the
    contracts key their mappings by `bytes32` and cannot hold a name of
    unbounded length. Something has to reduce one to the other, and while
    that reduction was unwritten the two halves of the protocol each assumed
    a different one — which is half of why they signed different bytes. The
    reduction is `sha256` of the name's UTF-8 bytes, it is stated here once,
    and the cross-language vectors carry both the name and the id so the
    mapping itself is under test rather than merely believed.

    Operator-chosen ids were the alternative and are rejected: an id nobody
    can recompute from the trail name is an id a verifier has to be TOLD,
    and a verifier that takes the binding on trust is not verifying it.

    Raises `LpEncodingError`, matching `lp`, for a `str` with no UTF-8 form
    (a lone UTF-16 surrogate) rather than letting the bare stdlib error out.
    """
    try:
        encoded = chain_id.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise LpEncodingError(
            f"trail_id_for() cannot encode {chain_id!r}: not representable in UTF-8"
        ) from exc
    return hashlib.sha256(encoded).digest()


def checkpoint_signing_digest(chain_id: str, checkpoint: Checkpoint) -> bytes:
    """The 32 bytes a writer's key signs when publishing a checkpoint.

    The trail is INSIDE the digest. Without it, a signature over trail A's
    checkpoint at seq 9 is a valid signature over trail B's checkpoint at seq
    9 whenever the two happen to agree, and — worse in the other direction —
    two unrelated trails at the same seq look to the contract like one writer
    equivocating. Binding the identity costs one length-prefixed field and
    removes the whole class.

    It is bound as `trail_id_for(chain_id)` spelled in lowercase hex, not as
    the name itself: the contracts already hold that `bytes32` as their
    mapping key, so the digest is built from what the contract HAS and there
    is no name-to-id check to get wrong on the slashing path.

    The frame is signed DIRECTLY rather than through its own hash. The
    alternative — signing `sha256(frame)` hex-encoded — buys a fixed-length
    preimage, which is the mitigation you need when fields are not length
    prefixed. lp64 length-prefixes them, so the concatenation below is
    already injective: the prefix and field count are fixed, `lp` is
    self-delimiting, and the frame is last and takes the remainder. Paying an
    extra hash and an extra ASCII re-spelling for a property the encoding
    already guarantees would add two more surfaces for the two languages to
    disagree on, which is the failure this whole bead is about.
    """
    frame = (
        LEDGER_CHECKPOINT_SIG_PREFIX
        + struct.pack(">Q", 2)
        + lp(trail_id_for(chain_id).hex())
        + checkpoint_frame(checkpoint)
    )
    return hashlib.sha256(frame).digest()


EQUIVOCATION_SEQ_MISMATCH: Final = "seq_mismatch"
EQUIVOCATION_NOT_DIVERGENT: Final = "not_divergent"
EQUIVOCATION_MISSING_SIGNATURE: Final = "missing_signature"


@dataclass(frozen=True, slots=True)
class EquivocationProof:
    """Two signed checkpoints at the same seq that disagree."""

    chain_id: str
    checkpoint_a: Checkpoint
    signature_a: bytes
    checkpoint_b: Checkpoint
    signature_b: bytes

    def digests(self) -> tuple[bytes, bytes]:
        """The two digests the contract recovers the signer's address from."""
        return (
            checkpoint_signing_digest(self.chain_id, self.checkpoint_a),
            checkpoint_signing_digest(self.chain_id, self.checkpoint_b),
        )

    def validate(self) -> str | None:
        """Structural admissibility, never a signature check.

        Returns None when the pair is the shape of an equivocation, else the
        reason it is not. Signature recovery is the contract's; this process
        holds no crypto library and must not imply that it does.
        """
        if not self.signature_a or not self.signature_b:
            return EQUIVOCATION_MISSING_SIGNATURE
        if self.checkpoint_a.seq != self.checkpoint_b.seq:
            # Different heights are what a growing log looks like.
            return EQUIVOCATION_SEQ_MISMATCH
        if (
            self.checkpoint_a.entry_hash == self.checkpoint_b.entry_hash
            and self.checkpoint_a.root == self.checkpoint_b.root
        ):
            return EQUIVOCATION_NOT_DIVERGENT
        return None


NON_EXTENSION_SEQ_NOT_ADVANCING: Final = "seq_not_advancing"
NON_EXTENSION_LEAF_INDEX_DIFFERS: Final = "leaf_index_differs"
NON_EXTENSION_LEAF_OUTSIDE_OLDER_TREE: Final = "leaf_outside_older_tree"
NON_EXTENSION_LEAVES_AGREE: Final = "leaves_agree"
NON_EXTENSION_MISSING_SIGNATURE: Final = "missing_signature"


@dataclass(frozen=True, slots=True)
class NonExtensionChallenge:
    """A challenge that a newer checkpoint does not extend an older one, and
    the consistency proof offered as the writer's defence.

    NOT what `BondedCheckpoints.proveNonExtension` takes — that is
    `NonExtensionProof` below. This type carried the `NonExtensionProof` name
    through 0.1.5, which put one name on two incompatible ideas and left
    `EvmLedgerSink.submit_fraud_proof` raising on its own domain type; the
    name moved to the shape the deployed contract accepts, and this kept the
    behaviour under an honest one.

    It is a challenge, not a proof: see the module docstring.
    `extension_holds()` returning False is NOT evidence of a fork on its own
    — a submitter who supplies noise gets False every time. Only the expiry
    of the defence window without a passing proof is slashable, and that
    expiry is a clock this process does not own.
    """

    chain_id: str
    older: Checkpoint
    newer: Checkpoint
    proof: Sequence[str] = ()

    def validate(self) -> str | None:
        """Structural admissibility of the challenge itself."""
        if self.newer.seq <= self.older.seq:
            # Equal seq is equivocation's business; a "newer" that is older
            # is nothing at all.
            return NON_EXTENSION_SEQ_NOT_ADVANCING
        return None

    def extension_holds(self) -> bool:
        """Does `proof` show the newer tree extends the older one?

        Delegates to `verify_consistency` (`domain/anchoring.py`), the one
        RFC 9162 implementation in this codebase, so the Python side and the
        Solidity side cannot drift into two different notions of consistency.
        A checkpoint's `seq` is the index of its last entry, so the tree size
        is `seq + 1`. Never raises: `verify_consistency` does not, and the
        proof is submitter-supplied.
        """
        return verify_consistency(
            self.older.root,
            self.older.seq + 1,
            self.newer.root,
            self.newer.seq + 1,
            self.proof,
        )


@dataclass(frozen=True, slots=True)
class DivergentLeaf:
    """One leaf position, the entry claimed to sit there, and the inclusion
    proof tying it to a signed root.

    `BondedCheckpoints.LeafClaim` on the wire. It lived in `adapters/evm.py`
    through 0.1.5 on the reasoning that a wire shape belongs to the adapter,
    which was true of the ENCODING and not of the evidence: whether a pair of
    these actually contradicts each other is RFC 9162 arithmetic over hashes,
    which is domain work and had no domain home. The adapter now encodes this
    and decides nothing.
    """

    index: int
    entry_hash: str
    proof: Sequence[str] = ()


@dataclass(frozen=True, slots=True)
class NonExtensionProof:
    """POSITIVE evidence that a newer tree contradicts an older one: one leaf
    index at which the two signed roots each prove a DIFFERENT entry.

    This is what `BondedCheckpoints.proveNonExtension` accepts, and the
    asymmetry with `NonExtensionChallenge` is the whole design. A consistency
    proof that fails shows only that the submitter supplied a bad one, so
    slashing on it would let anyone drain an honest writer's bond for the
    price of gas. A divergent leaf needs no such trust: both inclusion proofs
    verify against roots the writer signed, and no context beyond them is
    required to see the contradiction.

    `validate()` is STRUCTURAL admissibility, as on `EquivocationProof`: it
    reproduces the three conditions the contract reverts on before spending
    gas, and it says nothing about whose signatures these are. The contract
    folds two of them into one `LeafIndexOutsideOlderTree` revert; they are
    separate reasons here because they need different fixes — one submitter
    named two indices, the other named a leaf the older tree never claimed.
    """

    chain_id: str
    older: Checkpoint
    newer: Checkpoint
    older_signature: bytes
    newer_signature: bytes
    in_older: DivergentLeaf
    in_newer: DivergentLeaf

    def digests(self) -> tuple[bytes, bytes]:
        """The two digests the contract recovers ONE writer's address from."""
        return (
            checkpoint_signing_digest(self.chain_id, self.older),
            checkpoint_signing_digest(self.chain_id, self.newer),
        )

    def validate(self) -> str | None:
        """Structural admissibility, in the contract's own order, and never a
        signature check — the two `ecrecover` calls are the contract's, as on
        `EquivocationProof`."""
        if not self.older_signature or not self.newer_signature:
            return NON_EXTENSION_MISSING_SIGNATURE
        if self.newer.seq <= self.older.seq:
            return NON_EXTENSION_SEQ_NOT_ADVANCING
        if self.in_older.index != self.in_newer.index:
            return NON_EXTENSION_LEAF_INDEX_DIFFERS
        if self.in_older.index > self.older.seq:
            # A leaf the older tree does not contain cannot contradict it.
            return NON_EXTENSION_LEAF_OUTSIDE_OLDER_TREE
        if self.in_older.entry_hash == self.in_newer.entry_hash:
            return NON_EXTENSION_LEAVES_AGREE
        return None

    def divergence_holds(self) -> bool:
        """Do BOTH inclusion proofs check out against their own roots?

        Delegates to `verify_membership` (`domain/anchoring.py`), the same
        RFC 9162 implementation `Rfc9162.verifyInclusion` is cross-checked
        against, so Python and Solidity cannot drift into two notions of
        inclusion. False here means the submitter proved nothing and nobody
        is slashed — the opposite direction from the challenge type, where
        False was the alarming answer. Never raises: the claims are
        submitter-supplied.
        """
        return verify_membership(
            self.in_older.entry_hash,
            self.in_older.index,
            self.older.seq + 1,
            self.in_older.proof,
            self.older.root,
        ) and verify_membership(
            self.in_newer.entry_hash,
            self.in_newer.index,
            self.newer.seq + 1,
            self.in_newer.proof,
            self.newer.root,
        )


BONDED: Final = "bonded"
SLASHED: Final = "slashed"
UNBONDED: Final = "unbonded"
BOND_UNREACHABLE: Final = "unreachable"

BOND_SLASHED: Final = "bond_slashed"
NO_BOND_POSTED: Final = "no_bond_posted"


@dataclass(frozen=True, slots=True)
class BondStatus:
    """What the bond contract says about one writer.

    Four values, not three, and the extra one is the point. `slashed` names
    an ADJUDICATED event: a fraud proof was submitted and accepted.
    `unbonded` names a writer that never posted a stake. Both are measured,
    both are bad news, and folding the second into the first would print
    "slashed" over a writer nobody ever proved anything against — asserting
    an adjudication from an absence, which is the same move CLAUDE.md rule 5
    forbids in the other direction. The evidential trichotomy the Ternary
    Evidence Principle asks for is intact: measured-good, measured-bad,
    unmeasured; `slashed` and `unbonded` are two distinct measured-bad
    findings, and `unreachable` remains the one value that means nothing was
    measured.

    `amount_wei` is None when unmeasured and never 0, which would read as a
    measured absence of stake.
    """

    writer_id: str
    status: str
    amount_wei: int | None = None
    reason: str | None = None

    def to_verdict(self) -> Verdict:
        """The `ledger-status` mapping: exit 1 is a positive detection."""
        try:
            return _BOND_STATUS[self.status]
        except KeyError:
            raise ValueError(f"not a bond status: {self.status!r}") from None


_BOND_STATUS: Final[dict[str, Verdict]] = {
    BONDED: Verdict.OK,
    SLASHED: Verdict.BROKEN,
    UNBONDED: Verdict.BROKEN,
    BOND_UNREACHABLE: Verdict.UNVERIFIABLE,
}


def bond_status_for(writer_id: str, *, amount_wei: int, slashed: bool) -> BondStatus:
    """Combine the contract's two reads into one status.

    Two reads rather than one packed return, because `isSlashed` is what
    separates "slashed to zero" from "never deposited" — a distinction a bare
    `bondOf` of 0 cannot make, and the reason this function can answer
    without guessing.
    """
    if slashed:
        return BondStatus(writer_id, SLASHED, amount_wei=amount_wei, reason=BOND_SLASHED)
    if amount_wei <= 0:
        return BondStatus(writer_id, UNBONDED, amount_wei=amount_wei, reason=NO_BOND_POSTED)
    return BondStatus(writer_id, BONDED, amount_wei=amount_wei)


def unreachable_bond(writer_id: str, *, reason: str) -> BondStatus:
    """A bond contract that could not be asked.

    Built by the caller that owns the network, the same split
    `unreachable_witness` and `unreachable_ledger` use, so nothing in this
    module has to know what an RPC endpoint is.
    """
    return BondStatus(writer_id, BOND_UNREACHABLE, amount_wei=None, reason=reason)
