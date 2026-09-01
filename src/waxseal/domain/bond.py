"""Bonded checkpoints: what a writer can be slashed for (pure; no I/O).

The bonded equivocation contract is the third construction the paper
describes as designed but not implemented. It does not make a writer honest.
It makes ONE specific dishonesty expensive: signing two different
checkpoints at the same position. That fact is self-contained — anyone
holding both signed checkpoints can present them, and no further context is
needed to see the contradiction — which is what makes it enforceable by a
contract with no view of the log.

The other fault the contract is asked about, a writer whose new tree does
not extend its old one, is NOT self-contained, and the asymmetry is easy to
miss:

  * Equivocation is PROVEN by exhibiting the pair. `EquivocationProof`.
  * Non-extension cannot be proven by exhibiting anything. An RFC 9162
    consistency proof establishes that a tree DOES extend another; there is
    no proof of the negative, because a submitter who wants the check to
    fail need only submit noise. `NonExtensionProof` is therefore a
    CHALLENGE, and `extension_holds()` is the writer's DEFENCE. Only the
    expiry of the defence window without a passing proof is slashable, and
    that window is why the contract's `withdraw()` must be delayed by at
    least delta.

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

from waxseal.domain.anchoring import verify_consistency
from waxseal.domain.checkpoint import Checkpoint, checkpoint_frame
from waxseal.domain.hashing import lp
from waxseal.domain.verdict import Verdict

LEDGER_CHECKPOINT_SIG_PREFIX: Final = b"waxseal-ledger-checkpoint-sig-v1\n"


def checkpoint_signing_digest(chain_id: str, checkpoint: Checkpoint) -> bytes:
    """The 32 bytes a writer's key signs when publishing a checkpoint.

    The trail's `chain_id` is INSIDE the digest. Without it, a signature over
    trail A's checkpoint at seq 9 is a valid signature over trail B's
    checkpoint at seq 9 whenever the two happen to agree, and — worse in the
    other direction — two unrelated trails at the same seq look to the
    contract like one writer equivocating. Binding the identity costs one
    length-prefixed field and removes the whole class.
    """
    frame = (
        LEDGER_CHECKPOINT_SIG_PREFIX
        + struct.pack(">Q", 2)
        + lp(chain_id)
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


@dataclass(frozen=True, slots=True)
class NonExtensionProof:
    """A challenge that a newer checkpoint does not extend an older one, and
    the consistency proof offered as the writer's defence.

    Named `NonExtensionProof` because that is what the contract's
    `proveNonExtension` entry point is called, but it is a challenge: see the
    module docstring. `extension_holds()` returning False is NOT evidence of
    a fork on its own — a submitter who supplies noise gets False every time.
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
