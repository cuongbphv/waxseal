"""Chain-agnostic ledger port: read a contract, write to one, sign for it.

The on-chain layer is deliberately behind a port. EVM is the first adapter,
not the design: nothing in these Protocols mentions JSON-RPC, gas, blocks or
Solidity, so a second chain is another adapter rather than a second copy of
the verifier. That is the first of the four locked decisions for this layer.

Three contracts sit behind `LedgerReader`, and they answer three different
questions: did the writer anchor on time (liveness), does the world agree
with this build about what a fingerprint means (registry), and is there a
stake behind the writer's signatures (bond). Every one of those answers is
three-valued, and the third value is why this file's error contract is what
it is.

THE ERROR CONTRACT, which an implementer must not soften:

  * A method returns `None` ONLY for "the contract answered, and it holds
    nothing" — no checkpoint for this chain id, no deadline configured, no
    descriptor under this fingerprint. That is a measured absence.
  * A method RAISES `LedgerUnreachable` when it could not ask. Returning
    `None` there would render "the node was down" as "the writer never
    anchored", which is a false alarm manufactured out of a network
    problem, and the caller could not tell the two apart afterwards.
  * A method raises `LedgerDisagreement` when two or more endpoints
    answered and did not agree. That is not unreachability and not a
    verdict about the trail: it is an eclipse-shaped observation, and the
    pair that disagreed must reach the operator (CLAUDE.md rule 6 — a
    degradation is reported, never swallowed).

`LedgerSink` mirrors `AnchorSink` (`ports/anchor.py`) exactly: an opaque
receipt string on success, an exception on failure, and never a quiet "no
receipt" that a caller would read as a successful publish.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol

from waxseal.domain.bond import BondStatus, EquivocationProof, NonExtensionProof
from waxseal.domain.checkpoint import Checkpoint
from waxseal.domain.liveness import OnChainCheckpoint


class LedgerError(RuntimeError):
    """Base for every ledger failure that must not be read as a verdict."""


class LedgerUnreachable(LedgerError):
    """The chain could not be asked. Nothing was measured.

    Distinct from every domain verdict on purpose: the domain functions are
    pure and never learn what an endpoint is, so unreachability enters the
    verdict vocabulary only where a caller catches this and builds
    `unreachable_ledger` / `unreachable_bond` explicitly.
    """


class LedgerDisagreement(LedgerError):
    """Two or more endpoints answered and did not agree.

    A measured conflict, not a silence, and not evidence that the trail was
    edited. An adapter reading several RPC endpoints raises this instead of
    picking a winner: choosing one is exactly what an eclipsing adversary
    needs the client to do.
    """


class LedgerReader(Protocol):
    """The read path. Stdlib-only in the EVM adapter: `eth_call` over
    JSON-RPC, so verification never needs an installed web3 stack."""

    name: str

    def latest_checkpoint(self, chain_id: str) -> OnChainCheckpoint | None:
        """The newest checkpoint the liveness contract holds for `chain_id`,
        or None if it holds none. Raise `LedgerUnreachable` if it could not
        be asked."""
        ...

    def deadline_s(self, chain_id: str) -> int | None:
        """The anchoring deadline (delta) registered for `chain_id`, or None
        if none is configured. Raise `LedgerUnreachable` if it could not be
        asked. None is NOT a default: a caller with no deadline has nothing
        to be late against and must report unmeasured."""
        ...

    def registry_lookup(self, fingerprint: str) -> bytes | None:
        """The descriptor bytes published under `fingerprint`, or None if
        the registry holds none. Raise `LedgerUnreachable` if it could not
        be asked.

        Bytes, not hex text: the contract stores the preimage the
        fingerprint is the SHA-256 of, and hexing it here would force every
        caller to undo that before it could hash anything.
        """
        ...

    def bond_status(self, writer_id: str) -> BondStatus:
        """The bond contract's view of `writer_id`. Never None: `BondStatus`
        already distinguishes bonded, slashed and never-deposited, so an
        extra None would be a fourth encoding of one of them. Raise
        `LedgerUnreachable` if it could not be asked — or catch that and
        return `unreachable_bond(...)`, but never both."""
        ...


class LedgerSink(Protocol):
    """The write path. Every method returns an opaque receipt (a transaction
    hash for EVM) and raises on failure, matching `AnchorSink`."""

    name: str

    def submit_checkpoint(self, chain_id: str, checkpoint: Checkpoint, signature: bytes) -> str:
        """Publish a signed checkpoint to the liveness contract.

        The signature is over `checkpoint_signing_digest(chain_id,
        checkpoint)` (`domain/bond.py`) and travels separately from the
        checkpoint so that ANY party may submit a checkpoint the writer
        signed — which is what the paper's construction requires — while
        nobody can submit one the writer did not.
        """
        ...

    def register_fingerprint(self, descriptor: bytes) -> str:
        """Publish a descriptor to the fingerprint registry.

        The descriptor alone: the contract computes `fp = sha256(desc)`
        itself, so there is no fingerprint argument that could disagree with
        the bytes beside it. Registration is append-only and a duplicate
        reverts, which is the feature, not a limitation to work around.
        """
        ...

    def submit_fraud_proof(self, proof: EquivocationProof | NonExtensionProof) -> str:
        """Submit a fraud proof to the bond contract.

        BOTH shapes go here (see `domain/bond.py`): two signed checkpoints
        that disagree at one seq, or one leaf index at which two signed roots
        prove different entries. Both are self-contained — an implementation
        that cannot act on one of them is required to say so rather than
        approximate it into a call the contract reverts on.

        A `NonExtensionChallenge` is deliberately NOT accepted here. It only
        becomes evidence when the defence window closes unanswered, which is
        a clock no ledger call owns.
        """
        ...


class Signer(Protocol):
    """Signs a 32-byte digest for the ledger layer.

    NOT `waxseal.ports.sign.Signer`, which signs arbitrary attestation bytes
    with a named algorithm. This one signs a fixed-size digest under the
    chain's own scheme (secp256k1 for EVM, so the contract can `ecrecover`),
    and the two are separate protocols because an implementation of one is
    not an implementation of the other.

    Injected by the operator, exactly as the `s3` and `rfc3161` extras take
    an injected client: waxseal imports no crypto library (CLAUDE.md rule 1).
    An implementation might shell out to `cast wallet sign`, call
    `eth-account`, or talk to an HSM. The private key never reaches waxseal,
    and never belongs in a CLI flag where it would sit in the process table.
    """

    address: str
    public_id: str

    def sign(self, digest32: bytes) -> bytes:
        """Sign exactly 32 bytes. Raise on failure; never return empty."""
        ...


class TransactionSigner(Signer, Protocol):
    """A `Signer` that can also sign a whole transaction.

    Separate from `Signer` because the read path and the fraud-proof path
    need only digest signing, and a fake for those should not have to
    implement transaction serialization. The sink adapter asks for this one.
    """

    def sign_transaction(self, fields: Mapping[str, object]) -> bytes:
        """Return the raw RLP-encoded signed transaction for `fields`."""
        ...
