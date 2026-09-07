"""EvmAnchorSink: publish a checkpoint through EvmLedgerSink."""

from __future__ import annotations

from collections.abc import Callable, Sequence

from waxseal.adapters.evm._rpc import SIGNATURE_BYTES
from waxseal.adapters.evm.sink import EvmLedgerSink
from waxseal.domain.bond import checkpoint_signing_digest
from waxseal.domain.checkpoint import Checkpoint
from waxseal.ports.ledger import LedgerError, Signer


class EvmAnchorSink:
    """`AnchorSink` writing the trail head to the liveness contract.

    This replaces the docs-only example in `docs/anchoring-external-time.md`
    with code. The digest signer and the transaction signer are injected
    SEPARATELY because `ports/ledger.py` keeps them as separate Protocols: a
    key that signs a 32-byte checkpoint digest is not necessarily the key
    that pays for gas, and in a sane deployment it is not.
    """

    name: str = "evm"

    def __init__(
        self,
        sink: EvmLedgerSink,
        chain_id: str,
        signer: Signer,
        *,
        proof_fn: Callable[[Checkpoint], Sequence[str]] | None = None,
    ) -> None:
        self._sink = sink
        self._chain_id = chain_id
        self._signer = signer
        self._proof_fn = proof_fn

    def anchor(self, checkpoint: Checkpoint) -> str:
        """Sign and publish, returning `evm:<chainid>:<block>:<txhash>`.

        `proof_fn` supplies the RFC 9162 consistency proof the contract
        requires from the second submit onwards; `AnchorSink.anchor` is
        handed only a `Checkpoint`, so an operator anchoring repeatedly must
        inject it. Without one, the second anchor raises `LedgerError` when
        the contract refuses — loudly, as `AnchorSink` requires, never as a
        silent no-receipt.
        """
        digest = checkpoint_signing_digest(self._chain_id, checkpoint)
        signature = self._signer.sign(digest)
        if len(signature) != SIGNATURE_BYTES:
            raise LedgerError(
                f"the signer returned {len(signature)} bytes; CheckpointCodec.recoverSigner "
                f"reads exactly {SIGNATURE_BYTES} (r‖s‖v) and recovers address(0) from "
                "anything else, which the contract rejects only after the gas is spent"
            )
        proof = () if self._proof_fn is None else self._proof_fn(checkpoint)
        receipt = self._sink.submit_checkpoint_receipt(
            self._chain_id, checkpoint, signature, consistency_proof=proof
        )
        return receipt.anchor_receipt()
