"""EvmLedgerSink: one-endpoint writes via an injected TransactionSigner."""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from waxseal.adapters.evm._rpc import T, _hex_int, _RpcRevert
from waxseal.adapters.evm.contracts import (
    SELECTOR_SUBMIT_HEAD,
    EvmTxReceipt,
    _signed_checkpoint,
    leaf_claim,
)
from waxseal.adapters.evm.reader import EvmLedgerReader
from waxseal.domain.abi import (
    SELECTOR_DEPOSIT,
    SELECTOR_PROVE_EQUIVOCATION,
    SELECTOR_PROVE_NON_EXTENSION,
    SELECTOR_REGISTER,
    SELECTOR_REGISTER_TRAIL,
    encode_address,
    encode_bytes,
    encode_bytes32,
    encode_bytes32_array,
    encode_call,
    encode_uint,
)
from waxseal.domain.bond import EquivocationProof, NonExtensionProof, trail_id_for
from waxseal.domain.checkpoint import Checkpoint
from waxseal.ports.ledger import LedgerError, LedgerUnreachable, TransactionSigner


class EvmLedgerSink:
    """`LedgerSink` over JSON-RPC with an injected `TransactionSigner`.

    The signer is never constructed here and no private key ever reaches
    waxseal: this class assembles the transaction FIELDS, hands them over,
    and broadcasts whatever raw bytes come back. An implementation may shell
    out to `cast wallet`, call `eth-account`, or talk to an HSM.

    Writes go to ONE endpoint, not to the reader's quorum. A transaction is
    submitted, not measured — broadcasting the same signed bytes to several
    nodes is a propagation strategy, not a cross-check, and the confirmation
    that matters is read back through the reader's agreement path afterwards.
    """

    name: str = "evm"

    def __init__(
        self,
        reader: EvmLedgerReader,
        signer: TransactionSigner,
        *,
        rpc_url: str | None = None,
        confirm_tag: str = "finalized",
        poll_interval_s: float = 1.0,
        max_polls: int = 60,
        sleep_fn: Callable[[float], None] = time.sleep,
    ) -> None:
        if max_polls < 1:
            raise ValueError(f"max_polls must be at least 1, got {max_polls}")
        self._reader = reader
        self._signer = signer
        self._url = rpc_url if rpc_url is not None else reader._urls[0]
        self._confirm_tag = confirm_tag
        self._poll_interval_s = poll_interval_s
        self._max_polls = max_polls
        self._sleep = sleep_fn

    # ------------------------------------------------------------ plumbing

    def _rpc(self, what: str, method: str, params: list[Any]) -> Any:
        return self._reader._rpc(self._url, what, method, params)

    def _poll(self, what: str, probe: Callable[[], T | None]) -> T:
        for attempt in range(self._max_polls):
            found = probe()
            if found is not None:
                return found
            if attempt + 1 < self._max_polls:
                self._sleep(self._poll_interval_s)
        raise LedgerUnreachable(f"{what}: still unresolved after {self._max_polls} polls")

    def _send(self, what: str, to: str, data: bytes, *, value: int = 0) -> EvmTxReceipt:
        chain_id = _hex_int(what, self._rpc(what, "eth_chainId", []))
        nonce = _hex_int(
            what, self._rpc(what, "eth_getTransactionCount", [self._signer.address, "pending"])
        )
        block = self._rpc(what, "eth_getBlockByNumber", ["latest", False])
        if not isinstance(block, Mapping):
            raise LedgerUnreachable(f"{what}: the node returned no latest block")
        base_fee = _hex_int(what, block.get("baseFeePerGas"))
        priority_fee = _hex_int(what, self._rpc(what, "eth_maxPriorityFeePerGas", []))
        call = {
            "from": self._signer.address,
            "to": to,
            "data": "0x" + data.hex(),
            "value": hex(value),
        }
        try:
            gas = _hex_int(what, self._rpc(what, "eth_estimateGas", [call]))
        except _RpcRevert as revert:
            # A revert on the WRITE path is the contract rejecting this
            # transaction, which is a positive answer — the opposite of the
            # read path, where an unrecognised revert means nothing was
            # measured. Sending it anyway would burn the operator's gas to
            # learn what the estimate already said.
            raise LedgerError(f"{what}: the contract rejected this call: {revert}") from revert
        fields: dict[str, object] = {
            "type": 2,
            "chainId": chain_id,
            "nonce": nonce,
            "to": to,
            "value": value,
            "data": "0x" + data.hex(),
            "gas": gas,
            # Twice the base fee plus the tip: the base fee can rise by 12.5%
            # per block, so a bare `base + tip` is a transaction that stops
            # being includable the moment one busy block passes.
            "maxFeePerGas": 2 * base_fee + priority_fee,
            "maxPriorityFeePerGas": priority_fee,
            "accessList": [],
        }
        raw = self._signer.sign_transaction(fields)
        if not raw:
            raise LedgerError(f"{what}: the signer returned no transaction bytes")
        try:
            sent = self._rpc(what, "eth_sendRawTransaction", ["0x" + raw.hex()])
        except _RpcRevert as revert:
            raise LedgerError(f"{what}: the node rejected the transaction: {revert}") from revert
        tx_hash = str(sent)
        receipt = self._poll(f"{what}: receipt for {tx_hash}", lambda: self._receipt(what, tx_hash))
        status = _hex_int(what, receipt.get("status"))
        if status != 1:
            raise LedgerError(f"{what}: transaction {tx_hash} reverted on chain (status {status})")
        block_number = _hex_int(what, receipt.get("blockNumber"))
        self._poll(
            f"{what}: {tx_hash} in block {block_number} reaching {self._confirm_tag}",
            lambda: self._confirmed(what, block_number),
        )
        return EvmTxReceipt(tx_hash=tx_hash, block_number=block_number, chain_id=chain_id)

    def _receipt(self, what: str, tx_hash: str) -> Mapping[str, Any] | None:
        result = self._rpc(what, "eth_getTransactionReceipt", [tx_hash])
        return result if isinstance(result, Mapping) else None

    def _confirmed(self, what: str, block_number: int) -> bool | None:
        """True once `confirm_tag` has reached `block_number`, else None.

        None, not False, because `_poll` reads None as "keep waiting" — and
        because "not final yet" is not a measurement that the block was
        excluded. A dev node whose `finalized` never advances will time out
        here with a message naming both numbers rather than claim finality.
        """
        head = self._rpc(what, "eth_getBlockByNumber", [self._confirm_tag, False])
        if not isinstance(head, Mapping):
            return None
        return True if _hex_int(what, head.get("number")) >= block_number else None

    # ---------------------------------------------------------- LedgerSink

    def register_trail(self, chain_id: str, writer: str, deadline_s: int) -> str:
        """Bind a trail id to its writer key and deadline (one-time)."""
        return self.register_trail_receipt(chain_id, writer, deadline_s).tx_hash

    def register_trail_receipt(self, chain_id: str, writer: str, deadline_s: int) -> EvmTxReceipt:
        calldata = encode_call(
            SELECTOR_REGISTER_TRAIL,
            [
                encode_bytes32(trail_id_for(chain_id)),
                encode_address(writer),
                encode_uint(deadline_s, bits=64),
            ],
        )
        return self._send("registerTrail", self._reader._address("liveness"), calldata)

    def submit_checkpoint(
        self,
        chain_id: str,
        checkpoint: Checkpoint,
        signature: bytes,
        *,
        consistency_proof: Sequence[str] = (),
    ) -> str:
        return self.submit_checkpoint_receipt(
            chain_id, checkpoint, signature, consistency_proof=consistency_proof
        ).tx_hash

    def submit_checkpoint_receipt(
        self,
        chain_id: str,
        checkpoint: Checkpoint,
        signature: bytes,
        *,
        consistency_proof: Sequence[str] = (),
    ) -> EvmTxReceipt:
        """Publish a writer-signed head.

        `consistency_proof` is a keyword with a default because
        `ports/ledger.LedgerSink` was written against a five-argument
        `submit` and the deployed contract takes a sixth: an RFC 9162 proof
        that the recorded head's tree is a prefix of this one. Empty is
        correct for the FIRST submit and only the first; afterwards the
        contract reverts `NotAnExtension`, which arrives here as a
        `LedgerError` rather than as a quiet no-op.
        """
        calldata = encode_call(
            SELECTOR_SUBMIT_HEAD,
            [
                encode_bytes32(trail_id_for(chain_id)),
                encode_uint(checkpoint.seq, bits=64),
                encode_bytes32(checkpoint.entry_hash),
                encode_bytes32(checkpoint.root),
                encode_bytes(signature),
                encode_bytes32_array(consistency_proof),
            ],
        )
        return self._send("submit", self._reader._address("liveness"), calldata)

    def register_fingerprint(self, descriptor: bytes) -> str:
        """Publish a descriptor. The contract computes `sha256(descriptor)`
        itself, so there is no fingerprint argument to disagree with it."""
        calldata = encode_call(SELECTOR_REGISTER, [encode_bytes(descriptor)])
        return self._send("register", self._reader._address("registry"), calldata).tx_hash

    def deposit_bond(self, amount_wei: int) -> str:
        """Post or top up the signer's bond."""
        calldata = encode_call(SELECTOR_DEPOSIT, [])
        return self._send(
            "deposit", self._reader._address("bond"), calldata, value=amount_wei
        ).tx_hash

    def submit_fraud_proof(self, proof: EquivocationProof | NonExtensionProof) -> str:
        """Submit a fraud proof to the bond contract. ONE door for both shapes.

        It was not one through 0.1.5: `domain/bond.NonExtensionProof` then
        modelled a consistency-proof CHALLENGE, which `proveNonExtension` does
        not accept — the contract slashes on POSITIVE evidence (one leaf index
        and two inclusion proofs putting different entry hashes there, each
        valid against its own signed root) because a FAILING consistency proof
        shows only that the prover supplied a bad one, and slashing on that
        would let anyone burn an honest writer's bond for the price of gas. So
        this method raised on one of its own two argument types and pointed at
        a second entry point. The domain type is now that positive evidence
        (the challenge kept its behaviour under the honest name
        `NonExtensionChallenge`), and the second door is gone.
        """
        if isinstance(proof, NonExtensionProof):
            return self._submit_non_extension(proof)
        reason = proof.validate()
        if reason is not None:
            # Structural admissibility is free to check here; sending an
            # inadmissible pair only buys a revert and the gas that paid for it.
            raise LedgerError(f"proveEquivocation: the pair is not an equivocation: {reason}")
        calldata = encode_call(
            SELECTOR_PROVE_EQUIVOCATION,
            [
                encode_bytes32(trail_id_for(proof.chain_id)),
                encode_uint(proof.checkpoint_a.seq, bits=64),
                _signed_checkpoint(proof.checkpoint_a, proof.signature_a),
                _signed_checkpoint(proof.checkpoint_b, proof.signature_b),
            ],
        )
        return self._send("proveEquivocation", self._reader._address("bond"), calldata).tx_hash

    def _submit_non_extension(self, proof: NonExtensionProof) -> str:
        """Slash a writer whose newer head contradicts its older one at a leaf
        both trees contain. Private: `submit_fraud_proof` is the door."""
        reason = proof.validate()
        if reason is not None:
            raise LedgerError(f"proveNonExtension: the pair is not a non-extension: {reason}")
        calldata = encode_call(
            SELECTOR_PROVE_NON_EXTENSION,
            [
                encode_bytes32(trail_id_for(proof.chain_id)),
                _signed_checkpoint(proof.older, proof.older_signature),
                _signed_checkpoint(proof.newer, proof.newer_signature),
                leaf_claim(proof.in_older),
                leaf_claim(proof.in_newer),
            ],
        )
        return self._send("proveNonExtension", self._reader._address("bond"), calldata).tx_hash
