"""Deployed addresses, receipts, and ABI blobs for the EVM adapter."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from waxseal.domain.abi import (
    SELECTOR_SUBMIT,
    WORD,
    Dynamic,
    encode_bytes,
    encode_bytes32,
    encode_bytes32_array,
    encode_uint,
)
from waxseal.domain.bond import DivergentLeaf
from waxseal.domain.checkpoint import Checkpoint

# ---------------------------------------------------------------- selectors
#
# NOT frozen here. Every function selector is frozen ONCE, in domain/abi.py,
# whose whole table is cross-checked against `cast sig` and against
# `forge inspect`'s own output (tests/domain/test_abi.py). This module kept
# its own copies of five of them through 0.1.5, from a period when the domain
# table really did describe an earlier contract draft; waxseal-fg4.40
# corrected the table and the copies outlived their reason, leaving two
# hand-maintained lists of the same constants — the exact shape that let six
# selectors drift through every green gate the first time.
# tests/architecture/test_invariants.py::TestSelectorsAreFrozenInOnePlace
# pins the single owner.
#
# Only the alias is local: `SELECTOR_SUBMIT_HEAD` says which of the two
# `submit`-shaped calls in this file is meant, at the call site.
SELECTOR_SUBMIT_HEAD: Final = SELECTOR_SUBMIT

@dataclass(frozen=True, slots=True)
class EvmContracts:
    """Deployed addresses. Each is optional because an operator may run the
    liveness contract without a registry, or a registry without a bond."""

    liveness: str | None = None
    registry: str | None = None
    bond: str | None = None


@dataclass(frozen=True, slots=True)
class EvmTxReceipt:
    """A mined, confirmed transaction."""

    tx_hash: str
    block_number: int
    chain_id: int

    def anchor_receipt(self) -> str:
        """`evm:<chainid>:<block>:<txhash>` — the receipt string an
        `.anchors` sidecar records, chosen so an operator can re-derive the
        transaction from the receipt alone without a lookup table."""
        return f"evm:{self.chain_id}:{self.block_number}:{self.tx_hash}"


def leaf_claim(leaf: DivergentLeaf) -> Dynamic:
    """`BondedCheckpoints.LeafClaim` as one ABI tail blob.

    Was a dataclass of its own here through 0.1.5, holding the same three
    fields as `domain/bond.DivergentLeaf` because the domain type did not
    exist yet: the adapter owned both the wire shape AND the evidence. Only
    the shape was ever the adapter's — whether two of these contradict each
    other is RFC 9162 arithmetic, which now lives in domain and is checked
    there before any gas is spent.
    """
    return Dynamic(
        encode_uint(leaf.index)
        + encode_bytes32(leaf.entry_hash)
        + encode_uint(3 * WORD)
        + bytes(encode_bytes32_array(leaf.proof))
    )


def _signed_checkpoint(checkpoint: Checkpoint, signature: bytes) -> Dynamic:
    """`BondedCheckpoints.SignedCheckpoint` as one ABI tail blob.

    A struct with a dynamic member is itself dynamic, so it contributes an
    offset to the head and this whole blob to the tail — which is exactly
    what `Dynamic` already means to `encode_call`. Building it as a blob
    rather than teaching the encoder about tuples keeps `domain/abi.py`
    untouched and keeps the offset arithmetic in one place.
    """
    return Dynamic(
        encode_uint(checkpoint.seq, bits=64)
        + encode_bytes32(checkpoint.entry_hash)
        + encode_bytes32(checkpoint.root)
        + encode_uint(4 * WORD)
        + bytes(encode_bytes(signature))
    )
