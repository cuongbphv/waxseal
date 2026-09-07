"""EVM adapter package. Public names stay on `waxseal.adapters.evm`.

The read-path contract (two endpoints, revert as measured absence) lives
on `reader.py`. Submodules never import this package barrel.
"""

from __future__ import annotations

from waxseal.adapters.evm._rpc import ERROR_TRAIL_NOT_REGISTERED, MIN_ENDPOINTS
from waxseal.adapters.evm.anchor import EvmAnchorSink
from waxseal.adapters.evm.contracts import (
    SELECTOR_SUBMIT_HEAD,
    EvmContracts,
    EvmTxReceipt,
    leaf_claim,
)
from waxseal.adapters.evm.reader import EvmLedgerReader
from waxseal.adapters.evm.sink import EvmLedgerSink

__all__ = (
    "ERROR_TRAIL_NOT_REGISTERED",
    "EvmAnchorSink",
    "EvmContracts",
    "EvmLedgerReader",
    "EvmLedgerSink",
    "EvmTxReceipt",
    "MIN_ENDPOINTS",
    "SELECTOR_SUBMIT_HEAD",
    "leaf_claim",
)
