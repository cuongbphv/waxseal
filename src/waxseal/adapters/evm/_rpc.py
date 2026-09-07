"""JSON-RPC helpers for the EVM adapter. No contract types here."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final, TypeVar

from waxseal.ports.ledger import LedgerUnreachable

T = TypeVar("T")

# Two, not one. See the module docstring: one endpoint is one narrative.
MIN_ENDPOINTS: Final = 2

# JSON-RPC's "execution reverted" code, as geth defines it and anvil emits it.
# Matched alongside the message text because not every node populates `code`.
_EXECUTION_REVERTED: Final = 3

# `error TrailNotRegistered(bytes32)` — the ONE revert this adapter reads as
# a measured absence rather than as a failure to measure.
ERROR_TRAIL_NOT_REGISTERED: Final = bytes.fromhex("45ed42e1")

# A secp256k1 signature as `CheckpointCodec.recoverSigner` reads it: r‖s‖v.
# Anything else recovers address(0) on chain, which the contract reports as a
# BadWriterSignature revert after the gas is already spent.
SIGNATURE_BYTES: Final = 65


class _RpcRevert(LedgerUnreachable):
    """The contract reverted.

    A subclass of `LedgerUnreachable` so that an UNRECOGNISED revert degrades
    to "nothing was measured" by default — the safe direction — while the two
    call sites that recognise `TrailNotRegistered` catch this first and turn
    it into a measured absence. Inheriting the other way round would make
    every unhandled revert look like a successful read.
    """

    def __init__(self, message: str, data: bytes) -> None:
        super().__init__(message)
        self.data = data

    def selector(self) -> bytes:
        return self.data[:4]

def _hex_bytes(what: str, value: object) -> bytes:
    if not isinstance(value, str) or not value.startswith("0x"):
        raise LedgerUnreachable(f"{what}: the node returned {value!r}, which is not 0x-hex")
    try:
        return bytes.fromhex(value[2:])
    except ValueError as exc:
        raise LedgerUnreachable(f"{what}: the node returned {value!r}, which is not hex") from exc


def _hex_int(what: str, value: object) -> int:
    if not isinstance(value, str):
        raise LedgerUnreachable(f"{what}: the node returned {value!r}, which is not a quantity")
    try:
        return int(value, 16)
    except ValueError as exc:
        raise LedgerUnreachable(f"{what}: the node returned {value!r}, not a hex quantity") from exc


def _rpc_failure(what: str, error: object) -> LedgerUnreachable:
    """Turn a JSON-RPC `error` member into the right exception.

    An execution revert is the contract SPEAKING; everything else (rate
    limits, bad params, a node that has not synced the block tag) is the node
    failing to answer. Collapsing the two would make a contract's designed
    three-valued reply indistinguishable from an outage.
    """
    if not isinstance(error, Mapping):
        return LedgerUnreachable(f"{what}: the node returned a malformed error member {error!r}")
    message = str(error.get("message", error))
    if error.get("code") == _EXECUTION_REVERTED or "execution reverted" in message.lower():
        raw = _revert_data(error.get("data"))
        return _RpcRevert(f"{what}: reverted ({_selector_text(raw)}): {message}", raw)
    return LedgerUnreachable(f"{what}: {message}")


def _revert_data(value: object) -> bytes:
    """The ABI-encoded revert payload, or empty when there is none to read.

    Empty rather than an exception: a node that reverts without carrying the
    custom error's bytes (some proxies strip them) has still reverted, and
    the caller's decision — is this the one revert we recognise? — is simply
    "no" in that case. Losing the whole answer over a missing detail would be
    the larger error.
    """
    if not isinstance(value, str) or not value.startswith("0x"):
        return b""
    try:
        return bytes.fromhex(value[2:])
    except ValueError:
        return b""


def _selector_text(raw: bytes) -> str:
    return f"custom error 0x{raw[:4].hex()}" if raw else "no revert data"


def _nonempty(what: str, raw: bytes) -> bytes:
    """Guard the "no contract at that address" case.

    `eth_call` against an address holding no code returns `0x` — a SUCCESS
    with an empty body, not a revert. Decoding that yields zero words, and a
    zero-word answer read as "the trail holds nothing" would report a typo in
    a `--liveness` flag as a measured fact about the writer.
    """
    if not raw:
        raise LedgerUnreachable(
            f"{what}: the call returned no data at all — no contract at that address, "
            "or the node has no state at this block tag"
        )
    return raw
