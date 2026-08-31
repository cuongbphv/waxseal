"""The server's receipt chain — REMOTE.md section 10, frame in SPEC.md section 19.

A receipt chain is a running hash over the entries this server has acknowledged,
in acknowledgment order. It exists so the server is bound by its own answers: it
cannot later re-tell the history of what it accepted without the retelling being
visible to anyone who kept a receipt.

`lp` is imported from the library rather than restated here. The encoding is
frozen by SPEC.md section 2 and the golden vectors, and a second copy of it in
this repository is a second thing that can drift from the frame the client will
verify against.
"""

from __future__ import annotations

import hashlib
import struct
from typing import Final

from waxseal.domain.hashing import lp

RECEIPT_FRAME_PREFIX: Final = b"waxseal-receipt-v1\n"
RECEIPT_GENESIS: Final = "0" * 64

_HEX64 = frozenset("0123456789abcdef")


def _require_hex64(value: str, label: str) -> str:
    if len(value) != 64 or not set(value) <= _HEX64:
        raise ValueError(f"{label} must be 64 lowercase hex characters, got {value!r}")
    return value


def receipt_head(receipt_seq: int, prev_receipt_head: str, entry_hash: str) -> str:
    """One link of the receipt chain (SPEC.md section 19)."""
    frame = (
        RECEIPT_FRAME_PREFIX
        + struct.pack(">Q", 3)
        + lp(str(receipt_seq))
        + lp(prev_receipt_head)
        + lp(entry_hash)
    )
    return hashlib.sha256(frame).hexdigest()


class ReceiptChain:
    """Append-only acknowledgment log for one `chain_id`.

    Deliberately not a set: two acknowledgments of the same `entry_hash` are two
    receipts. Collapsing them would let the server answer one `receipt_seq` with
    two different heads later, which is the one thing REMOTE.md section 10
    forbids.
    """

    __slots__ = ("_head", "_seq")

    def __init__(self) -> None:
        self._seq = -1
        self._head = RECEIPT_GENESIS

    @classmethod
    def resume(cls, receipt_seq: int, head: str) -> ReceiptChain:
        """Continue a chain from its last issued link.

        A server restores state from the last line of its receipt log rather
        than replaying the whole log, so an acknowledgment costs the same on
        entry one and entry one million.
        """
        if receipt_seq < 0:
            raise ValueError(f"receipt_seq must be non-negative, got {receipt_seq}")
        chain = cls()
        chain._seq = receipt_seq
        chain._head = _require_hex64(head, "head")
        return chain

    def acknowledge(self, entry_hash: str) -> tuple[int, str]:
        _require_hex64(entry_hash, "entry_hash")
        next_seq = self._seq + 1
        self._head = receipt_head(next_seq, self._head, entry_hash)
        self._seq = next_seq
        return next_seq, self._head

    def head(self) -> tuple[int, str] | None:
        """The current head, or None when nothing has been acknowledged yet.

        None is "no receipts", which REMOTE.md section 10 renders as 404 — not
        an error, and never the same as a receipt at seq 0.
        """
        if self._seq < 0:
            return None
        return self._seq, self._head
