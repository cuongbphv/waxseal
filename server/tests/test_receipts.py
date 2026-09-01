"""The server-side receipt chain (REMOTE.md section 10, frame in SPEC.md section 19).

The expected bytes here are built from the specification prose with `struct`,
NOT by calling the code under test or importing `waxseal.domain.hashing` — the
same cross-check discipline `tools/gen_*_vectors.py` applies to the golden
vectors. A frame suite only ever checked against the implementation it came
from checks nothing.
"""

from __future__ import annotations

import hashlib
import struct

import pytest
from waxseal_server.domain.receipts import (
    RECEIPT_FRAME_PREFIX,
    RECEIPT_GENESIS,
    ReceiptChain,
    receipt_head,
)


def _lp(value: str) -> bytes:
    """SPEC.md section 2: 8-byte big-endian length over `0x01` + UTF-8."""
    enc = b"\x01" + value.encode("utf-8")
    return struct.pack(">Q", len(enc)) + enc


def _spec_receipt_head(receipt_seq: int, prev_receipt_head: str, entry_hash: str) -> str:
    frame = (
        RECEIPT_FRAME_PREFIX
        + struct.pack(">Q", 3)
        + _lp(str(receipt_seq))
        + _lp(prev_receipt_head)
        + _lp(entry_hash)
    )
    return hashlib.sha256(frame).hexdigest()


class TestReceiptFrame:
    def test_prefix_and_genesis_are_the_spec_constants(self) -> None:
        assert RECEIPT_FRAME_PREFIX == b"waxseal-receipt-v1\n"
        assert RECEIPT_GENESIS == "0" * 64

    def test_first_receipt_hashes_the_spec_frame(self) -> None:
        entry_hash = "aa" * 32
        assert receipt_head(0, RECEIPT_GENESIS, entry_hash) == _spec_receipt_head(
            0, RECEIPT_GENESIS, entry_hash
        )

    def test_later_receipt_chains_on_the_previous_head(self) -> None:
        first = receipt_head(0, RECEIPT_GENESIS, "aa" * 32)
        assert receipt_head(1, first, "bb" * 32) == _spec_receipt_head(1, first, "bb" * 32)

    def test_head_is_lowercase_hex64(self) -> None:
        head = receipt_head(0, RECEIPT_GENESIS, "aa" * 32)
        assert len(head) == 64
        assert head == head.lower()
        int(head, 16)

    def test_a_different_entry_hash_gives_a_different_head(self) -> None:
        assert receipt_head(0, RECEIPT_GENESIS, "aa" * 32) != receipt_head(
            0, RECEIPT_GENESIS, "ab" * 32
        )

    def test_a_different_seq_gives_a_different_head(self) -> None:
        assert receipt_head(0, RECEIPT_GENESIS, "aa" * 32) != receipt_head(
            1, RECEIPT_GENESIS, "aa" * 32
        )


class TestReceiptChain:
    def test_a_fresh_chain_has_no_head(self) -> None:
        assert ReceiptChain().head() is None

    def test_first_acknowledgement_is_receipt_seq_zero(self) -> None:
        chain = ReceiptChain()
        assert chain.acknowledge("aa" * 32) == (0, receipt_head(0, RECEIPT_GENESIS, "aa" * 32))

    def test_receipt_seq_increments_per_acknowledgement(self) -> None:
        chain = ReceiptChain()
        chain.acknowledge("aa" * 32)
        seq, _ = chain.acknowledge("bb" * 32)
        assert seq == 1

    def test_head_reports_the_last_acknowledgement(self) -> None:
        chain = ReceiptChain()
        chain.acknowledge("aa" * 32)
        expected = chain.acknowledge("bb" * 32)
        assert chain.head() == expected

    def test_acknowledging_the_same_entry_hash_twice_still_advances(self) -> None:
        # Two appends of the same entry_hash cannot happen on one chain, but the
        # receipt chain is a log of acknowledgements, not a set: it must never
        # collapse two acknowledgements into one.
        chain = ReceiptChain()
        first = chain.acknowledge("aa" * 32)
        second = chain.acknowledge("aa" * 32)
        assert second[0] == first[0] + 1
        assert second[1] != first[1]

    @pytest.mark.parametrize("bad", ["", "xy" * 32, "aa" * 31, "AA" * 32])
    def test_acknowledge_rejects_a_hash_that_is_not_lowercase_hex64(self, bad: str) -> None:
        with pytest.raises(ValueError):
            ReceiptChain().acknowledge(bad)


class TestResume:
    """Restart continues the chain from its last line, not from a full replay.

    A server that replays its whole receipt log on every append pays O(n) per
    acknowledgment and O(n^2) over a chain's life — the accumulation this
    release exists partly to remove from the library itself.
    """

    def test_resume_reports_the_head_it_was_given(self) -> None:
        head = receipt_head(0, RECEIPT_GENESIS, "aa" * 32)
        assert ReceiptChain.resume(0, head).head() == (0, head)

    def test_resuming_then_acknowledging_matches_an_unbroken_chain(self) -> None:
        unbroken = ReceiptChain()
        unbroken.acknowledge("aa" * 32)
        expected = unbroken.acknowledge("bb" * 32)

        resumed = ReceiptChain.resume(0, receipt_head(0, RECEIPT_GENESIS, "aa" * 32))
        assert resumed.acknowledge("bb" * 32) == expected

    def test_resume_rejects_a_head_that_is_not_hex64(self) -> None:
        with pytest.raises(ValueError):
            ReceiptChain.resume(0, "nope")

    def test_resume_rejects_a_negative_receipt_seq(self) -> None:
        with pytest.raises(ValueError):
            ReceiptChain.resume(-1, RECEIPT_GENESIS)
