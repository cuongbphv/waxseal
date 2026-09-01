"""Tests for the receipt-frame descriptor fingerprint (SPEC.md section 19,
waxseal-fg4.9).

Mirrors tests/domain/test_fingerprint.py's own style: the fingerprint is
recomputed here from the descriptor construction directly, with raw hashlib,
so drift between this module and its own doctring is caught the same way
header-fingerprint drift is caught.
"""

import hashlib
import struct

from waxseal.domain.hashing import ENCODING
from waxseal.domain.receipt_fingerprint import (
    RECEIPT_DESCRIPTOR_PREFIX,
    RECEIPT_FRAME_FIELDS,
    receipt_fingerprint,
    receipt_fingerprint_for,
)


def u64be(n: int) -> bytes:
    return struct.pack(">Q", n)


def manual_lp(value: str) -> bytes:
    enc = value.encode("utf-8")
    return u64be(len(enc)) + enc


def manual_receipt_fingerprint(fields: tuple[str, ...]) -> str:
    components = ["sha256", "lp64", *fields]
    frame = RECEIPT_DESCRIPTOR_PREFIX + u64be(len(components))
    for c in components:
        frame += manual_lp(c)
    return hashlib.sha256(frame).hexdigest()


class TestReceiptFingerprint:
    def test_field_order_is_the_spec_order(self) -> None:
        # SPEC.md section 19: receipt_head = SHA-256(RECEIPT_FRAME_PREFIX ||
        # u64be(3) || lp(receipt_seq) || lp(prev_receipt_head) || lp(entry_hash)).
        assert RECEIPT_FRAME_FIELDS == ("receipt_seq", "prev_receipt_head", "entry_hash")

    def test_fingerprint_matches_the_descriptor_construction(self) -> None:
        assert receipt_fingerprint() == manual_receipt_fingerprint(RECEIPT_FRAME_FIELDS)

    def test_fingerprint_is_64_lowercase_hex(self) -> None:
        fp = receipt_fingerprint()
        assert len(fp) == 64
        assert fp == fp.lower()
        int(fp, 16)

    def test_widening_the_field_set_changes_the_fingerprint(self) -> None:
        # The migration-060 class made unrepresentable for the receipt frame
        # too: adding a field cannot keep the old identity.
        widened = (*RECEIPT_FRAME_FIELDS, "chain_id")
        assert receipt_fingerprint_for(widened) != receipt_fingerprint()

    def test_reordering_fields_changes_the_fingerprint(self) -> None:
        reordered = tuple(reversed(RECEIPT_FRAME_FIELDS))
        assert receipt_fingerprint_for(reordered) != receipt_fingerprint()

    def test_receipt_fingerprint_for_is_deterministic(self) -> None:
        assert receipt_fingerprint_for(RECEIPT_FRAME_FIELDS) == receipt_fingerprint_for(
            RECEIPT_FRAME_FIELDS
        )
        assert receipt_fingerprint_for(RECEIPT_FRAME_FIELDS) == receipt_fingerprint()

    def test_encoding_is_a_descriptor_component(self) -> None:
        components = ["sha256", "some-other-encoding", *RECEIPT_FRAME_FIELDS]
        frame = RECEIPT_DESCRIPTOR_PREFIX + u64be(len(components))
        for c in components:
            frame += manual_lp(c)
        assert hashlib.sha256(frame).hexdigest() != receipt_fingerprint()
        assert ENCODING == "lp64"

    def test_receipt_descriptor_prefix_is_its_own_frame_shape_name(self) -> None:
        # Constraint 2: a SEPARATE prefix from domain/fingerprint.py's
        # DESCRIPTOR_PREFIX -- coupling them would let a change to one
        # frame's descriptor silently move the other's identity.
        from waxseal.domain.fingerprint import DESCRIPTOR_PREFIX

        # Ternary Evidence Principle regression guard (CLAUDE.md item 5),
        # same shape as tests/domain/test_witnessing.py's: the two Final
        # byte-string literals are provably distinct today, which is exactly
        # why mypy flags the comparison as non-overlapping -- the assertion
        # exists to catch a future edit that collapses the two prefixes onto
        # the same bytes, not to model runtime uncertainty.
        assert RECEIPT_DESCRIPTOR_PREFIX != DESCRIPTOR_PREFIX  # type: ignore[comparison-overlap]

    def test_receipt_fingerprint_is_independent_of_the_header_fingerprint(self) -> None:
        from waxseal.domain.fingerprint import fingerprint

        assert receipt_fingerprint() != fingerprint()
