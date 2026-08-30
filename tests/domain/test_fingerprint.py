"""Tests for the schema fingerprint (SPEC.md section 4).

The fingerprint is recomputed here from the SPEC prose with raw hashlib — if
the implementation drifts from the SPEC, this fails.
"""

import hashlib
import struct

from waxseal.domain.fingerprint import HEADER_FIELDS, fingerprint, fingerprint_for
from waxseal.domain.hashing import ENCODING


def u64be(n: int) -> bytes:
    return struct.pack(">Q", n)


def manual_lp(value: str) -> bytes:
    """The DESCRIPTOR frame's length prefix (SPEC section 4) — untagged, and
    deliberately not the same function as the header frame's (section 2)."""
    enc = value.encode("utf-8")
    return u64be(len(enc)) + enc


def manual_fingerprint(fields: tuple[str, ...]) -> str:
    components = ["sha256", "lp64", *fields]
    frame = b"waxseal-descriptor-v1\n" + u64be(len(components))
    for c in components:
        frame += manual_lp(c)
    return hashlib.sha256(frame).hexdigest()


class TestFingerprint:
    def test_field_order_is_the_spec_order(self) -> None:
        assert HEADER_FIELDS == (
            "seq",
            "ts",
            "hash_version",
            "payload_type",
            "payload_hash",
            "prev_hash",
        )

    def test_fingerprint_matches_spec_prose(self) -> None:
        assert fingerprint() == manual_fingerprint(HEADER_FIELDS)

    def test_fingerprint_is_64_lowercase_hex(self) -> None:
        fp = fingerprint()
        assert len(fp) == 64
        assert fp == fp.lower()
        int(fp, 16)

    def test_widening_the_field_set_changes_the_fingerprint(self) -> None:
        # This is the migration-060 class of bug made unrepresentable: adding a
        # field CANNOT keep the old identity.
        widened = (*HEADER_FIELDS, "redaction_version")
        assert fingerprint_for(widened) != fingerprint()

    def test_reordering_fields_changes_the_fingerprint(self) -> None:
        reordered = tuple(reversed(HEADER_FIELDS))
        assert fingerprint_for(reordered) != fingerprint()

    def test_fingerprint_for_is_deterministic(self) -> None:
        assert fingerprint_for(HEADER_FIELDS) == fingerprint_for(HEADER_FIELDS)
        assert fingerprint_for(HEADER_FIELDS) == fingerprint()

    def test_encoding_is_a_descriptor_component(self) -> None:
        # The reason changing the encoding cannot keep the old identity: the
        # encoding name is hashed into the descriptor alongside the fields.
        # Recompute with a different encoding name and the fingerprint moves,
        # with no migration and no in-place edit of any released meaning.
        components = ["sha256", "some-other-encoding", *HEADER_FIELDS]
        frame = b"waxseal-descriptor-v1\n" + u64be(len(components))
        for c in components:
            frame += manual_lp(c)
        assert hashlib.sha256(frame).hexdigest() != fingerprint()
        assert ENCODING == "lp64"
