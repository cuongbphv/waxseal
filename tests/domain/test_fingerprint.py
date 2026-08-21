"""Tests for the schema fingerprint (SPEC.md section 4).

The v1 fingerprint is recomputed here from the SPEC prose with raw hashlib —
if the implementation drifts from the SPEC, this fails.
"""

import hashlib
import struct

from waxseal.domain.fingerprint import HEADER_V1_FIELDS, fingerprint_for, fingerprint_v1


def u64be(n: int) -> bytes:
    return struct.pack(">Q", n)


def manual_lp(value: str) -> bytes:
    enc = value.encode("utf-8")
    return u64be(len(enc)) + enc


def manual_fingerprint(fields: tuple[str, ...]) -> str:
    components = ["sha256", "lp64v1", *fields]
    frame = b"waxseal-descriptor-v1\n" + u64be(len(components))
    for c in components:
        frame += manual_lp(c)
    return hashlib.sha256(frame).hexdigest()


class TestFingerprint:
    def test_v1_field_order_is_the_spec_order(self) -> None:
        assert HEADER_V1_FIELDS == (
            "seq",
            "ts",
            "hash_version",
            "payload_type",
            "payload_hash",
            "prev_hash",
        )

    def test_v1_fingerprint_matches_spec_prose(self) -> None:
        assert fingerprint_v1() == manual_fingerprint(HEADER_V1_FIELDS)

    def test_fingerprint_is_64_lowercase_hex(self) -> None:
        fp = fingerprint_v1()
        assert len(fp) == 64
        assert fp == fp.lower()
        int(fp, 16)

    def test_widening_the_field_set_changes_the_fingerprint(self) -> None:
        # This is the migration-060 class of bug made unrepresentable: adding a
        # field CANNOT keep the old identity.
        widened = (*HEADER_V1_FIELDS, "redaction_version")
        assert fingerprint_for(widened) != fingerprint_v1()

    def test_reordering_fields_changes_the_fingerprint(self) -> None:
        reordered = tuple(reversed(HEADER_V1_FIELDS))
        assert fingerprint_for(reordered) != fingerprint_v1()

    def test_fingerprint_for_is_deterministic(self) -> None:
        assert fingerprint_for(HEADER_V1_FIELDS) == fingerprint_for(HEADER_V1_FIELDS)
        assert fingerprint_for(HEADER_V1_FIELDS) == fingerprint_v1()
