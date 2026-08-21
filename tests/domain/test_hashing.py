"""Tests for lp64v1 canonical encoding and entry hashing (SPEC.md sections 2-3).

Expected values are computed here with raw hashlib/struct, straight from the SPEC
prose — deliberately NOT via waxseal helpers, so a drift between SPEC and
implementation fails loudly.
"""

import hashlib
import struct

from waxseal.domain.hashing import NULL, compute_entry_hash, header_frame, lp
from waxseal.domain.header import EntryHeader

GENESIS = "0" * 64


def u64be(n: int) -> bytes:
    return struct.pack(">Q", n)


def manual_lp(value: str | None) -> bytes:
    enc = b"\x00NULL\x00" if value is None else value.encode("utf-8")
    return u64be(len(enc)) + enc


def make_header(**overrides: object) -> EntryHeader:
    fields: dict = {
        "seq": 0,
        "ts": "2026-08-21T06:00:00+00:00",
        "hash_version": "a" * 64,
        "payload_type": "application/vnd.test.event+json",
        "payload_hash": hashlib.sha256(b"{}").hexdigest(),
        "prev_hash": GENESIS,
    }
    fields.update(overrides)
    return EntryHeader(**fields)


class TestLp:
    def test_string_is_length_prefixed_utf8(self) -> None:
        assert lp("abc") == u64be(3) + b"abc"

    def test_empty_string_is_eight_zero_bytes(self) -> None:
        assert lp("") == u64be(0)

    def test_null_sentinel_distinct_from_empty_string(self) -> None:
        assert lp(NULL) == u64be(6) + b"\x00NULL\x00"
        assert lp(NULL) != lp("")

    def test_non_ascii_uses_utf8_byte_length(self) -> None:
        # "Việt" is 4 codepooints but 6 UTF-8 bytes; prefix must count bytes.
        assert lp("Việt") == u64be(6) + "Việt".encode()


class TestHeaderFrame:
    def test_frame_matches_spec_prose_byte_for_byte(self) -> None:
        h = make_header()
        expected = (
            b"waxseal-v1\n"
            + u64be(6)
            + manual_lp("0")
            + manual_lp("2026-08-21T06:00:00+00:00")
            + manual_lp("a" * 64)
            + manual_lp("application/vnd.test.event+json")
            + manual_lp(hashlib.sha256(b"{}").hexdigest())
            + manual_lp(GENESIS)
        )
        assert header_frame(h) == expected

    def test_seq_encoded_as_decimal_string(self) -> None:
        frame = header_frame(make_header(seq=1234))
        assert manual_lp("1234") in frame


class TestComputeEntryHash:
    def test_hash_is_sha256_of_frame_lowercase_hex(self) -> None:
        h = make_header()
        assert compute_entry_hash(h) == hashlib.sha256(header_frame(h)).hexdigest()

    def test_any_single_field_change_changes_hash(self) -> None:
        base = compute_entry_hash(make_header())
        variants = [
            make_header(seq=1),
            make_header(ts="2026-08-21T06:00:01+00:00"),
            make_header(hash_version="b" * 64),
            make_header(payload_type="application/vnd.other+json"),
            make_header(payload_hash=hashlib.sha256(b"x").hexdigest()),
            make_header(prev_hash="f" * 64),
        ]
        hashes = {compute_entry_hash(v) for v in variants}
        assert base not in hashes
        assert len(hashes) == len(variants)

    def test_field_boundary_shifts_cannot_collide(self) -> None:
        # Length-prefixing exists to prevent exactly this: moving a character
        # across a field boundary must change the hash.
        a = make_header(payload_type="ab", ts="2026-08-21T06:00:00+00:00")
        b = make_header(payload_type="b", ts="2026-08-21T06:00:00+00:00a")
        assert compute_entry_hash(a) != compute_entry_hash(b)
