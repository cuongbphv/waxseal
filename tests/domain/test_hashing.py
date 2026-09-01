"""Tests for the lp64 canonical encoding and entry hashing (SPEC.md sections 2-3).

Expected values are computed here with raw hashlib/struct, straight from the SPEC
prose — deliberately NOT via waxseal helpers, so a drift between SPEC and
implementation fails loudly.
"""

import hashlib
import struct
from typing import Any

from waxseal.domain.hashing import NULL, compute_entry_hash, header_frame, lp
from waxseal.domain.header import EntryHeader

GENESIS = "0" * 64


def u64be(n: int) -> bytes:
    return struct.pack(">Q", n)


def manual_lp(value: str | None) -> bytes:
    """SPEC section 2, re-implemented from the prose: a type tag inside the
    length-prefixed region — 0x00 for absent, 0x01 before a string's UTF-8."""
    enc = b"\x00" if value is None else b"\x01" + value.encode("utf-8")
    return u64be(len(enc)) + enc


def make_header(**overrides: object) -> EntryHeader:
    fields: dict[str, Any] = {
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
    def test_string_is_tagged_and_length_prefixed(self) -> None:
        assert lp("abc") == u64be(4) + b"\x01abc"

    def test_empty_string_is_the_tag_alone(self) -> None:
        assert lp("") == u64be(1) + b"\x01"

    def test_absent_is_the_zero_tag(self) -> None:
        assert lp(NULL) == u64be(1) + b"\x00"

    def test_absent_and_empty_never_encode_alike(self) -> None:
        assert lp(NULL) != lp("")

    def test_non_ascii_is_utf8(self) -> None:
        assert lp("Việt") == manual_lp("Việt")

    def test_matches_spec_prose_for_every_example(self) -> None:
        for value in ("abc", "", "Việt", "\x00", "NULL", "\x00NULL\x00"):
            assert lp(value) == manual_lp(value), value

    def test_no_string_can_collide_with_absent(self) -> None:
        # Unconditional injectivity: the tag byte differs before any content
        # does, so there is no invariant to maintain and no input to reject.
        # (lp64v1 encoded absent as a sentinel that was itself valid UTF-8 —
        # exactly one string collided with it. That is finding F1, and this
        # assertion is what makes it unconstructible rather than unlikely.)
        for value in ("", "\x00", "NULL", "\x00NULL\x00", "\x00NULL\x00x"):
            assert lp(NULL) != lp(value), value


class TestHeaderFrame:
    def test_frame_matches_spec_prose_byte_for_byte(self) -> None:
        h = make_header()
        expected = (
            b"waxseal-lp64\n"
            + u64be(6)
            + manual_lp("0")
            + manual_lp(h.ts)
            + manual_lp(h.hash_version)
            + manual_lp(h.payload_type)
            + manual_lp(h.payload_hash)
            + manual_lp(h.prev_hash)
        )
        assert header_frame(h) == expected

    def test_seq_encoded_as_decimal_string(self) -> None:
        frame = header_frame(make_header(seq=1234))
        assert manual_lp("1234") in frame

    def test_prefix_domain_separates_the_frame(self) -> None:
        assert header_frame(make_header()).startswith(b"waxseal-lp64\n")


class TestComputeEntryHash:
    def test_hash_is_sha256_of_frame_lowercase_hex(self) -> None:
        h = make_header()
        assert compute_entry_hash(h) == hashlib.sha256(header_frame(h)).hexdigest()

    def test_every_header_field_is_covered(self) -> None:
        base = compute_entry_hash(make_header())
        variants = [
            make_header(seq=1),
            make_header(ts="2026-08-21T06:00:01+00:00"),
            make_header(hash_version="b" * 64),
            make_header(payload_type="application/vnd.other+json"),
            make_header(payload_hash="c" * 64),
            make_header(prev_hash="d" * 64),
        ]
        hashes = {compute_entry_hash(v) for v in variants}
        assert base not in hashes
        assert len(hashes) == len(variants)

    def test_explicit_frame_argument_is_honoured(self) -> None:
        # The parameter exists so a verifier can pass the frame the row's own
        # fingerprint names (VersionRegistry.encoder_for), rather than
        # assuming whatever this build implements.
        h = make_header()
        assert compute_entry_hash(h, frame=header_frame) == compute_entry_hash(h)
        assert compute_entry_hash(h, frame=lambda _: b"other") == (
            hashlib.sha256(b"other").hexdigest()
        )
