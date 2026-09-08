"""Property-based tests (hypothesis) for the encoding and chain invariants."""

import string
import struct
from dataclasses import replace

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from tests.domain.test_verify import build_chain
from waxseal.domain.fingerprint import fingerprint_for
from waxseal.domain.hashing import NULL, LpEncodingError, compute_entry_hash, lp
from waxseal.domain.header import EntryHeader
from waxseal.domain.registry import VersionRegistry
from waxseal.domain.verify import verify_chain

field_text = st.text(min_size=0, max_size=50)
name_text = st.text(alphabet=string.ascii_lowercase + "_", min_size=1, max_size=20)


@given(a=field_text, b=field_text)
def test_lp_concatenation_is_injective(a: str, b: str) -> None:
    # (a, b) and (a+b, "") etc. must never encode alike — the property
    # length-prefixing exists to guarantee.
    if a != b:
        assert lp(a) != lp(b)
    for split in range(len(a) + 1):
        left, right = a[:split], a[split:]
        if (left, right) != (a, b) and lp(left) + lp(right) == lp(a) + lp(b):
            raise AssertionError(f"collision: {(left, right)!r} vs {(a, b)!r}")


@given(fields=st.lists(name_text, min_size=1, max_size=8, unique=True))
def test_fingerprint_unique_per_field_tuple(fields: list[str]) -> None:
    base = tuple(fields)
    assert fingerprint_for(base) == fingerprint_for(base)
    widened = (*base, "extra_field_zz")
    assert fingerprint_for(widened) != fingerprint_for(base)


@given(
    ts=field_text,
    payload_type=field_text,
    seq=st.integers(min_value=0, max_value=2**40),
)
def test_entry_hash_is_deterministic_and_hex(ts: str, payload_type: str, seq: int) -> None:
    header = EntryHeader(
        seq=seq,
        ts=ts,
        hash_version="a" * 64,
        payload_type=payload_type,
        payload_hash="b" * 64,
        prev_hash="0" * 64,
    )
    h1, h2 = compute_entry_hash(header), compute_entry_hash(header)
    assert h1 == h2
    assert len(h1) == 64
    int(h1, 16)


@settings(max_examples=25)
@given(n=st.integers(min_value=1, max_value=8), data=st.data())
def test_any_single_payload_tamper_is_detected(n: int, data: st.DataObject) -> None:
    chain = build_chain(n)
    victim = data.draw(st.integers(min_value=0, max_value=n - 1))
    # build_chain() always constructs a bytes payload; Entry.payload is typed
    # `bytes | None` only because a redacted entry stores none (CLAUDE.md
    # "redact-before-hash"), which never applies to this fixture.
    victim_payload = chain[victim].payload
    assert victim_payload is not None
    chain[victim] = replace(chain[victim], payload=victim_payload + b"x")
    result = verify_chain(chain, VersionRegistry())
    assert not result.ok
    assert result.broken_seq == victim


# --- Unconditional injectivity of lp (SPEC section 2) ------------------------
#
# The absent marker is encoded with a leading 0x00 tag and every string with a
# leading 0x01, so the two differ before any content does. There is no sentinel
# to collide with, no side condition, and no input lp has to reject.
#
# This is the closed form of finding F1. The superseded lp64v1 encoded absent
# as the six bytes b"\x00NULL\x00", which are themselves valid UTF-8 -- so the
# one string equal to that sequence encoded identically to absent, and lp64v1's
# injectivity silently depended on "no field ever carries that string". The
# encoding chosen to keep *absent* and *empty* apart conflated *absent* with one
# specific *present* value. lp64v1 was retired in 0.1.4; the tests below assert
# the property that made retiring it worthwhile.
#
# Lone (unpaired) UTF-16 surrogates are excluded from THIS generator on
# purpose: they are valid Python str characters but have no UTF-8
# representation at all, so `value.encode("utf-8")` raises before lp can
# produce any bytes to compare against another encoding -- they are not a
# collision case, they are a different documented behaviour of lp(), covered
# separately below (test_lone_surrogate_raises_named_encoding_error, closing
# gap G4 of docs/paper/conformance.md).
_utf8_text = st.text(alphabet=st.characters(codec="utf-8"), min_size=0, max_size=40)

# A lone surrogate: a Python str character with no UTF-8 representation at
# all (gap G4). st.characters(codec="utf-8") above cannot produce these --
# that exclusion is deliberate, not an oversight -- so they need their own
# strategy, built directly from the codepoint range.
_lone_surrogate_char = st.characters(min_codepoint=0xD800, max_codepoint=0xDFFF)

# A lone surrogate is unencodable wherever it sits in the string, not only
# when it is the whole string -- surround it with ordinary UTF-8-safe text on
# both sides to pin that down.
_text_with_lone_surrogate = st.builds(
    lambda pre, c, post: pre + c + post,
    pre=_utf8_text,
    c=_lone_surrogate_char,
    post=_utf8_text,
)

# Strings around the shape lp64v1's sentinel used to have. None of them is
# special any more -- that is precisely the point of asserting it.
_former_sentinel_shapes = st.sampled_from(
    [
        "\x00NULL\x00",
        "\x00NULL\x00x",
        "x\x00NULL\x00",
        "\x00",
        "NULL",
        "\x00NULL",
        "NULL\x00",
        "\x00null\x00",
        "",
    ]
)


@settings(max_examples=100)
@given(s=st.one_of(_utf8_text, _former_sentinel_shapes))
def test_no_string_encodes_like_the_absent_marker(s: str) -> None:
    assert lp(NULL) != lp(s)


@settings(max_examples=100)
@given(
    a=st.one_of(_utf8_text, _former_sentinel_shapes),
    b=st.one_of(_utf8_text, _former_sentinel_shapes),
)
def test_distinct_strings_never_encode_alike(a: str, b: str) -> None:
    if a != b:
        assert lp(a) != lp(b)


def test_absent_marker_byte_value() -> None:
    assert lp(NULL) == struct.pack(">Q", 1) + b"\x00"


def test_empty_string_byte_value_is_distinct_from_absent() -> None:
    assert lp("") == struct.pack(">Q", 1) + b"\x01"
    assert lp("") != lp(NULL)


# --- lp() on a string UTF-8 cannot encode (gap G4) ---------------------------
#
# Python str permits lone (unpaired) UTF-16 surrogates (U+D800-U+DFFF); UTF-8
# has no representation for them. Before this test existed, lp("\ud800") let
# a bare stdlib UnicodeEncodeError escape -- an unlabelled error, not a
# waxseal-domain verdict, in a library whose own rule (CLAUDE.md rule 6/9) is
# that a failure must be labelled, never left to leak the wrong error type.
# The decision this test pins down: lp() raises LpEncodingError, named and
# chained from the original UnicodeEncodeError, for every such input.
@settings(max_examples=50)
@given(s=st.one_of(_lone_surrogate_char, _text_with_lone_surrogate))
def test_lone_surrogate_raises_named_encoding_error(s: str) -> None:
    with pytest.raises(LpEncodingError) as exc_info:
        lp(s)
    assert isinstance(exc_info.value.__cause__, UnicodeEncodeError)
