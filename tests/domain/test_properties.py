"""Property-based tests (hypothesis) for the encoding and chain invariants."""

import string
from dataclasses import replace

from hypothesis import given, settings
from hypothesis import strategies as st

from tests.domain.test_verify import build_chain
from waxseal.domain.fingerprint import fingerprint_for
from waxseal.domain.hashing import compute_entry_hash, lp
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
    chain[victim] = replace(chain[victim], payload=chain[victim].payload + b"x")
    result = verify_chain(chain, VersionRegistry())
    assert not result.ok
    assert result.broken_seq == victim
