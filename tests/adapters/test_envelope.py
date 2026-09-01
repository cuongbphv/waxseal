"""Tests for the shared envelope serialization (SPEC.md section 7).

Extracted from jsonl.py + s3.py, which had this {header, entry_hash,
payload_b64} shape copy-pasted; these tests are the byte-identity guard for
that extraction — jsonl.py/test_jsonl.py and s3.py/test_s3.py keep asserting
the same line/object layout independently, so a regression here would also
break there.
"""

import base64

import pytest

from tests.adapters.test_jsonl import build_entry
from waxseal.adapters._envelope import entry_from_fields, from_obj, to_obj
from waxseal.domain.header import Entry

GENESIS = "0" * 64


class TestToObj:
    def test_shape_matches_spec_envelope(self) -> None:
        entry = build_entry(0, GENESIS, b'{"a":1}')
        obj = to_obj(entry, backend="test")
        assert set(obj) == {"header", "entry_hash", "payload_b64"}
        assert set(obj["header"]) == {
            "seq",
            "ts",
            "hash_version",
            "payload_type",
            "payload_hash",
            "prev_hash",
        }
        assert obj["header"]["seq"] == 0
        assert obj["entry_hash"] == entry.entry_hash
        assert base64.b64decode(obj["payload_b64"]) == b'{"a":1}'

    def test_rejects_none_payload_naming_the_backend(self) -> None:
        entry = build_entry(0, GENESIS)
        headerless = Entry(header=entry.header, entry_hash=entry.entry_hash, payload=None)
        with pytest.raises(ValueError, match="mybackend.*payload"):
            to_obj(headerless, backend="mybackend")


class TestRoundTrip:
    def test_from_obj_reverses_to_obj(self) -> None:
        entry = build_entry(3, "a" * 64, b"hello world")
        assert from_obj(to_obj(entry, backend="test")) == entry

    def test_round_trip_preserves_binary_payload(self) -> None:
        entry = build_entry(1, GENESIS, bytes(range(256)))
        assert from_obj(to_obj(entry, backend="test")).payload == entry.payload


class TestEntryFromFields:
    def test_reconstructs_entry_from_flat_fields(self) -> None:
        entry = build_entry(5, "b" * 64, b"payload bytes")
        assert entry.payload is not None
        reconstructed = entry_from_fields(
            seq=entry.header.seq,
            ts=entry.header.ts,
            hash_version=entry.header.hash_version,
            payload_type=entry.header.payload_type,
            payload_hash=entry.header.payload_hash,
            prev_hash=entry.header.prev_hash,
            entry_hash=entry.entry_hash,
            payload=entry.payload,
        )
        assert reconstructed == entry
