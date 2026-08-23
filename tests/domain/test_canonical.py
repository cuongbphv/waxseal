"""Direct tests for domain/canonical.py — the single owner of payload JSON bytes.

The chain commits to `payload_hash`, so every option of `canonical_json` is part
of the on-disk format. These tests freeze the observable byte behavior: if any
assertion here starts failing, someone changed the serialization options, which
is a SPEC break (a silent change would surface later as a mass false tampering
report — the migration-060 failure class, one layer down). That failure means
STOP, not "update the expected bytes".
"""

from __future__ import annotations

import hashlib

from waxseal.domain.canonical import canonical_json


class TestCanonicalJsonFrozenFormat:
    def test_keys_are_sorted(self) -> None:
        assert canonical_json({"b": 1, "a": 2}) == b'{"a":2,"b":1}'

    def test_separators_carry_no_whitespace(self) -> None:
        assert canonical_json({"a": [1, 2], "b": {"c": 3}}) == b'{"a":[1,2],"b":{"c":3}}'

    def test_non_ascii_is_escaped_not_encoded(self) -> None:
        # ensure_ascii=True is load-bearing: the frame must not depend on any
        # downstream tool's Unicode normalization. Vietnamese text must come out
        # as \uXXXX escapes inside pure-ASCII bytes.
        out = canonical_json({"msg": "chuỗi"})
        assert out == b'{"msg":"chu\\u1ed7i"}'
        out.decode("ascii")  # must not raise

    def test_empty_object(self) -> None:
        assert canonical_json({}) == b"{}"

    def test_null_and_empty_string_hash_differently(self) -> None:
        # None ≠ "" at the payload layer too — collapsing them would let an
        # absent field and an empty field alias to one payload_hash.
        assert canonical_json({"a": None}) != canonical_json({"a": ""})

    def test_equal_payloads_with_different_key_order_are_byte_identical(self) -> None:
        # Two producers disagreeing about key order must still commit to the
        # same payload_hash — that is the whole reason this module exists.
        left = canonical_json({"seq": 1, "actor": "a", "note": None})
        right = canonical_json({"note": None, "actor": "a", "seq": 1})
        assert left == right

    def test_golden_payload_hash_is_frozen(self) -> None:
        # Write-once golden value. A mismatch means the canonical options
        # changed and every historical payload_hash is now unreproducible.
        payload = {"tool": "verify", "args": ["--pin"], "ok": True, "note": None}
        digest = hashlib.sha256(canonical_json(payload)).hexdigest()
        assert canonical_json(payload) == (
            b'{"args":["--pin"],"note":null,"ok":true,"tool":"verify"}'
        )
        assert digest == hashlib.sha256(
            b'{"args":["--pin"],"note":null,"ok":true,"tool":"verify"}'
        ).hexdigest()
