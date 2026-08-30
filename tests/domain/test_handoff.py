"""Tests for the cross-trail handoff-binding schema (SPEC D3).

Covers: the pointer triple validates like every other digest-carrying schema
in this codebase (domain.decision precedent), round-trips through the same
canonical_json path every other payload uses, and ``binding_holds`` is the
fail-closed origin-side half of transitive anchoring.
"""

from __future__ import annotations

import json

import pytest

from waxseal.domain.canonical import canonical_json
from waxseal.domain.handoff import (
    HANDOFF_PAYLOAD_TYPE,
    HandoffBinding,
    binding_holds,
    from_payload,
    to_payload,
)

A_HASH = "a" * 64
B_HASH = "b" * 64


class TestHandoffBinding:
    def test_valid_binding_constructs(self) -> None:
        b = HandoffBinding(chain_id="agent-a", seq=3, head_hash=A_HASH)
        assert b.chain_id == "agent-a"
        assert b.seq == 3
        assert b.head_hash == A_HASH

    def test_empty_chain_id_rejected(self) -> None:
        with pytest.raises(ValueError, match="chain_id"):
            HandoffBinding(chain_id="", seq=0, head_hash=A_HASH)

    def test_non_string_chain_id_rejected(self) -> None:
        with pytest.raises(ValueError, match="chain_id"):
            HandoffBinding(chain_id=None, seq=0, head_hash=A_HASH)  # type: ignore[arg-type]

    def test_negative_seq_rejected(self) -> None:
        with pytest.raises(ValueError, match="seq"):
            HandoffBinding(chain_id="a", seq=-1, head_hash=A_HASH)

    def test_bool_seq_rejected(self) -> None:
        # bool is an int subclass; silently accepting True as seq=1 would
        # hide a caller's type error inside a number that looks plausible.
        with pytest.raises(ValueError, match="seq"):
            HandoffBinding(chain_id="a", seq=True, head_hash=A_HASH)  # type: ignore[arg-type]

    def test_non_int_seq_rejected(self) -> None:
        with pytest.raises(ValueError, match="seq"):
            HandoffBinding(chain_id="a", seq="0", head_hash=A_HASH)  # type: ignore[arg-type]

    def test_malformed_head_hash_rejected(self) -> None:
        with pytest.raises(ValueError, match="head_hash"):
            HandoffBinding(chain_id="a", seq=0, head_hash="not-hex")

    def test_short_head_hash_rejected(self) -> None:
        with pytest.raises(ValueError, match="head_hash"):
            HandoffBinding(chain_id="a", seq=0, head_hash="aa" * 10)

    def test_uppercase_head_hash_rejected(self) -> None:
        # Hex case must be pinned to one spelling or two producers of "the
        # same" hash disagree at the byte level -- the same rationale
        # canonical_json's ensure_ascii=True note gives for payload bytes.
        with pytest.raises(ValueError, match="head_hash"):
            HandoffBinding(chain_id="a", seq=0, head_hash=A_HASH.upper())


class TestPayloadRoundTrip:
    def test_to_payload_then_from_payload_round_trips(self) -> None:
        binding = HandoffBinding(chain_id="agent-a", seq=7, head_hash=A_HASH)
        assert from_payload(to_payload(binding)) == binding

    def test_to_payload_is_exactly_three_fields(self) -> None:
        # No business data (SPEC D3): the payload must be the pointer triple
        # and nothing else, or an entry of this type could carry exactly the
        # data an erasure policy would later need to remove.
        binding = HandoffBinding(chain_id="agent-a", seq=1, head_hash=A_HASH)
        assert set(to_payload(binding)) == {"chain_id", "seq", "head_hash"}

    def test_payload_survives_canonical_json_and_back(self) -> None:
        # The same path AuditLog.append hashes every payload through
        # (CLAUDE.md: one canonical encoding, never invent a second).
        binding = HandoffBinding(chain_id="agent-a", seq=2, head_hash=B_HASH)
        wire = canonical_json(to_payload(binding))
        assert from_payload(json.loads(wire)) == binding

    def test_from_payload_rejects_non_dict(self) -> None:
        with pytest.raises(ValueError, match="JSON object"):
            from_payload(["not", "a", "dict"])

    def test_from_payload_rejects_missing_field(self) -> None:
        with pytest.raises(ValueError, match="missing field"):
            from_payload({"chain_id": "a", "seq": 0})

    def test_from_payload_propagates_binding_validation(self) -> None:
        # A malformed head_hash surfaces as the same ValueError the
        # constructor raises -- from_payload must not swallow it into a
        # different, less specific error.
        with pytest.raises(ValueError, match="head_hash"):
            from_payload({"chain_id": "a", "seq": 0, "head_hash": "bad"})


class TestPayloadType:
    def test_payload_type_follows_the_domain_level_vnd_waxseal_convention(self) -> None:
        # Matches FILE_VERSION_PAYLOAD_TYPE / OPENCLAW_GAP_PAYLOAD_TYPE, not
        # the per-integration application/vnd.<host>.<event>+json shape:
        # this type is meant to be written by ANY integration/source, not
        # one host's hook.
        assert HANDOFF_PAYLOAD_TYPE == "application/vnd.waxseal.handoff-binding+json"


class TestBindingHolds:
    def test_holds_when_origin_hash_at_seq_matches(self) -> None:
        binding = HandoffBinding(chain_id="a", seq=1, head_hash=A_HASH)
        assert binding_holds(binding, ["h0", A_HASH, "h2"]) is True

    def test_does_not_hold_when_origin_was_rewritten(self) -> None:
        # The property under test: a rewrite of the origin trail at the
        # bound seq changes its entry_hash there, and the pin catches it.
        binding = HandoffBinding(chain_id="a", seq=1, head_hash=A_HASH)
        assert binding_holds(binding, ["h0", "rewritten-hash", "h2"]) is False

    def test_seq_beyond_current_origin_length_fails_closed(self) -> None:
        # Origin trail truncated (or never reached that far) since the
        # binding was recorded -- False, not IndexError/exception (rule 5 /
        # anchoring.py's fail-closed contract).
        binding = HandoffBinding(chain_id="a", seq=5, head_hash=A_HASH)
        assert binding_holds(binding, ["h0", "h1"]) is False

    def test_never_raises_on_empty_origin_hashes(self) -> None:
        binding = HandoffBinding(chain_id="a", seq=0, head_hash=A_HASH)
        assert binding_holds(binding, []) is False
