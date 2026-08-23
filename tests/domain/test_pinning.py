"""Pinned-head verification (domain/pinning.py).

A hash chain proves its own links hold. It cannot prove the copy you are
reading today is the copy you read last week — a server (or anyone who can
rewrite the whole file) can hand out a consistently re-hashed history that
verifies perfectly against itself. The pin is the verifier's own memory: a
checkpoint it computed once, stored under its own authority, and re-checked
against whatever it is served next time.

Two distinctions the tests below hold the implementation to:

- a pin that does not match is *checked and false* — the history the verifier
  previously confirmed has changed, which is a break, not a curiosity;
- a pin state from a NEWER waxseal is unverifiable BY NAME, never a break.
  That is the beads-v1.2.2 failure class applied to the verifier's own state
  file: an unreadable version identifier must not be spelled the same way as
  evidence of tampering.
"""

from __future__ import annotations

import json

import pytest

from waxseal.domain.checkpoint import Checkpoint, checkpoint_for
from waxseal.domain.pinning import (
    PIN_STATE_VERSION,
    PinMalformed,
    PinState,
    PinVersionUnknown,
    check_pin,
    check_pin_target,
    parse_pin_state,
    render_pin_state,
)

HASHES = [f"{i:064x}" for i in range(1, 6)]


def pin_at(n: int) -> Checkpoint:
    """A checkpoint over the first ``n`` hashes — what a verifier would have
    pinned after seeing that much of the trail."""
    return checkpoint_for(HASHES[:n])


def state_at(n: int, *, target: str = "/trail.jsonl", chain_id: str | None = None) -> PinState:
    return PinState(
        target=target,
        chain_id=chain_id,
        checkpoint=pin_at(n),
        pinned_ts="2026-08-23T09:00:00+00:00",
    )


class TestCheckPin:
    def test_unchanged_prefix_passes(self) -> None:
        assert check_pin(HASHES, pin_at(3)) is None

    def test_pin_of_the_whole_trail_passes(self) -> None:
        assert check_pin(HASHES, pin_at(len(HASHES))) is None

    def test_rewritten_tip_is_pin_mismatch(self) -> None:
        tampered = [*HASHES[:2], "f" * 64, *HASHES[3:]]
        assert check_pin(tampered, pin_at(3)) == "pin_mismatch"

    def test_rewritten_earlier_entry_is_pin_mismatch(self) -> None:
        # The tip at the pinned seq still matches; only the batch root over
        # the prefix moves. A chain-only check cannot see this, which is the
        # whole reason the pin carries a root.
        tampered = ["f" * 64, *HASHES[1:]]
        assert check_pin(tampered, pin_at(3)) == "pin_mismatch"

    def test_truncated_trail_is_pin_beyond_head(self) -> None:
        # Distinct reason from a rewrite: the trail is now SHORTER than what
        # the verifier already confirmed, i.e. a rollback.
        assert check_pin(HASHES[:2], pin_at(4)) == "pin_beyond_head"

    def test_empty_trail_against_any_pin_is_pin_beyond_head(self) -> None:
        assert check_pin([], pin_at(1)) == "pin_beyond_head"

    def test_negative_seq_is_malformed_not_mismatch(self) -> None:
        bad = Checkpoint(seq=-1, entry_hash=HASHES[0], root=HASHES[0])
        assert check_pin(HASHES, bad) == "malformed_pin"

    def test_never_raises_on_hostile_input(self) -> None:
        weird = Checkpoint(seq=0, entry_hash="", root="")
        assert check_pin([], weird) == "pin_beyond_head"
        assert check_pin(HASHES, weird) == "pin_mismatch"


class TestCheckPinTarget:
    def test_same_target_and_chain_id_passes(self) -> None:
        state = state_at(3, target="https://host/api", chain_id="prod")
        assert check_pin_target(state, target="https://host/api", chain_id="prod") is None

    def test_different_target_refuses(self) -> None:
        # Could be a moved trail or the wrong file entirely. Guessing either
        # way is worse than making the operator say which.
        state = state_at(3, target="/a.jsonl")
        assert check_pin_target(state, target="/b.jsonl", chain_id=None) == "pin_target_mismatch"

    def test_different_chain_id_refuses(self) -> None:
        state = state_at(3, target="https://host/api", chain_id="prod")
        assert (
            check_pin_target(state, target="https://host/api", chain_id="staging")
            == "pin_target_mismatch"
        )


class TestSerialization:
    def test_round_trip(self) -> None:
        state = state_at(3, target="https://host/api", chain_id="prod")
        assert parse_pin_state(render_pin_state(state)) == state

    def test_round_trip_without_chain_id(self) -> None:
        state = state_at(2)
        assert parse_pin_state(render_pin_state(state)) == state

    def test_rendered_form_is_stable_and_versioned(self) -> None:
        obj = json.loads(render_pin_state(state_at(3)))
        assert obj["v"] == PIN_STATE_VERSION
        assert obj["chain_id"] is None
        assert set(obj) == {"v", "target", "chain_id", "seq", "entry_hash", "root", "pinned_ts"}

    def test_absent_chain_id_is_explicit_null_not_omitted(self) -> None:
        # Same rule the decision record follows: "not applicable" is written
        # down, so a reader can tell it apart from a key someone dropped.
        assert '"chain_id": null' in render_pin_state(state_at(1))

    @pytest.mark.parametrize(
        "text",
        [
            "",
            "not json",
            "[]",
            '"a string"',
            "{}",
            '{"v": 1}',
            '{"v": 1, "target": "/t", "chain_id": null, "seq": "x", '
            '"entry_hash": "a", "root": "b", "pinned_ts": "t"}',
            '{"v": null, "target": "/t", "chain_id": null, "seq": 0, '
            '"entry_hash": "a", "root": "b", "pinned_ts": "t"}',
        ],
    )
    def test_malformed_states_raise_pin_malformed(self, text: str) -> None:
        with pytest.raises(PinMalformed):
            parse_pin_state(text)

    def test_newer_version_is_unknown_not_malformed(self) -> None:
        text = json.dumps(
            {
                "v": PIN_STATE_VERSION + 1,
                "target": "/t",
                "chain_id": None,
                "seq": 0,
                "entry_hash": "a" * 64,
                "root": "a" * 64,
                "pinned_ts": "t",
            }
        )
        with pytest.raises(PinVersionUnknown):
            parse_pin_state(text)

    def test_unknown_version_is_not_caught_as_malformed(self) -> None:
        # The two must stay distinguishable by type: one is exit 1, the other
        # exit 2, and a shared base class that swallowed the difference would
        # hand an unreadable-by-name state the tampering verdict.
        assert not issubclass(PinVersionUnknown, PinMalformed)
        assert not issubclass(PinMalformed, PinVersionUnknown)

    def test_non_string_chain_id_is_malformed(self) -> None:
        text = json.dumps(
            {
                **json.loads(render_pin_state(state_at(1))),
                "chain_id": 7,
            }
        )
        with pytest.raises(PinMalformed):
            parse_pin_state(text)

    def test_extra_keys_are_ignored(self) -> None:
        # Forward compatibility WITHIN a version: a v1 state written by a
        # build that also records something extra is still a v1 state.
        text = json.dumps(
            {
                **json.loads(render_pin_state(state_at(2))),
                "recorded_by": "some future build",
            }
        )
        assert parse_pin_state(text).checkpoint == pin_at(2)
