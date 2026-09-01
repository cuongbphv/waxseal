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
from datetime import UTC, datetime

import pytest

from waxseal.domain.checkpoint import Checkpoint, checkpoint_for
from waxseal.domain.pinning import (
    ANCHOR_BINDING_UNREADABLE,
    ANCHOR_POLICY_DOWNGRADE,
    ANCHOR_STALE,
    ANCHOR_TIMESTAMP_UNPARSEABLE,
    PIN_STATE_VERSION,
    PinMalformed,
    PinState,
    PinVersionUnknown,
    anchor_policy_downgrade,
    anchor_staleness,
    check_pin,
    check_pin_target,
    parse_pin_state,
    render_pin_state,
)
from waxseal.domain.separation import SeparationTopology

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
        assert set(obj) == {
            "v",
            "target",
            "chain_id",
            "seq",
            "entry_hash",
            "root",
            "pinned_ts",
            "expect_anchor_binding",
        }

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


class TestDeclaredTopology:
    """``declared_topology`` is a trailing optional field: absent means "this
    pin never declared a separation topology", the ordinary case for every
    pin state on disk before this bead and still the default afterward.
    Present, it is all-or-nothing — four required subfields, none defaulted
    (rule 5: a defaulted field here would be indistinguishable from an
    operator's actual declaration)."""

    def topology_at(self, n: int) -> PinState:
        return PinState(
            target="/trail.jsonl",
            chain_id=None,
            checkpoint=pin_at(n),
            pinned_ts="2026-08-23T09:00:00+00:00",
            declared_topology=SeparationTopology(
                seal_escrow=True, anchor_sinks=2, witness=True, pin_separate=False
            ),
        )

    def test_round_trip_with_declared_topology(self) -> None:
        state = self.topology_at(3)
        assert parse_pin_state(render_pin_state(state)) == state

    def test_round_trip_without_declared_topology_is_backward_compatible(self) -> None:
        # An ordinary pin state, with no declared_topology key at all — must
        # keep parsing exactly as it did before this bead.
        state = state_at(2)
        assert state.declared_topology is None
        rendered = render_pin_state(state)
        assert "declared_topology" not in json.loads(rendered)
        assert parse_pin_state(rendered) == state

    def test_hand_written_pin_without_the_key_parses_as_not_declared(self) -> None:
        # A pin file written by a build before this bead existed: no
        # declared_topology key in the JSON at all.
        text = json.dumps(
            {
                "v": PIN_STATE_VERSION,
                "target": "/trail.jsonl",
                "chain_id": None,
                "seq": pin_at(2).seq,
                "entry_hash": pin_at(2).entry_hash,
                "root": pin_at(2).root,
                "pinned_ts": "2026-08-23T09:00:00+00:00",
            }
        )
        assert parse_pin_state(text).declared_topology is None

    def test_declared_topology_is_omitted_not_null_when_absent(self) -> None:
        assert "declared_topology" not in json.loads(render_pin_state(state_at(1)))

    @pytest.mark.parametrize(
        "missing_field", ["seal_escrow", "anchor_sinks", "witness", "pin_separate"]
    )
    def test_partial_declared_topology_is_malformed(self, missing_field: str) -> None:
        obj = json.loads(render_pin_state(self.topology_at(2)))
        del obj["declared_topology"][missing_field]
        with pytest.raises(PinMalformed):
            parse_pin_state(json.dumps(obj))

    @pytest.mark.parametrize(
        ("field", "bad_value"),
        [
            ("seal_escrow", "yes"),
            ("seal_escrow", 1),
            ("witness", "no"),
            ("witness", 0),
            ("pin_separate", None),
        ],
    )
    def test_non_bool_subfield_is_malformed(self, field: str, bad_value: object) -> None:
        obj = json.loads(render_pin_state(self.topology_at(2)))
        obj["declared_topology"][field] = bad_value
        with pytest.raises(PinMalformed):
            parse_pin_state(json.dumps(obj))

    def test_non_int_anchor_sinks_is_malformed(self) -> None:
        obj = json.loads(render_pin_state(self.topology_at(2)))
        obj["declared_topology"]["anchor_sinks"] = "two"
        with pytest.raises(PinMalformed):
            parse_pin_state(json.dumps(obj))

    def test_bool_anchor_sinks_is_malformed(self) -> None:
        # Same isinstance(x, bool) exclusion _require_int already applies to
        # every other integer field in this module.
        obj = json.loads(render_pin_state(self.topology_at(2)))
        obj["declared_topology"]["anchor_sinks"] = True
        with pytest.raises(PinMalformed):
            parse_pin_state(json.dumps(obj))

    def test_declared_topology_not_an_object_is_malformed(self) -> None:
        obj = json.loads(render_pin_state(self.topology_at(2)))
        obj["declared_topology"] = "not an object"
        with pytest.raises(PinMalformed):
            parse_pin_state(json.dumps(obj))


class TestDeclaredTopologyLedger:
    """``declared_topology.ledger`` (waxseal-fg4.45) is NOT a fifth required
    subfield the way the original four are: it was added after SPEC 13.1's
    "all four together" shape had already shipped, so it round-trips as its
    own optional key inside the object — present only when not ``None``,
    the same convention ``declared_topology`` itself and ``max_anchor_age_s``
    already use one level up. ``topology_at`` above (no ``ledger=`` given)
    is this class's own fixture for "predates the field entirely" — every
    assertion in ``TestDeclaredTopology`` already exercises that case
    without knowing it, which is the append-only property this bead exists
    to hold.
    """

    def topology_at(self, n: int, *, ledger: bool | None) -> PinState:
        return PinState(
            target="/trail.jsonl",
            chain_id=None,
            checkpoint=pin_at(n),
            pinned_ts="2026-08-23T09:00:00+00:00",
            declared_topology=SeparationTopology(
                seal_escrow=True, anchor_sinks=2, witness=True, pin_separate=False,
                ledger=ledger,
            ),
        )

    def test_round_trip_with_ledger_true(self) -> None:
        state = self.topology_at(3, ledger=True)
        assert parse_pin_state(render_pin_state(state)) == state
        assert json.loads(render_pin_state(state))["declared_topology"]["ledger"] is True

    def test_round_trip_with_ledger_false(self) -> None:
        state = self.topology_at(3, ledger=False)
        assert parse_pin_state(render_pin_state(state)) == state
        assert json.loads(render_pin_state(state))["declared_topology"]["ledger"] is False

    def test_ledger_key_is_omitted_not_null_when_undeclared(self) -> None:
        # The same rule 5 discipline `declared_topology` itself gets from
        # `render_pin_state`: undeclared must round-trip as an ABSENT key,
        # never a present `null`, or a reader could not tell "never asked"
        # from "asked and the answer was written as null".
        state = self.topology_at(3, ledger=None)
        rendered = render_pin_state(state)
        assert "ledger" not in json.loads(rendered)["declared_topology"]
        parsed = parse_pin_state(rendered)
        assert parsed == state
        assert parsed.declared_topology is not None
        assert parsed.declared_topology.ledger is None

    def test_a_pin_written_before_ledger_existed_parses_it_as_none(self) -> None:
        # `TestDeclaredTopology.topology_at` builds exactly this shape: a
        # declared_topology object with the original four subfields and no
        # "ledger" key at all — every one of THAT class's own tests already
        # covers this without naming it; this test names it directly.
        obj = json.loads(render_pin_state(TestDeclaredTopology().topology_at(2)))
        assert "ledger" not in obj["declared_topology"]
        parsed = parse_pin_state(json.dumps(obj))
        assert parsed.declared_topology is not None
        assert parsed.declared_topology.ledger is None

    @pytest.mark.parametrize("bad_value", ["yes", 1, 0])
    def test_non_bool_ledger_value_is_malformed(self, bad_value: object) -> None:
        obj = json.loads(render_pin_state(self.topology_at(2, ledger=True)))
        obj["declared_topology"]["ledger"] = bad_value
        with pytest.raises(PinMalformed):
            parse_pin_state(json.dumps(obj))

    def test_explicit_json_null_for_ledger_parses_the_same_as_absent(self) -> None:
        # `_optional_bool_or_none`'s own convention (matching every other
        # `_optional_*` reader in this module): an explicit `null` and a
        # missing key both mean "not declared".
        obj = json.loads(render_pin_state(self.topology_at(2, ledger=True)))
        obj["declared_topology"]["ledger"] = None
        parsed = parse_pin_state(json.dumps(obj))
        assert parsed.declared_topology is not None
        assert parsed.declared_topology.ledger is None


class TestMaxAnchorAge:
    """``max_anchor_age_s`` is a second trailing-optional field on PinState,
    the same pattern ``declared_topology`` established: absent means "this
    pin never declared a silence deadline" (W4/C3), present it is a plain
    scalar (unlike declared_topology's nested object — there is only one
    number here, not a group of fields that must arrive together)."""

    def age_at(self, n: int, *, max_anchor_age_s: int = 3600) -> PinState:
        return PinState(
            target="/trail.jsonl",
            chain_id=None,
            checkpoint=pin_at(n),
            pinned_ts="2026-08-23T09:00:00+00:00",
            max_anchor_age_s=max_anchor_age_s,
        )

    def test_round_trip_present(self) -> None:
        state = self.age_at(3)
        assert parse_pin_state(render_pin_state(state)) == state

    def test_round_trip_absent(self) -> None:
        # An old pin file, including one written before declared_topology
        # existed — both new-since-then fields must still parse as None.
        state = state_at(2)
        assert state.max_anchor_age_s is None
        assert state.declared_topology is None
        rendered = render_pin_state(state)
        assert "max_anchor_age_s" not in json.loads(rendered)
        assert parse_pin_state(rendered) == state

    def test_omitted_not_null_when_absent(self) -> None:
        assert "max_anchor_age_s" not in json.loads(render_pin_state(state_at(1)))

    def test_hand_written_pin_without_the_key_parses_as_not_declared(self) -> None:
        text = json.dumps(
            {
                "v": PIN_STATE_VERSION,
                "target": "/trail.jsonl",
                "chain_id": None,
                "seq": pin_at(2).seq,
                "entry_hash": pin_at(2).entry_hash,
                "root": pin_at(2).root,
                "pinned_ts": "2026-08-23T09:00:00+00:00",
            }
        )
        assert parse_pin_state(text).max_anchor_age_s is None

    def test_wrong_type_raises_pin_malformed(self) -> None:
        obj = json.loads(render_pin_state(self.age_at(2)))
        obj["max_anchor_age_s"] = "3600"
        with pytest.raises(PinMalformed):
            parse_pin_state(json.dumps(obj))

    def test_bool_is_malformed(self) -> None:
        # Same isinstance(x, bool) exclusion every other integer field in
        # this module applies: a JSON true/false is never silently an int.
        obj = json.loads(render_pin_state(self.age_at(2)))
        obj["max_anchor_age_s"] = True
        with pytest.raises(PinMalformed):
            parse_pin_state(json.dumps(obj))


class TestAnchorStaleness:
    """``anchor_staleness`` — the pure W4/C3 decision, independent of any
    CLI plumbing. Takes plain ``(checkpoint_seq, ts)`` pairs rather than
    ``AnchorRecord`` objects: ``AnchorRecord`` lives in
    ``adapters/anchors.py``, and this module (``domain/``) must not import
    it (CLAUDE.md's layer DAG)."""

    NOW = datetime(2026, 8, 29, 12, 0, 0, tzinfo=UTC)

    def test_fresh_record_is_not_stale(self) -> None:
        records = [(1, "2026-08-29T11:59:00+00:00")]  # 1 minute old, Δ=1h
        assert anchor_staleness(3600, records, now=self.NOW) is None

    def test_record_older_than_deadline_is_stale(self) -> None:
        records = [(1, "2026-08-29T10:00:00+00:00")]  # 2h old, Δ=1h
        assert anchor_staleness(3600, records, now=self.NOW) == ANCHOR_STALE

    def test_no_records_at_all_is_stale(self) -> None:
        # Absence of anchoring evidence is itself staleness — "vắng anchor =
        # vắng bằng chứng" — never a pass and never exit-1 broken.
        assert anchor_staleness(3600, [], now=self.NOW) == ANCHOR_STALE

    def test_picks_highest_seq_as_most_recent_not_string_order(self) -> None:
        # seq=5's ts sorts BEFORE seq=2's ts as a string, which would give
        # the wrong answer if this compared timestamps as strings instead of
        # picking by checkpoint position.
        records = [
            (2, "2026-08-29T11:59:00+00:00"),  # fresh, but not the newest seq
            (5, "2020-01-01T00:00:00+00:00"),  # ancient, but the newest seq
        ]
        assert anchor_staleness(3600, records, now=self.NOW) == ANCHOR_STALE

    def test_unparseable_timestamp_is_unverifiable_not_stale(self) -> None:
        records = [(1, "not-a-timestamp")]
        assert (
            anchor_staleness(3600, records, now=self.NOW)
            == ANCHOR_TIMESTAMP_UNPARSEABLE
        )

    def test_never_raises_on_naive_aware_mismatch(self) -> None:
        # A naive ts next to an aware `now` makes datetime subtraction raise
        # TypeError — still a format problem this build cannot interpret,
        # not a temporal fact, and never allowed to crash a pin check
        # running on attacker-writable sidecar data.
        records = [(1, "2026-08-29T11:59:00")]  # no offset
        assert (
            anchor_staleness(3600, records, now=self.NOW)
            == ANCHOR_TIMESTAMP_UNPARSEABLE
        )

    def test_exactly_at_the_deadline_is_not_stale(self) -> None:
        # age_s == max_age_s is still within the window: only strictly
        # older than the deadline is stale.
        records = [(1, "2026-08-29T11:00:00+00:00")]  # exactly 1h old
        assert anchor_staleness(3600, records, now=self.NOW) is None


class TestExpectAnchorBinding:
    """``expect_anchor_binding`` is a THIRD trailing field on ``PinState``,
    but a plain ``bool`` rather than an optional-with-``None`` field: it is a
    policy switch, so "never declared" and "declared False" mean the same
    thing (W5/F2)."""

    def flag_at(self, n: int, *, expect_anchor_binding: bool) -> PinState:
        return PinState(
            target="/trail.jsonl",
            chain_id=None,
            checkpoint=pin_at(n),
            pinned_ts="2026-08-23T09:00:00+00:00",
            expect_anchor_binding=expect_anchor_binding,
        )

    def test_round_trip_present_true(self) -> None:
        state = self.flag_at(3, expect_anchor_binding=True)
        assert parse_pin_state(render_pin_state(state)) == state
        assert json.loads(render_pin_state(state))["expect_anchor_binding"] is True

    def test_round_trip_present_false(self) -> None:
        state = self.flag_at(3, expect_anchor_binding=False)
        assert parse_pin_state(render_pin_state(state)) == state
        assert json.loads(render_pin_state(state))["expect_anchor_binding"] is False

    def test_round_trip_absent_old_pin_file_defaults_false(self) -> None:
        # A pin file written by hand in the exact shape a pre-bead build
        # would have written — no expect_anchor_binding key anywhere in the
        # JSON — must parse to False without error.
        text = json.dumps(
            {
                "v": PIN_STATE_VERSION,
                "target": "/trail.jsonl",
                "chain_id": None,
                "seq": pin_at(2).seq,
                "entry_hash": pin_at(2).entry_hash,
                "root": pin_at(2).root,
                "pinned_ts": "2026-08-23T09:00:00+00:00",
            }
        )
        assert parse_pin_state(text).expect_anchor_binding is False

    def test_always_rendered_explicitly_even_when_false(self) -> None:
        # Unlike declared_topology/max_anchor_age_s, this key is never
        # omitted: it is a plain flag with a real default, not an
        # undeclared-vs-declared distinction.
        state = self.flag_at(1, expect_anchor_binding=False)
        assert "expect_anchor_binding" in json.loads(render_pin_state(state))

    def test_wrong_type_raises_pin_malformed(self) -> None:
        obj = json.loads(render_pin_state(self.flag_at(2, expect_anchor_binding=True)))
        obj["expect_anchor_binding"] = "yes"
        with pytest.raises(PinMalformed):
            parse_pin_state(json.dumps(obj))


class TestAnchorPolicyDowngrade:
    """``anchor_policy_downgrade`` — the pure W5/F2 decision: was an
    aggregate binding (SPEC §15) that the operator expected actually present
    in the sidecar at or after the pinned seq, PoC turning F2 from
    [Inference] to [Verified]."""

    def test_only_v1_shaped_records_is_a_downgrade(self) -> None:
        # Case 1: none carry a binding, none unreadable.
        records = [(0, None), (1, None), (2, None)]
        assert (
            anchor_policy_downgrade(2, records, any_unreadable=False)
            == ANCHOR_POLICY_DOWNGRADE
        )

    def test_binding_at_or_after_pinned_seq_is_no_downgrade(self) -> None:
        # Case 2.
        records = [(0, None), (2, "commit-2")]
        assert anchor_policy_downgrade(2, records, any_unreadable=False) is None

    def test_binding_strictly_before_pinned_seq_is_still_a_downgrade(self) -> None:
        # Case 3: a binding exists, but predates what is expected going
        # forward — it does not corroborate the declared policy at the
        # pinned position.
        records = [(0, "commit-0"), (1, None)]
        assert (
            anchor_policy_downgrade(1, records, any_unreadable=False)
            == ANCHOR_POLICY_DOWNGRADE
        )

    def test_unreadable_records_never_read_as_no_binding(self) -> None:
        # Case 4: some records unreadable, no READABLE record at-or-after
        # pinned_seq carries a binding -> unreadable, NOT downgrade.
        records = [(0, None), (1, None)]
        assert (
            anchor_policy_downgrade(1, records, any_unreadable=True)
            == ANCHOR_BINDING_UNREADABLE
        )

    def test_binding_found_wins_over_unreadable(self) -> None:
        # A readable record already satisfies the binding; the presence of
        # ALSO some unreadable ones does not need to downgrade anything.
        records = [(2, "commit-2")]
        assert anchor_policy_downgrade(2, records, any_unreadable=True) is None

    def test_no_records_at_all_is_a_downgrade(self) -> None:
        assert anchor_policy_downgrade(0, [], any_unreadable=False) == ANCHOR_POLICY_DOWNGRADE

    def test_no_records_at_all_but_unreadable_is_unreadable(self) -> None:
        assert (
            anchor_policy_downgrade(0, [], any_unreadable=True) == ANCHOR_BINDING_UNREADABLE
        )
