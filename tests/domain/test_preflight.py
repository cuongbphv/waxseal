"""The attacker-capability ladder as a reading, not a verdict (waxseal-ip8).

docs/security/threat-model.md section 5 tabulates six attacker capabilities
against what stops each. `waxseal preflight` prints which rung a configuration
stops, in that table's own language. This file pins the pure logic: given what
a run could see, which rungs are PRESENT, ABSENT, NOT MEASURED, or have no
mechanism at all, and where the contiguous claim caps.

The state that earns this module its own tests is NOT MEASURED. A run contacts
no witness and holds no seal key, so "no witness confirmed" is a fact about
the run, never about the deployment. Rendering it as ABSENT is the collapse
CLAUDE.md's Ternary Evidence Principle names: `f(not-measured) = f(false)`
gives a false alarm, `f(not-measured) = f(true)` gives false confidence, and
there is no third slot in a binary to put it in.
"""

from __future__ import annotations

from waxseal.domain.preflight import (
    LadderReading,
    Observed,
    PreflightObservation,
    Rung,
    RungState,
    ladder_for,
    render_ladder,
)


def observation(
    *,
    seal: bool | None = False,
    anchors: bool | None = False,
    external: bool | None = False,
    aggregate: bool | None = False,
    witness: bool | None = None,
    ledger: bool | None = None,
) -> PreflightObservation:
    """An observation with every dimension explicit.

    The defaults are the BARE trail: nothing sealed, nothing anchored, and a
    witness that was never contacted (``None``) — which is what a preflight
    run can actually say about a witness, since it opens no network
    connection. ``ledger`` (waxseal-fg4.45) defaults the same way, for the
    same reason: preflight opens no network connection to check it either.
    """
    return PreflightObservation(
        seal=Observed(seal, "seal detail"),
        anchor_records=Observed(anchors, "anchor detail"),
        external_anchor=Observed(external, "external detail"),
        aggregate_binding=Observed(aggregate, "aggregate detail"),
        witness=Observed(witness, "witness detail"),
        ledger=Observed(ledger, "ledger detail"),
    )


class TestLowestRung:
    def test_bare_trail_stops_nobody_and_names_what_rung_one_needs(self) -> None:
        reading = ladder_for(observation())
        assert reading.stops_at == 0
        assert reading.next_rung.number == 1
        assert reading.next_rung.state is RungState.ABSENT
        assert reading.next_rung.needs is not None
        assert "SPEC 11" in reading.next_rung.needs

    def test_the_table_always_carries_all_six_rungs(self) -> None:
        # The reading re-presents threat-model.md section 5's table; dropping
        # a row would silently narrow the ladder an operator is reading
        # against.
        reading = ladder_for(observation())
        assert [r.number for r in reading.rungs] == [1, 2, 3, 4, 5, 6]


class TestMiddleRung:
    def test_seal_only_stops_rung_one_and_asks_for_an_anchor(self) -> None:
        reading = ladder_for(observation(seal=True))
        assert reading.stops_at == 1
        assert reading.rungs[0].state is RungState.PRESENT
        assert reading.next_rung.number == 2
        assert reading.next_rung.state is RungState.ABSENT
        assert reading.next_rung.needs is not None
        assert "SPEC 9" in reading.next_rung.needs

    def test_seal_and_local_anchor_stops_rung_two(self) -> None:
        # Rung 2's attacker does NOT hold `.anchors`, which is why any record
        # at all — the local `file` sink included — is a record beyond reach.
        reading = ladder_for(observation(seal=True, anchors=True))
        assert reading.stops_at == 2
        assert reading.next_rung.number == 3


class TestHighestReachableRung:
    def test_full_stack_stops_rung_four_and_rung_five_has_no_mechanism(self) -> None:
        reading = ladder_for(observation(seal=True, anchors=True, external=True, aggregate=True))
        assert reading.stops_at == 4
        assert reading.next_rung.number == 5
        assert reading.next_rung.state is RungState.NO_MECHANISM
        # Rule 6 in its purest form: the absence of a mechanism is stated, not
        # left as an empty field a renderer might print as "configure this".
        assert reading.next_rung.needs is None

    def test_rung_five_and_six_are_never_present_however_much_is_configured(self) -> None:
        reading = ladder_for(
            observation(seal=True, anchors=True, external=True, aggregate=True, witness=True)
        )
        assert reading.rungs[4].state is RungState.NO_MECHANISM
        assert reading.rungs[5].state is RungState.NO_MECHANISM
        # The cap can therefore never exceed 4, which is what makes
        # `next_rung` total rather than optional.
        assert reading.stops_at == 4


class TestNotMeasuredIsNotAbsent:
    def test_unmeasured_external_anchor_is_not_measured_not_absent(self) -> None:
        # An `.anchors` sidecar this build could not parse: the count of
        # external sinks is unknown, and rendering it as zero is exactly the
        # rule-5 collapse.
        reading = ladder_for(observation(seal=True, anchors=True, external=None))
        assert reading.rungs[2].state is RungState.NOT_MEASURED
        assert reading.stops_at == 2

    def test_a_witness_that_was_never_contacted_cannot_make_rung_three_absent(self) -> None:
        # external=False is measured; witness=None is not. Rung 3's stopper is
        # "the TSA / calendar / witness holds its own copy", so with one half
        # unmeasured the rung is NOT MEASURED, never ABSENT.
        reading = ladder_for(observation(seal=True, anchors=True))
        assert reading.rungs[2].state is RungState.NOT_MEASURED

    def test_a_measured_absence_on_every_half_is_absent(self) -> None:
        reading = ladder_for(observation(seal=True, anchors=True, witness=False, ledger=False))
        assert reading.rungs[2].state is RungState.ABSENT

    def test_an_unmeasured_ledger_alone_cannot_make_rung_three_absent(self) -> None:
        # waxseal-fg4.45: external and witness are both measured absent, but
        # ledger was never checked this run (--rpc/--liveness not given) —
        # one unmeasured alternate is still enough to make the whole rung
        # NOT MEASURED, the same rule the pre-existing witness/external pair
        # already established above.
        reading = ladder_for(observation(seal=True, anchors=True, witness=False, ledger=None))
        assert reading.rungs[2].state is RungState.NOT_MEASURED

    def test_a_present_ledger_alone_stops_rung_three(self) -> None:
        # waxseal-fg4.45: neither external nor witness is present, but a
        # configured, passing ledger check is — rung 3's stopper is PRESENT
        # from the ledger alone, the same way it already is from witness
        # alone (test_a_present_half_beats_an_unmeasured_half below).
        reading = ladder_for(observation(seal=True, anchors=True, ledger=True))
        assert reading.rungs[2].state is RungState.PRESENT
        assert reading.stops_at == 3

    def test_a_present_half_beats_an_unmeasured_half(self) -> None:
        reading = ladder_for(observation(seal=True, anchors=True, external=True))
        assert reading.rungs[2].state is RungState.PRESENT


class TestContiguity:
    def test_a_stopper_above_a_gap_does_not_raise_the_cap(self) -> None:
        # An external anchor with no seal: rung 3's stopper is present, but
        # the claim "stops an attacker at rung 3" includes every weaker
        # attacker, so rung 1's missing stopper caps it at 0.
        reading = ladder_for(observation(external=True))
        assert reading.stops_at == 0
        assert reading.rungs[2].state is RungState.PRESENT

    def test_stoppers_above_the_cap_are_reported_not_hidden(self) -> None:
        # Understating is the safe direction, but silently dropping a
        # configured mechanism from the output would be its own lie by
        # omission: the operator anchored, and preflight must say so.
        reading = ladder_for(observation(external=True, aggregate=True))
        assert reading.present_above_cap == (3, 4)

    def test_nothing_above_the_cap_reports_nothing(self) -> None:
        reading = ladder_for(observation(seal=True))
        assert reading.present_above_cap == ()


class TestRendering:
    def test_every_rung_is_rendered_with_its_state_and_its_observation(self) -> None:
        reading = ladder_for(observation(seal=True))
        text = "\n".join(render_ladder(reading))
        for n in range(1, 7):
            assert f"rung {n}" in text
        assert "PRESENT" in text and "ABSENT" in text and "NOT MEASURED" in text
        assert "NO MECHANISM" in text
        assert "seal detail" in text and "witness detail" in text

    def test_the_contiguous_meaning_is_printed_not_assumed(self) -> None:
        text = "\n".join(render_ladder(ladder_for(observation(seal=True))))
        assert "stops an attacker at rung 1" in text
        assert "rung 2 needs" in text

    def test_rung_zero_does_not_render_a_backwards_range(self) -> None:
        text = "\n".join(render_ladder(ladder_for(observation())))
        assert "stops an attacker at rung 0" in text
        assert "1 through 0" not in text

    def test_an_unmeasured_next_rung_never_renders_as_a_thing_to_configure(self) -> None:
        text = "\n".join(render_ladder(ladder_for(observation(seal=True, anchors=True))))
        assert "rung 3: NOT MEASURED" in text
        assert "rung 3 needs" not in text

    def test_a_no_mechanism_next_rung_names_the_operational_requirement(self) -> None:
        reading = ladder_for(observation(seal=True, anchors=True, external=True, aggregate=True))
        text = "\n".join(render_ladder(reading))
        assert "no configuration raises this rung" in text
        assert "administrative authority" in text

    def test_stoppers_above_the_cap_reach_the_rendered_output(self) -> None:
        reading = ladder_for(observation(external=True, aggregate=True))
        text = "\n".join(render_ladder(reading))
        assert "above the cap" in text


class TestTypes:
    def test_the_reading_is_frozen_so_a_renderer_cannot_edit_a_verdict(self) -> None:
        # Same discipline every other report type in this package carries: the
        # thing an operator reads cannot be mutated between computing it and
        # printing it.
        for cls in (LadderReading, Observed, PreflightObservation, Rung):
            assert cls.__dataclass_params__.frozen  # type: ignore[union-attr]
