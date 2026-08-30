"""Separation degree (domain/separation.py).

τ (tau) counts how many independent authorities stand between a trail and a
single compromised operator: the writer (always present — it is not a thing
that can go undeclared, so there is no ``writer: bool`` field for it), plus
whatever the operator has separated out (seal escrow, external anchor sinks,
a witness, a separately-stored pin).

CLAUDE.md rule 5 — "None != 0, unverifiable != tampered, unmeasured != absent
... applies to any future metric" — names this bead's τ exactly. An operator
who has never declared a topology has not measured separation at all; that
is a different fact from having measured it and found the degree to be zero
or one. Collapsing "not declared" into a printed "0" or "1" is the same
false-confidence bug the rest of the codebase forbids for dropped_writes and
unknown fingerprints, so this module makes the undeclared case ``None`` by
construction rather than a struct with defaults.
"""

from __future__ import annotations

import dataclasses
import itertools

import pytest

from waxseal.domain.separation import (
    SeparationTopology,
    counted_authorities,
    render_counted_authorities,
    render_separation_degree,
    separation_degree,
    separation_shortfall,
)


class TestNotDeclared:
    def test_none_topology_is_none_degree(self) -> None:
        assert separation_degree(None) is None

    def test_undeclared_degree_is_never_zero_or_one(self) -> None:
        # The sharper regression for rule 5: not just `is None`, but a literal
        # assertion that the undeclared case can never be mistaken for the
        # smallest declared degrees (writer alone = 1, or a hypothetical 0).
        result = separation_degree(None)
        assert result != 0
        assert result != 1


class TestDeclaredDegree:
    def test_full_topology(self) -> None:
        topology = SeparationTopology(
            seal_escrow=True, anchor_sinks=2, witness=True, pin_separate=True
        )
        # writer(1) + seal_escrow(1) + anchor_sinks(2) + witness(1) + pin_separate(1)
        assert separation_degree(topology) == 6

    def test_minimal_topology_is_writer_alone(self) -> None:
        topology = SeparationTopology(
            seal_escrow=False, anchor_sinks=0, witness=False, pin_separate=False
        )
        assert separation_degree(topology) == 1

    def test_declared_degree_is_never_zero(self) -> None:
        # The writer always exists and is never optional, so any declared
        # topology contributes at least 1 — regardless of how bare it is.
        topology = SeparationTopology(
            seal_escrow=False, anchor_sinks=0, witness=False, pin_separate=False
        )
        assert separation_degree(topology) != 0


class TestMonotonicity:
    """τ is monotonic by construction: every term in the formula is
    non-negative, so flipping any single authority from absent to present
    (or adding one more anchor sink) can never decrease the degree. This
    walks a small but real range of topologies rather than asserting the
    property abstractly."""

    def test_flipping_any_single_field_never_decreases_degree(self) -> None:
        for anchor_sinks in range(0, 4):
            for seal_escrow, witness, pin_separate in itertools.product(
                [False, True], repeat=3
            ):
                base = SeparationTopology(
                    seal_escrow=seal_escrow,
                    anchor_sinks=anchor_sinks,
                    witness=witness,
                    pin_separate=pin_separate,
                )
                base_degree = separation_degree(base)
                assert base_degree is not None

                # Flip seal_escrow False -> True (skip if already True).
                if not seal_escrow:
                    bumped = dataclasses.replace(base, seal_escrow=True)
                    assert separation_degree(bumped) >= base_degree

                # Flip witness False -> True.
                if not witness:
                    bumped = dataclasses.replace(base, witness=True)
                    assert separation_degree(bumped) >= base_degree

                # Flip pin_separate False -> True.
                if not pin_separate:
                    bumped = dataclasses.replace(base, pin_separate=True)
                    assert separation_degree(bumped) >= base_degree

                # Increment anchor_sinks by one more external sink.
                bumped = dataclasses.replace(base, anchor_sinks=anchor_sinks + 1)
                assert separation_degree(bumped) >= base_degree


class TestRenderSeparationDegree:
    def test_none_renders_as_not_declared(self) -> None:
        assert render_separation_degree(None) == "not declared"

    def test_declared_degree_renders_as_its_number(self) -> None:
        assert render_separation_degree(6) == "6"
        assert render_separation_degree(1) == "1"

    def test_not_declared_never_renders_as_zero_or_one(self) -> None:
        rendered = render_separation_degree(None)
        assert rendered != "0"
        assert rendered != "1"


class TestCountedAuthorities:
    """The enumeration a report must carry alongside the bare number — τ is
    exactly the claim an assessor can check by asking who operates what, so
    the report has to name which authorities were counted, not just how
    many (waxseal-mfi, closing conformance.md gap G1)."""

    def test_none_topology_is_none(self) -> None:
        # Same rule 5 discipline as separation_degree: "not measured" must
        # never collapse into an empty tuple, which would read as "measured,
        # and nothing counted".
        assert counted_authorities(None) is None

    def test_writer_is_always_first_and_always_present(self) -> None:
        topology = SeparationTopology(
            seal_escrow=False, anchor_sinks=0, witness=False, pin_separate=False
        )
        counted = counted_authorities(topology)
        assert counted is not None
        assert counted[0] == ("writer", 1)
        assert len(counted) == 1

    def test_full_topology_enumerates_every_authority(self) -> None:
        topology = SeparationTopology(
            seal_escrow=True, anchor_sinks=2, witness=True, pin_separate=True
        )
        counted = counted_authorities(topology)
        assert counted == (
            ("writer", 1),
            ("seal_escrow", 1),
            ("anchor_sinks", 2),
            ("witness", 1),
            ("pin_separate", 1),
        )

    def test_undeclared_anchor_sinks_are_excluded_not_zero_valued(self) -> None:
        # anchor_sinks=0 contributes nothing, so it must not appear in the
        # enumeration at all — a caller printing "anchor_sinks(0)" would
        # imply a sink was declared and found to be zero.
        topology = SeparationTopology(
            seal_escrow=False, anchor_sinks=0, witness=True, pin_separate=False
        )
        counted = counted_authorities(topology)
        assert counted is not None
        names = [name for name, _ in counted]
        assert "anchor_sinks" not in names
        assert "witness" in names

    def test_sum_of_counted_equals_separation_degree(self) -> None:
        topology = SeparationTopology(
            seal_escrow=True, anchor_sinks=3, witness=False, pin_separate=True
        )
        counted = counted_authorities(topology)
        assert counted is not None
        assert sum(n for _, n in counted) == separation_degree(topology)


class TestRenderCountedAuthorities:
    def test_none_renders_as_not_declared(self) -> None:
        assert render_counted_authorities(None) == "not declared"

    def test_full_topology_names_every_authority_and_the_total(self) -> None:
        topology = SeparationTopology(
            seal_escrow=True, anchor_sinks=2, witness=True, pin_separate=False
        )
        rendered = render_counted_authorities(counted_authorities(topology))
        assert rendered == "writer(1) + seal_escrow(1) + anchor_sinks(2) + witness(1) = 5"

    def test_writer_alone_renders_without_a_plus(self) -> None:
        topology = SeparationTopology(
            seal_escrow=False, anchor_sinks=0, witness=False, pin_separate=False
        )
        rendered = render_counted_authorities(counted_authorities(topology))
        assert rendered == "writer(1) = 1"

    def test_not_declared_never_renders_as_zero_or_one(self) -> None:
        rendered = render_counted_authorities(None)
        assert rendered != "0"
        assert rendered != "1"


class TestSeparationTopologyIsFrozen:
    def test_mutating_a_field_raises(self) -> None:
        topology = SeparationTopology(
            seal_escrow=True, anchor_sinks=1, witness=False, pin_separate=False
        )
        with pytest.raises(dataclasses.FrozenInstanceError):
            topology.seal_escrow = False  # type: ignore[misc]


class TestSeparationShortfall:
    """Declared vs. observed, on the only two dimensions a CLI run can check.

    ``seal_escrow`` and ``pin_separate`` are declared-only claims — nothing in
    the trail or its sidecars can confirm or contradict them — so they must
    never move this function's answer, on either side of the boundary.
    """

    def test_shortfall_when_declared_anchor_sinks_exceeds_observed(self) -> None:
        declared = SeparationTopology(
            seal_escrow=False, anchor_sinks=2, witness=False, pin_separate=False
        )
        assert (
            separation_shortfall(
                declared, observed_anchor_sinks=1, observed_witness_consistent=True
            )
            is True
        )

    def test_shortfall_when_witness_declared_but_not_observed_consistent(self) -> None:
        declared = SeparationTopology(
            seal_escrow=False, anchor_sinks=0, witness=True, pin_separate=False
        )
        assert (
            separation_shortfall(
                declared, observed_anchor_sinks=0, observed_witness_consistent=False
            )
            is True
        )

    def test_no_shortfall_when_declared_matches_observed(self) -> None:
        declared = SeparationTopology(
            seal_escrow=False, anchor_sinks=2, witness=True, pin_separate=False
        )
        assert (
            separation_shortfall(
                declared, observed_anchor_sinks=2, observed_witness_consistent=True
            )
            is False
        )

    def test_no_shortfall_when_declared_is_less_than_observed(self) -> None:
        declared = SeparationTopology(
            seal_escrow=False, anchor_sinks=1, witness=False, pin_separate=False
        )
        assert (
            separation_shortfall(
                declared, observed_anchor_sinks=3, observed_witness_consistent=True
            )
            is False
        )

    def test_seal_escrow_and_pin_separate_never_affect_the_result(self) -> None:
        # Vary the two fields this function must ignore across every
        # combination, holding the checkable dimensions fixed at "no
        # shortfall", and confirm the outcome never changes.
        for seal_escrow, pin_separate in itertools.product([False, True], repeat=2):
            declared = SeparationTopology(
                seal_escrow=seal_escrow,
                anchor_sinks=1,
                witness=True,
                pin_separate=pin_separate,
            )
            assert (
                separation_shortfall(
                    declared, observed_anchor_sinks=1, observed_witness_consistent=True
                )
                is False
            )

        # Same sweep, this time with a real shortfall on anchor_sinks — the
        # two ignored fields still must not change the (now True) answer.
        for seal_escrow, pin_separate in itertools.product([False, True], repeat=2):
            declared = SeparationTopology(
                seal_escrow=seal_escrow,
                anchor_sinks=5,
                witness=True,
                pin_separate=pin_separate,
            )
            assert (
                separation_shortfall(
                    declared, observed_anchor_sinks=1, observed_witness_consistent=True
                )
                is True
            )
