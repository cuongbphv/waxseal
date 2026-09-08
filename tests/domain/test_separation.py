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
    ledger_shortfall,
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
            for seal_escrow, witness, pin_separate in itertools.product([False, True], repeat=3):
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
                    bumped_degree = separation_degree(bumped)
                    assert bumped_degree is not None
                    assert bumped_degree >= base_degree

                # Flip witness False -> True.
                if not witness:
                    bumped = dataclasses.replace(base, witness=True)
                    bumped_degree = separation_degree(bumped)
                    assert bumped_degree is not None
                    assert bumped_degree >= base_degree

                # Flip pin_separate False -> True.
                if not pin_separate:
                    bumped = dataclasses.replace(base, pin_separate=True)
                    bumped_degree = separation_degree(bumped)
                    assert bumped_degree is not None
                    assert bumped_degree >= base_degree

                # Increment anchor_sinks by one more external sink.
                bumped = dataclasses.replace(base, anchor_sinks=anchor_sinks + 1)
                bumped_degree = separation_degree(bumped)
                assert bumped_degree is not None
                assert bumped_degree >= base_degree


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


class TestLedgerField:
    """waxseal-fg4.45: F4's on-chain ledger dimension, wired into τ.

    ``ledger`` is the one field on ``SeparationTopology`` that is itself
    optional (``bool | None``), because it was added after the type had
    already shipped: every existing construction site, and every
    ``declared_topology`` already on disk, must keep meaning exactly what it
    meant before this bead (CLAUDE.md's append-only rule, and rule 5 one
    field down — a topology that never mentions ledger must never be read as
    having declared it false).
    """

    def test_omitting_ledger_is_none_not_false(self) -> None:
        topology = SeparationTopology(
            seal_escrow=False, anchor_sinks=0, witness=False, pin_separate=False
        )
        assert topology.ledger is None
        assert topology.ledger is not False

    def test_a_declared_ledger_raises_the_degree_by_one(self) -> None:
        # This is the falsifiability receipt for the tau-wiring itself: with
        # `ledger: bool` NOT summed in `separation_degree`, this assertion
        # is exactly what would fail (the two sides would be equal instead).
        without = SeparationTopology(
            seal_escrow=False, anchor_sinks=0, witness=False, pin_separate=False
        )
        with_ledger = dataclasses.replace(without, ledger=True)
        without_degree = separation_degree(without)
        assert without_degree is not None
        assert separation_degree(with_ledger) == without_degree + 1

    def test_undeclared_and_declared_false_ledger_contribute_the_same_degree(self) -> None:
        undeclared = SeparationTopology(
            seal_escrow=False, anchor_sinks=0, witness=False, pin_separate=False
        )
        declared_false = dataclasses.replace(undeclared, ledger=False)
        # The sum cannot and need not tell "never asked" from "asked,
        # answered no" apart — both claim zero ledger authorities.
        assert separation_degree(undeclared) == separation_degree(declared_false)
        # But the two remain distinguishable on the field itself (rule 5):
        # only this check, not the sum, is where the difference must show.
        assert undeclared.ledger is None
        assert declared_false.ledger is False

    def test_ledger_is_excluded_from_counted_authorities_unless_true(self) -> None:
        undeclared = SeparationTopology(
            seal_escrow=False, anchor_sinks=0, witness=False, pin_separate=False
        )
        declared_false = dataclasses.replace(undeclared, ledger=False)
        declared_true = dataclasses.replace(undeclared, ledger=True)
        undeclared_counted = counted_authorities(undeclared)
        declared_false_counted = counted_authorities(declared_false)
        declared_true_counted = counted_authorities(declared_true)
        assert undeclared_counted is not None
        assert declared_false_counted is not None
        assert declared_true_counted is not None
        assert "ledger" not in [n for n, _ in undeclared_counted]
        assert "ledger" not in [n for n, _ in declared_false_counted]
        assert "ledger" in [n for n, _ in declared_true_counted]

    def test_full_topology_with_ledger_enumerates_it_last(self) -> None:
        topology = SeparationTopology(
            seal_escrow=True, anchor_sinks=2, witness=True, pin_separate=True, ledger=True
        )
        assert counted_authorities(topology) == (
            ("writer", 1),
            ("seal_escrow", 1),
            ("anchor_sinks", 2),
            ("witness", 1),
            ("pin_separate", 1),
            ("ledger", 1),
        )
        assert separation_degree(topology) == 7


class TestLedgerShortfall:
    """``ledger_shortfall``: a declared ledger authority vs. what THIS run's
    own ledger check (``waxseal verify --rpc/--liveness/--registry``)
    corroborated — the ledger dimension's own ``separation_shortfall``, kept
    as a sibling function rather than a third parameter because it is
    measured independently of anchors and witnesses (see
    ``separation_shortfall``'s docstring).
    """

    def test_shortfall_when_declared_but_not_corroborated(self) -> None:
        declared = SeparationTopology(
            seal_escrow=False,
            anchor_sinks=0,
            witness=False,
            pin_separate=False,
            ledger=True,
        )
        assert ledger_shortfall(declared, observed_ledger_ok=False) is True

    def test_no_shortfall_when_declared_and_corroborated(self) -> None:
        declared = SeparationTopology(
            seal_escrow=False,
            anchor_sinks=0,
            witness=False,
            pin_separate=False,
            ledger=True,
        )
        assert ledger_shortfall(declared, observed_ledger_ok=True) is False

    def test_no_shortfall_when_never_declared_even_if_observed_false(self) -> None:
        # bool(None) is False: an undeclared ledger never falls short of an
        # authority it never claimed — the same rule 5 discipline
        # separation_shortfall already gives seal_escrow/pin_separate.
        undeclared = SeparationTopology(
            seal_escrow=False, anchor_sinks=0, witness=False, pin_separate=False
        )
        assert ledger_shortfall(undeclared, observed_ledger_ok=False) is False

    def test_no_shortfall_when_declared_false_even_if_observed_false(self) -> None:
        declared_false = SeparationTopology(
            seal_escrow=False,
            anchor_sinks=0,
            witness=False,
            pin_separate=False,
            ledger=False,
        )
        assert ledger_shortfall(declared_false, observed_ledger_ok=False) is False
