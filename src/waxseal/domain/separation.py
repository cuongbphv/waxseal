"""Separation degree: how many independent authorities stand behind a trail.

τ (tau) counts the operator's blast-radius reduction: a single compromised
authority should not be able to both write the trail AND rewrite the
evidence used to check it. ``writer`` always exists and is never optional,
so it is not a field on ``SeparationTopology``. It contributes a fixed 1 to
every declared degree, the same way it is present whether or not anyone
ever names it.

The other four authorities (seal escrow, external anchor sinks, a witness, a
separately-stored pin) are declared or not. CLAUDE.md rule 5 ("None != 0,
unverifiable != tampered, unmeasured != absent ... applies to any future
metric") is this module's entire contract: an operator who never declared a
topology has not measured separation, which is a different fact from having
measured it and found the degree to be the smallest possible values. That is
why "not declared" is represented by the ABSENCE of a ``SeparationTopology``
(``None`` at the call site), never by a struct carrying defaults or an
``is_declared`` flag, because a flag is one more field a caller could fail to check,
where ``None`` cannot be silently coerced into an int.

Parsing ``declared_topology`` out of pin-state JSON (where the "all 4
subfields required together" rule is enforced) lives in ``domain/pinning.py``.
This module only computes the degree from a topology however it was
constructed in memory.

Reachability, stated because it is not what a reader assumes: ``cli.py``'s
``--declare-topology`` (waxseal-ekd) is the CLI writer for a
``declared_topology``, taking all four subfields together in one spec string
(an operator can still write the pin state file's JSON by hand instead, and
either route produces the same shape SPEC section 13.1 specifies (that gap
was tracked as G2 in docs/paper/conformance.md; it is closed as of
waxseal-ekd). ``SeparationTopology``, ``separation_degree``, and ``Verdict``
were opened to the frozen public API, and ``waxseal report``/``waxseal
verify --pin`` now print τ and its enumerated breakdown, closing the G1
gap in docs/paper/conformance.md is closed as of waxseal-mfi.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class SeparationTopology:
    """An operator-declared separation topology, always fully populated.

    Every field here is required; there is no partial or default-valued
    instance. The "not declared at all" case is ``None``, not this type.
    """

    seal_escrow: bool
    anchor_sinks: int
    witness: bool
    pin_separate: bool


def separation_degree(topology: SeparationTopology | None) -> int | None:
    """Count independent authorities, or ``None`` if none were declared.

    ``None`` in, ``None`` out: "not measured", per rule 5. Never coerce this
    to ``0`` or ``1``; that collapse is exactly the false-confidence bug the
    two-incident preamble in CLAUDE.md exists to rule out.

    When a topology is given, the degree is ``writer`` (always 1, not a
    field) plus each declared authority: monotonicity falls out of the
    formula itself, since every term is non-negative. Adding an authority,
    or one more anchor sink, cannot lower the sum.
    """
    if topology is None:
        return None
    return (
        1  # writer: always present, never optional, not a declared/undeclared thing
        + int(topology.seal_escrow)
        + topology.anchor_sinks
        + int(topology.witness)
        + int(topology.pin_separate)
    )


def separation_shortfall(
    declared: SeparationTopology,
    *,
    observed_anchor_sinks: int,
    observed_witness_consistent: bool,
) -> bool:
    """True when the declared topology claims more independent authorities,
    on the two dimensions this build can actually check, than this run
    observed.

    ``seal_escrow`` (who holds the attestation key) and ``pin_separate``
    (where the pin file physically lives) are declared-only claims: nothing
    in the trail or its sidecars can corroborate or contradict them, so they
    are never part of this comparison. That is a permanent limitation of what
    a CLI run can see, not an oversight: comparing against them would mean
    inventing evidence this process never had.
    """
    return declared.anchor_sinks > observed_anchor_sinks or (
        declared.witness and not observed_witness_consistent
    )


def render_separation_degree(degree: int | None) -> str:
    """Render τ for a human, keeping "not measured" visibly distinct from
    any number, including the numbers 0 and 1 it must never be confused
    with (rule 5). This is the pure string rule the reporting path must
    reuse rather than reinvent.

    Called from ``domain/report.py`` (``waxseal report``, both renderings)
    and ``cli.py`` (``waxseal verify --pin``) as of waxseal-mfi, which closed
    conformance.md gap G1: a report now states τ, alongside the enumeration
    ``render_counted_authorities`` below prints, rather than computing it and
    never printing it.
    """
    if degree is None:
        return "not declared"
    return str(degree)


def counted_authorities(
    topology: SeparationTopology | None,
) -> tuple[tuple[str, int], ...] | None:
    """Which authorities contribute to τ, and each one's contribution: the
    enumeration the paper's τ recommendation asks for alongside the bare
    number, since which authorities are counted is exactly the claim an
    assessor can check by asking who operates what.

    ``writer`` is always first and always contributes 1, per this module's
    docstring on why it is not a ``SeparationTopology`` field. An authority
    declared but contributing zero (``anchor_sinks=0``) is omitted rather
    than listed at ``0``: printing ``anchor_sinks(0)`` would read as "a sink
    was declared and found empty", not "nothing here contributes".

    ``None`` in, ``None`` out, the same rule 5 discipline as
    ``separation_degree``: "not declared" must never collapse into an empty
    tuple, which would read as "declared, and nothing counted".
    """
    if topology is None:
        return None
    counted: list[tuple[str, int]] = [("writer", 1)]
    if topology.seal_escrow:
        counted.append(("seal_escrow", 1))
    if topology.anchor_sinks:
        counted.append(("anchor_sinks", topology.anchor_sinks))
    if topology.witness:
        counted.append(("witness", 1))
    if topology.pin_separate:
        counted.append(("pin_separate", 1))
    return tuple(counted)


def render_counted_authorities(counted: tuple[tuple[str, int], ...] | None) -> str:
    """Render the enumeration for a human: ``"writer(1) + anchor_sinks(2) +
    witness(1) = 4"``, naming which authorities contribute, not just the
    total ``render_separation_degree`` prints alone. ``"not declared"``
    mirrors that function's wording exactly, for the same undeclared input,
    so the two never drift apart on how "not measured" reads.
    """
    if counted is None:
        return "not declared"
    total = sum(n for _, n in counted)
    return " + ".join(f"{name}({n})" for name, n in counted) + f" = {total}"
