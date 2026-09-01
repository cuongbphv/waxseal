"""Which rung of the attacker-capability ladder a configuration stops.

docs/security/threat-model.md section 5 tabulates six attacker capabilities
against what stops each. This module turns what a `waxseal preflight` run
could SEE into that table's own language, and nothing more: it produces no
verdict about the chain, and every fact it re-presents was measured
elsewhere (`adapters/anchors.py`'s records, `domain/separation.py`'s tau, the
pin state). A second verdict source is something an operator would have to
reconcile against `verify`, so there is not one here.

The reading of the table this module commits to, stated because the table's
prose does not spell it out and two readings are possible. Rung 2's attacker
holds "trail + keyfile" and is stopped by "anchors: an external record of the
old root"; rung 3's holds "trail + keyfile + `.anchors`" and is stopped by an
"external anchor: the TSA / calendar / witness / ledger holds its own copy".
"External" on rung 2 therefore means external to the TRAIL FILE — any
`.anchors` record at all, the local `file` sink included, is a record that
attacker does not hold — and only on rung 3 does it mean external to the
HOST. The rejected reading, "external means off-host on both rows", would
make rungs 2 and 3 require exactly the same thing, and the table would have
no reason to carry two rows.

The ledger dimension (waxseal-fg4.45, F4's on-chain anchor/liveness/registry
layer) joins rung 3 the same way a witness already does, rather than
becoming a seventh row: it is one more record kept under a DIFFERENT
administrative authority than the trail's writer, which is exactly what
"external anchor" already names in general terms, and the six-row table
itself (threat-model.md section 5) is not this bead's to extend — that is
F5, an explicit, separately-approved SPEC append.

Four states, not two. A rung's stopper is PRESENT, ABSENT, NOT MEASURED, or —
for the top two rungs — there is NO MECHANISM at all. NOT MEASURED is the
state that earns this module: a preflight run contacts no witness and holds no
seal key, so "no witness confirmed" is a fact about the run, never a fact
about the deployment, and an `.anchors` sidecar this build cannot parse is not
zero sinks. Collapsing either into ABSENT is the false-confidence half of
CLAUDE.md's collapse theorem, which is what "migration 060" and beads v1.2.2
each produced from a different direction.

PRESENT means the mechanism the table names is CONFIGURED, not that it
currently checks out — checking is `waxseal verify`'s job, and preflight
holds neither the seal key nor a network connection to do it. The renderer
says so in the output rather than leaving a reader to assume the stronger
claim.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from itertools import takewhile
from typing import Final


class RungState(enum.Enum):
    """Whether the stopper a ladder row names is there.

    Not a severity and not a verdict: `PRESENT`/`ABSENT` are measurements,
    `NOT_MEASURED` is the absence of one, and `NO_MECHANISM` is a property of
    the ladder itself (the top two rows have no answer to give, in any
    configuration). Keeping the last two apart matters: "this run could not
    look" and "there is nothing to look for" call for entirely different
    operator actions.
    """

    PRESENT = "present"
    ABSENT = "absent"
    NOT_MEASURED = "not-measured"
    NO_MECHANISM = "no-mechanism"


_STATE_LABEL: Final[dict[RungState, str]] = {
    RungState.PRESENT: "PRESENT",
    RungState.ABSENT: "ABSENT",
    RungState.NOT_MEASURED: "NOT MEASURED",
    RungState.NO_MECHANISM: "NO MECHANISM",
}


@dataclass(frozen=True, slots=True)
class Observed:
    """One thing a preflight run looked for: what it found, and why.

    ``found`` is ``None`` when the run could not measure this at all, which is
    a third value and never a synonym for ``False`` (CLAUDE.md rule 5).
    ``detail`` is never optional, following `adapters/s3.py`'s ``WormReport``:
    a bare "not measured" gives an operator nothing to act on, and "no witness
    was contacted" and "the sidecar would not parse" call for different fixes.
    """

    found: bool | None
    detail: str


@dataclass(frozen=True, slots=True)
class PreflightObservation:
    """Everything a run saw, one field per mechanism the ladder names.

    Path knowledge stays in `cli.py`, which fills each ``detail`` in: this
    module must not learn where a sidecar lives (the layer DAG forbids the
    domain any filesystem knowledge at all).

    ``ledger`` (waxseal-fg4.45, F4's on-chain ledger dimension) joins
    ``witness`` at rung 3 rather than gaining a rung of its own: threat-model.md
    section 5 still tabulates six rows, unchanged by this bead (extending
    that table is F5, an explicit, separately-approved SPEC append this bead
    is not), and a ledger — like a witness — is one more record kept under a
    DIFFERENT administrative authority than the process that writes the
    trail, which is exactly what rung 3's stopper already names in general
    terms ("an external record"). Never network-reachable from `preflight`
    (see the module docstring: this command opens no connection at all), so
    it is ``NOT_MEASURED`` the same way ``witness`` always is here.
    """

    seal: Observed
    anchor_records: Observed
    external_anchor: Observed
    aggregate_binding: Observed
    witness: Observed
    ledger: Observed


@dataclass(frozen=True, slots=True)
class Rung:
    """One row of threat-model.md section 5, plus what this run found for it.

    ``needs`` is what would make the stopper PRESENT, and ``None`` exactly
    when no configuration can (rungs 5 and 6). ``None`` here is a stated
    property of the ladder, not a missing string: a renderer that printed an
    empty ``needs`` as advice would promise a fix that does not exist.
    """

    number: int
    attacker_holds: str
    stopper: str
    state: RungState
    detail: str
    needs: str | None


@dataclass(frozen=True, slots=True)
class LadderReading:
    """The whole table plus the one sentence an operator quotes from it.

    ``stops_at`` counts LEADING PRESENT rungs, not the highest one that
    happens to be present. "Stops an attacker at rung N" is a claim about
    every attacker weaker than rung N+1, so a gap lower down caps it.
    Understating is the safe direction, but it must not hide anything, which
    is what ``present_above_cap`` is for: a mechanism the operator did
    configure is still reported, it just does not raise the headline.

    ``next_rung`` is total, not optional: rungs 5 and 6 are permanently
    ``NO_MECHANISM``, so ``stops_at`` can never exceed 4 and index
    ``stops_at`` is always in range.
    """

    rungs: tuple[Rung, ...]
    stops_at: int
    next_rung: Rung
    present_above_cap: tuple[int, ...]


_NEEDS_SEAL: Final = (
    "a forward-secure seal (SPEC 11) — open the trail with an attestor, so "
    "every append writes an attestation beside it"
)
_NEEDS_ANCHOR: Final = (
    "at least one anchor record (SPEC 9) — `waxseal anchor <trail>`, or "
    "`anchor_every=N` on the writer"
)
_NEEDS_EXTERNAL: Final = (
    "an anchor sink that keeps its own copy off this host — `waxseal anchor "
    "--tsa-url URL` (RFC 3161, SPEC 17), `--ots-calendar URL` "
    "(OpenTimestamps, SPEC 18), a witness (`--witness URL`, SPEC 14), or an "
    "on-chain ledger (`waxseal anchor --evm-rpc URL --evm-liveness ADDR`, F4)"
)
_NEEDS_AGGREGATE: Final = (
    "an aggregate binding inside an anchored checkpoint (SPEC 15) — anchor a "
    "SEALED trail, so the record carries `agg_commit`"
)

_DETAIL_ANCHOR_SINK_HELD: Final = (
    "an attacker who holds the anchor sink itself is outside what any local "
    "mechanism can reach"
)
_DETAIL_COLLUSION: Final = (
    "collusion between the writer and every witness leaves no independent "
    "copy left to compare against"
)

_OPERATIONAL_REQUIREMENT: Final = (
    "The seal key, the anchor sink, the witness, and the ledger must each "
    "sit under a DIFFERENT administrative authority than the process that "
    "writes the trail; no configuration flag substitutes for that, and "
    "waxseal cannot check it for you (threat-model.md section 5)"
)

_CONTIGUOUS_MEANING: Final = (
    '"stops at rung N" is a CONTIGUOUS claim: an attacker weaker than rung '
    "N+1 includes every attacker below, so a missing stopper lower down caps "
    "it. PRESENT means the mechanism is CONFIGURED, not that it currently "
    "checks out — that is `waxseal verify`'s job."
)


def _state_of(*observed: Observed) -> RungState:
    """Combine the alternate stoppers of one rung (rung 3 now takes three:
    external anchor, witness, and — waxseal-fg4.45 — ledger).

    Order matters and is not arbitrary: one confirmed alternate is enough to
    stop the rung, so PRESENT wins first; otherwise a single unmeasured
    alternate is enough to make the whole rung unmeasured, because a run
    that did not look cannot report an absence it never established.
    """
    if any(o.found is True for o in observed):
        return RungState.PRESENT
    if any(o.found is None for o in observed):
        return RungState.NOT_MEASURED
    return RungState.ABSENT


def ladder_for(observation: PreflightObservation) -> LadderReading:
    """Read threat-model.md section 5's table against one observation."""
    rungs = (
        Rung(
            number=1,
            attacker_holds="the trail file only",
            stopper="seals: forging one needs the epoch key",
            state=_state_of(observation.seal),
            detail=observation.seal.detail,
            needs=_NEEDS_SEAL,
        ),
        Rung(
            number=2,
            attacker_holds="trail + keyfile",
            stopper="anchors: an external record of the old root",
            state=_state_of(observation.anchor_records),
            detail=observation.anchor_records.detail,
            needs=_NEEDS_ANCHOR,
        ),
        Rung(
            number=3,
            attacker_holds="trail + keyfile + `.anchors`",
            stopper=(
                "external anchor: the TSA / calendar / witness / ledger holds "
                "its own copy"
            ),
            state=_state_of(
                observation.external_anchor, observation.witness, observation.ledger
            ),
            detail=(
                f"{observation.external_anchor.detail}; {observation.witness.detail}; "
                f"{observation.ledger.detail}"
            ),
            needs=_NEEDS_EXTERNAL,
        ),
        Rung(
            number=4,
            attacker_holds="trail + keyfile + `.sealagg`",
            stopper="the aggregate binding in an anchored checkpoint (SPEC 15)",
            state=_state_of(observation.aggregate_binding),
            detail=observation.aggregate_binding.detail,
            needs=_NEEDS_AGGREGATE,
        ),
        Rung(
            number=5,
            attacker_holds="all local files + the anchor sink",
            stopper="nothing this library can offer",
            state=RungState.NO_MECHANISM,
            detail=_DETAIL_ANCHOR_SINK_HELD,
            needs=None,
        ),
        Rung(
            number=6,
            attacker_holds="all local files + every witness",
            stopper="nothing — this is the collusion case",
            state=RungState.NO_MECHANISM,
            detail=_DETAIL_COLLUSION,
            needs=None,
        ),
    )
    # takewhile rather than a loop with a break: the loop's fall-through arc
    # is unreachable (rung 5 is never PRESENT), so a `for`/`break` here would
    # leave a partial branch no test could ever close.
    stops_at = len(tuple(takewhile(lambda r: r.state is RungState.PRESENT, rungs)))
    return LadderReading(
        rungs=rungs,
        stops_at=stops_at,
        next_rung=rungs[stops_at],
        present_above_cap=tuple(
            r.number
            for r in rungs
            if r.number > stops_at and r.state is RungState.PRESENT
        ),
    )


def render_ladder(reading: LadderReading) -> list[str]:
    """The lines `waxseal preflight` prints for the ladder.

    A pure string rule kept beside the logic that produced it, the same
    arrangement `domain/separation.py` uses for tau, so the CLI cannot invent
    a second wording for a state.
    """
    lines = [
        "attacker-capability ladder (docs/security/threat-model.md section 5)",
    ]
    for rung in reading.rungs:
        label = _STATE_LABEL[rung.state]
        lines.append(
            f"  rung {rung.number}  {label:<12}  attacker holds {rung.attacker_holds} "
            f"— stopped by {rung.stopper}"
        )
        lines.append(f"                        observed: {rung.detail}")
    if reading.stops_at == 0:
        lines.append(
            "this configuration stops an attacker at rung 0 — rung 1's own "
            "stopper is not PRESENT."
        )
    else:
        lines.append(
            f"this configuration stops an attacker at rung {reading.stops_at}: "
            f"every stopper this table names for rungs 1 through "
            f"{reading.stops_at} is PRESENT."
        )
    lines.append(_CONTIGUOUS_MEANING)
    nxt = reading.next_rung
    if nxt.state is RungState.NOT_MEASURED:
        lines.append(
            f"rung {nxt.number}: NOT MEASURED this run — {nxt.detail}. This run "
            "cannot say whether it is stopped, and NOT MEASURED is not ABSENT."
        )
    elif nxt.needs is None:
        lines.append(
            f"rung {nxt.number}: no configuration raises this rung — "
            f"{nxt.stopper}. {_OPERATIONAL_REQUIREMENT}"
        )
    else:
        lines.append(f"rung {nxt.number} needs: {nxt.needs}")
    if reading.present_above_cap:
        above = ", ".join(str(n) for n in reading.present_above_cap)
        lines.append(
            f"note: rung(s) {above} have a stopper PRESENT above the cap — "
            "configured, and reported here, but they do not raise the number "
            "above, because a stopper below them is missing."
        )
    return lines
