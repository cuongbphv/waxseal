"""Cost-optimal anchoring cadence: how often *should* this trail anchor.

Every prior module in this package answers "is the chain intact" after the
fact. This one answers how often the trail should anchor. `waxseal cadence`
prints the number; the closed form below is where it comes from. The paper
recorded the gap by name ("Nothing in `src/` computes a cadence"); this
module is that gap closed, the same move `fingerprint.py` made for a
hand-typed `hash_version`.

The trade-off it closes: anchor too rarely and the unattested tail of the
trail is long, and an attacker who compromises the writer gets a wide window to
rewrite entries no external anchor has yet witnessed. Anchor too often and
the marginal cost `c` per anchor operation is paid for no additional
protection, since the compromise hazard `rho` did not get any more likely to
land inside a shorter window. Treating anchoring cadence `N` (entries per
anchor) as a free parameter and minimizing

    C(N) = c*lam/N + M*w*rho*(N-1)/2

over it has a closed form, `N* = sqrt(2*c*lam / (M*w*rho))`, the classical
EOQ-shaped optimum: an anchoring-cost term that falls in `N` set against an
exposure-cost term that rises in `N`, balanced at their crossing point. The
`(N-1)` term is the paper's own cost function: the discrete expected
exposure of entries in whole-entry anchoring steps, out of `N` entries only
the last is anchored immediately, so the average exposed count runs `0`
through `N-1`, not `1` through `N`. It is kept exactly in `total_cost`
because that value is what a caller actually pays. It is deliberately NOT
used in `exposure_cost_term` (which uses the continuous `M*w*rho*N/2`
instead): the first-order condition on `C(N)` differentiates the constant
`-M*w*rho/2` contributed by `-1` to zero, so it participates in neither
where `N*` sits nor in the algebraic identity that the two cost terms are
equal there. Substituting the discrete form into that identity would produce
an inequality off by a constant and mislabel a true algebraic equality as a
mere approximation, and the "don't approximate away the -1" instruction cuts
the other way here: precision means keeping the `-1` where the caller pays
for it (`total_cost`) and correctly leaving it out of where the FOC says it
does not belong (`exposure_cost_term`).

`w`, `rho`, and `c` are measurements only the operator holds: expected harm
per rewritable record, compromise hazard rate, marginal anchor cost. Every
function below takes them as required keyword arguments with no defaults;
inventing a "reasonable" number for any of them would be inventing a
measurement, exactly the class of mistake CLAUDE.md rule on redaction exists
to forbid for a different measurement (secrets). `M=1` is not a measurement
in that sense. It is the structural statement "one agent, no fleet
sharing", the same role `SeparationTopology`'s absence-vs-declared split
plays in `domain/separation.py`, so it is the one parameter here that may
default.

`clamp_to_feasible` is where CLAUDE.md rule 6 ("fail-open must be labelled")
applies to a pure computation instead of a redactor: `delta > t_max` means no
cadence exists that meets the operator's tolerated detection window, because
a single anchor's finality latency alone already exceeds it. Silently
clamping to `lam*t_max` anyway would hand back a number that looks like an
answer and hides that the anchor technology itself, not the choice of `N`,
is what's wrong, and `AnchorTechnologyInfeasible` makes that an explicit,
inspectable state instead of a nonsensical int.
"""

from __future__ import annotations

import math
from dataclasses import dataclass


class AnchorTechnologyInfeasible(Exception):
    """No cadence can meet the operator's tolerated detection window.

    Raised when `delta` (anchor finality latency) exceeds `t_max` (the
    operator's tolerated detection window): even anchoring on every single
    entry cannot finalize inside the window the operator asked for. The fix
    is a faster anchor technology or a larger `t_max`, never a smaller `N`,
    which is why this is its own labelled type rather than a `ValueError`
    indistinguishable from a bad-input mistake (see `TestClampToFeasible`,
    `test_infeasible_is_not_a_bare_valueerror`, in the test module).
    """

    def __init__(self, *, delta: float, t_max: float) -> None:
        self.delta = delta
        self.t_max = t_max
        super().__init__(
            f"infeasible: anchor finality latency delta={delta!r} exceeds the "
            f"operator's tolerated detection window t_max={t_max!r}; the anchor "
            "technology, not the cadence, does not meet this requirement"
        )


def _require_positive(**values: float) -> None:
    for name, value in values.items():
        if value <= 0:
            raise ValueError(
                f"{name} must be > 0 (operator-supplied measurement, got {value!r})"
            )


def _require_agent_count(M: int) -> None:
    if M < 1:
        raise ValueError(f"M must be >= 1 (got {M!r})")


def optimal_cadence(*, lam: float, c: float, w: float, rho: float, M: int = 1) -> float:
    """N* = sqrt(2*c*lam / (M*w*rho)), the unclamped closed-form optimum.

    `M` agents sharing one anchor over a Merkle root of their heads act, from
    the anchor's point of view, as a single stream at `M` times the
    exposure rate: each of the `M` heads is independently at risk over the
    same anchoring interval. That is the entire mechanism behind the fleet
    dividend (`fleet_dividend`). It is not a separate formula, it falls out
    of `M` appearing here.
    """
    _require_positive(lam=lam, c=c, w=w, rho=rho)
    _require_agent_count(M)
    return math.sqrt(2.0 * c * lam / (M * w * rho))


def fleet_dividend(n_star_single_agent: float, M: int) -> float:
    """Per-agent optimal cadence when `M` agents share one anchor.

    `n_star_single_agent / sqrt(M)`, equal by construction to calling
    `optimal_cadence(..., M=M)` directly (see
    `TestFleetDividend.test_matches_direct_computation_with_M`), expressed
    as its own function because "pooling agents means anchoring the shared
    root more often per agent, never less" is the property under test, and a
    caller should be able to state it without re-deriving `optimal_cadence`.
    Monotone non-increasing in `M` follows immediately: `sqrt(M)` in the
    denominator only grows as `M` grows, the same way monotonicity in
    `domain/separation.py`'s `separation_degree` falls out of every term
    there being non-negative rather than needing a separate proof.
    """
    _require_agent_count(M)
    return n_star_single_agent / math.sqrt(M)


def anchor_cost_term(n: float, *, lam: float, c: float) -> float:
    """The anchoring-cost half of `C(N)`: `c*lam/n`."""
    return c * lam / n


def exposure_cost_term(n: float, *, w: float, rho: float, M: int = 1) -> float:
    """The exposure-cost half of the balance property: `M*w*rho*n/2`.

    Continuous form (`n/2`, not the discrete `(n-1)/2` `total_cost` uses),
    see the module docstring for why the `-1` correctly drops out of this
    specific identity rather than being approximated away.
    """
    return M * w * rho * n / 2.0


def total_cost(n: float, *, lam: float, c: float, w: float, rho: float, M: int = 1) -> float:
    """`C(N) = c*lam/N + M*w*rho*(N-1)/2`, the paper's cost function, exact.

    Kept with its discrete `-1` term because this is the number a caller
    actually pays, unlike `exposure_cost_term`'s continuous form used only
    for the balance identity at `N*`.
    """
    return c * lam / n + M * w * rho * (n - 1.0) / 2.0


def flatness_bound(x: float) -> float:
    """`C(N)/C(N*) ~= 0.5*(x + 1/x)` for `x = N/N*`, the usability payoff.

    Pure function of the ratio alone, independent of `lam/c/w/rho/M`: this
    is the paper's asymptotic shape, exact in the continuous cost function
    and accurate to the discrete `total_cost` whenever `N*` is not tiny
    (the `-1` term's relative contribution shrinks as `N*` grows; see the
    module docstring). At `x=2` this is `1.25` (a cadence off by a factor of
    2 costs ~25% more than optimal); at `x=3` it is `5/3` (~67% more), so
    the concrete numbers the bead asks this module make assertable.
    """
    return 0.5 * (x + 1.0 / x)


def clamp_to_feasible(n_star: float, *, lam: float, delta: float, t_max: float) -> float:
    """`N_opt = clamp(N*, lam*delta, lam*t_max)`, or raise if infeasible.

    `delta > t_max` means the floor exceeds the ceiling. See
    `AnchorTechnologyInfeasible`. `delta == t_max` is the boundary and is
    feasible (floor equals ceiling, a single valid cadence), so the check is
    strictly-greater, not greater-or-equal.
    """
    if delta > t_max:
        raise AnchorTechnologyInfeasible(delta=delta, t_max=t_max)
    lower = lam * delta
    upper = lam * t_max
    return min(max(n_star, lower), upper)


@dataclass(frozen=True, slots=True)
class CadencePlan:
    """A fully-computed cadence recommendation: the optimum, its clamp, and
    the balance terms at the (unclamped) optimum, bundled for a caller (such
    as the `waxseal cadence` CLI command a later bead wires up) that wants
    one call instead of assembling the pieces above by hand.
    """

    n_star: float
    n_opt: float
    lower_bound: float
    upper_bound: float
    anchor_term: float
    exposure_term: float


def plan_cadence(
    *, lam: float, c: float, w: float, rho: float, M: int = 1, delta: float, t_max: float
) -> CadencePlan:
    """Compute `N*`, clamp it to `[lam*delta, lam*t_max]`, and report the
    balance terms at `N*`, or raise `AnchorTechnologyInfeasible` if
    `delta > t_max`. Raises before doing any of the arithmetic that would
    otherwise produce a number nobody asked for.
    """
    if delta > t_max:
        raise AnchorTechnologyInfeasible(delta=delta, t_max=t_max)
    n_star = optimal_cadence(lam=lam, c=c, w=w, rho=rho, M=M)
    n_opt = clamp_to_feasible(n_star, lam=lam, delta=delta, t_max=t_max)
    return CadencePlan(
        n_star=n_star,
        n_opt=n_opt,
        lower_bound=lam * delta,
        upper_bound=lam * t_max,
        anchor_term=anchor_cost_term(n_star, lam=lam, c=c),
        exposure_term=exposure_cost_term(n_star, w=w, rho=rho, M=M),
    )
