"""Cost-optimal anchoring cadence (domain/cadence.py).

`waxseal cadence` prints N* from operator-supplied measurements. These tests
are the falsifiable claims the paper makes about that closed form: the
balance property at N*, the flatness bound's concrete numbers (factor-of-2
off costs ~25% more, factor-of-3 off costs ~67% more), the labelled
infeasible state when the anchor technology itself cannot meet the
operator's tolerated detection window, and the monotone fleet dividend.
"""

from __future__ import annotations

import math

import pytest

from waxseal.domain.cadence import (
    AnchorTechnologyInfeasible,
    CadencePlan,
    anchor_cost_term,
    clamp_to_feasible,
    exposure_cost_term,
    flatness_bound,
    fleet_dividend,
    optimal_cadence,
    plan_cadence,
    total_cost,
)

# Chosen so N* ~= 63,245 -- large enough that the paper's C(N) discrete "-1"
# term (the exact expected-exposure correction for anchoring in whole-entry
# steps) is relatively negligible (~1.6e-5) next to the continuous terms, so
# the closed-form identities below can be asserted to a tight tolerance
# without smuggling in a large fudge factor that would hide a real bug.
LAM = 100_000.0
C = 2.0
W = 1.0
RHO = 0.0001


class TestOptimalCadence:
    def test_matches_closed_form(self) -> None:
        n_star = optimal_cadence(lam=LAM, c=C, w=W, rho=RHO)
        expected = math.sqrt(2 * C * LAM / (1 * W * RHO))
        assert math.isclose(n_star, expected, rel_tol=1e-12)

    def test_scales_with_M(self) -> None:
        n1 = optimal_cadence(lam=LAM, c=C, w=W, rho=RHO, M=1)
        n4 = optimal_cadence(lam=LAM, c=C, w=W, rho=RHO, M=4)
        # M enters under the sqrt in the denominator: quadrupling M halves N*.
        assert math.isclose(n4, n1 / 2, rel_tol=1e-9)

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"lam": 0.0, "c": C, "w": W, "rho": RHO},
            {"lam": -1.0, "c": C, "w": W, "rho": RHO},
            {"lam": LAM, "c": 0.0, "w": W, "rho": RHO},
            {"lam": LAM, "c": -1.0, "w": W, "rho": RHO},
            {"lam": LAM, "c": C, "w": 0.0, "rho": RHO},
            {"lam": LAM, "c": C, "w": -1.0, "rho": RHO},
            {"lam": LAM, "c": C, "w": W, "rho": 0.0},
            {"lam": LAM, "c": C, "w": W, "rho": -1.0},
        ],
    )
    def test_rejects_non_positive_operator_inputs(self, kwargs: dict[str, float]) -> None:
        # The "Khong lam" ban: w, rho, c (and lam, the fourth measured input)
        # are never defaulted or coerced into something computable -- a
        # non-positive value is a bad measurement, reported as ValueError,
        # never silently clamped into a usable number.
        with pytest.raises(ValueError):
            optimal_cadence(**kwargs)  # type: ignore[arg-type]

    def test_rejects_M_below_one(self) -> None:
        with pytest.raises(ValueError):
            optimal_cadence(lam=LAM, c=C, w=W, rho=RHO, M=0)


class TestBalanceProperty:
    """CLAUDE.md-style property: at N*, the anchoring-cost term and the
    exposure-cost term are equal, both to sqrt(c*lam*M*w*rho/2) -- this is
    the algebraic content of the first-order condition, not an approximation
    of it, so it holds to floating-point tightness rather than to a loose
    empirical tolerance.
    """

    def test_terms_are_equal_at_n_star(self) -> None:
        n_star = optimal_cadence(lam=LAM, c=C, w=W, rho=RHO)
        anchor_term = anchor_cost_term(n_star, lam=LAM, c=C)
        exposure_term = exposure_cost_term(n_star, w=W, rho=RHO)
        assert math.isclose(anchor_term, exposure_term, rel_tol=1e-9)

    def test_terms_match_closed_form_value(self) -> None:
        n_star = optimal_cadence(lam=LAM, c=C, w=W, rho=RHO)
        expected = math.sqrt(C * LAM * 1 * W * RHO / 2)
        assert math.isclose(anchor_cost_term(n_star, lam=LAM, c=C), expected, rel_tol=1e-9)
        assert math.isclose(exposure_cost_term(n_star, w=W, rho=RHO), expected, rel_tol=1e-9)

    def test_balance_holds_with_fleet_sharing(self) -> None:
        n_star = optimal_cadence(lam=LAM, c=C, w=W, rho=RHO, M=5)
        anchor_term = anchor_cost_term(n_star, lam=LAM, c=C)
        exposure_term = exposure_cost_term(n_star, w=W, rho=RHO, M=5)
        assert math.isclose(anchor_term, exposure_term, rel_tol=1e-9)


class TestFlatnessBound:
    """The paper's headline usability claim: guessing N within a factor of 2
    or 3 of N* is cheap; the cost curve is flat near the optimum. x=2 gives
    0.5*(2 + 0.5) = 1.25 (25% more); x=3 gives 0.5*(3 + 1/3) = 1.6666...
    (66.67% more, i.e. ~67%).
    """

    def test_pure_formula_values(self) -> None:
        assert math.isclose(flatness_bound(2.0), 1.25, rel_tol=1e-12)
        assert math.isclose(flatness_bound(3.0), 5.0 / 3.0, rel_tol=1e-12)
        assert math.isclose(flatness_bound(1.0), 1.0, rel_tol=1e-12)

    def test_actual_cost_ratio_matches_bound_at_factor_2(self) -> None:
        n_star = optimal_cadence(lam=LAM, c=C, w=W, rho=RHO)
        c_star = total_cost(n_star, lam=LAM, c=C, w=W, rho=RHO)
        c_double = total_cost(2 * n_star, lam=LAM, c=C, w=W, rho=RHO)
        ratio = c_double / c_star
        assert math.isclose(ratio, flatness_bound(2.0), rel_tol=1e-3)
        # ~25% more, not merely "close to the formula" in the abstract.
        assert 1.24 < ratio < 1.26

    def test_actual_cost_ratio_matches_bound_at_factor_3(self) -> None:
        n_star = optimal_cadence(lam=LAM, c=C, w=W, rho=RHO)
        c_star = total_cost(n_star, lam=LAM, c=C, w=W, rho=RHO)
        c_triple = total_cost(3 * n_star, lam=LAM, c=C, w=W, rho=RHO)
        ratio = c_triple / c_star
        assert math.isclose(ratio, flatness_bound(3.0), rel_tol=1e-3)
        assert 1.66 < ratio < 1.68

    def test_ratio_is_symmetric_in_x_and_1_over_x(self) -> None:
        n_star = optimal_cadence(lam=LAM, c=C, w=W, rho=RHO)
        c_star = total_cost(n_star, lam=LAM, c=C, w=W, rho=RHO)
        half = total_cost(n_star / 2, lam=LAM, c=C, w=W, rho=RHO)
        double = total_cost(n_star * 2, lam=LAM, c=C, w=W, rho=RHO)
        assert math.isclose(half / c_star, double / c_star, rel_tol=1e-3)

    def test_cost_at_n_star_is_the_minimum(self) -> None:
        # Convexity, exercised directly rather than assumed: any perturbation
        # away from N* costs strictly more.
        n_star = optimal_cadence(lam=LAM, c=C, w=W, rho=RHO)
        c_star = total_cost(n_star, lam=LAM, c=C, w=W, rho=RHO)
        for factor in (0.5, 0.9, 1.1, 2.0, 5.0):
            other = total_cost(n_star * factor, lam=LAM, c=C, w=W, rho=RHO)
            assert other > c_star


class TestClampToFeasible:
    def test_n_star_within_bounds_is_unchanged(self) -> None:
        n_star = optimal_cadence(lam=LAM, c=C, w=W, rho=RHO)
        n_opt = clamp_to_feasible(n_star, lam=LAM, delta=0.01, t_max=10.0)
        assert n_opt == n_star

    def test_clamped_to_floor_when_n_star_too_small(self) -> None:
        # A large delta (slow anchor finality) pushes the floor lam*delta
        # above a deliberately tiny N* (huge w*rho relative to c*lam).
        n_star = optimal_cadence(lam=10.0, c=0.001, w=1000.0, rho=1.0)
        floor = 10.0 * 5.0  # lam * delta
        assert n_star < floor
        n_opt = clamp_to_feasible(n_star, lam=10.0, delta=5.0, t_max=100.0)
        assert n_opt == floor

    def test_clamped_to_ceiling_when_n_star_too_large(self) -> None:
        n_star = optimal_cadence(lam=LAM, c=C, w=W, rho=RHO)
        ceiling = LAM * 0.1  # lam * t_max, deliberately below N*
        assert n_star > ceiling
        n_opt = clamp_to_feasible(n_star, lam=LAM, delta=0.0001, t_max=0.1)
        assert n_opt == ceiling

    def test_delta_greater_than_t_max_is_labelled_infeasible(self) -> None:
        n_star = optimal_cadence(lam=LAM, c=C, w=W, rho=RHO)
        with pytest.raises(AnchorTechnologyInfeasible) as exc_info:
            clamp_to_feasible(n_star, lam=LAM, delta=10.0, t_max=5.0)
        # Not a bare ValueError with no context: the exception carries the
        # two numbers an operator needs to see this is an anchor-technology
        # problem, not a cadence problem.
        assert exc_info.value.delta == 10.0
        assert exc_info.value.t_max == 5.0
        assert "delta" in str(exc_info.value)
        assert "t_max" in str(exc_info.value)

    def test_infeasible_is_not_a_bare_valueerror(self) -> None:
        # It must be identifiable as its own labelled condition, not merely
        # catchable as ValueError alongside ordinary bad-input errors.
        assert not issubclass(AnchorTechnologyInfeasible, ValueError)

    def test_equal_delta_and_t_max_is_feasible_not_infeasible(self) -> None:
        # The boundary delta == t_max is not "the floor exceeds the
        # ceiling" -- only strictly greater is.
        n_opt = clamp_to_feasible(1000.0, lam=1.0, delta=2.0, t_max=2.0)
        assert n_opt == 2.0


class TestFleetDividend:
    def test_matches_direct_computation_with_M(self) -> None:
        n_star_1 = optimal_cadence(lam=LAM, c=C, w=W, rho=RHO, M=1)
        for m in (1, 2, 3, 4, 9, 16, 25):
            direct = optimal_cadence(lam=LAM, c=C, w=W, rho=RHO, M=m)
            via_dividend = fleet_dividend(n_star_1, m)
            assert math.isclose(direct, via_dividend, rel_tol=1e-9)

    def test_dividend_is_n_star_1_over_sqrt_M(self) -> None:
        n_star_1 = 1000.0
        assert math.isclose(fleet_dividend(n_star_1, 4), 500.0, rel_tol=1e-12)
        assert math.isclose(fleet_dividend(n_star_1, 100), 100.0, rel_tol=1e-12)

    def test_monotone_increasing_M_never_increases_per_agent_n_star(self) -> None:
        n_star_1 = optimal_cadence(lam=LAM, c=C, w=W, rho=RHO, M=1)
        previous = n_star_1
        for m in range(1, 51):
            current = optimal_cadence(lam=LAM, c=C, w=W, rho=RHO, M=m)
            assert current <= previous + 1e-9
            previous = current

    def test_rejects_M_below_one(self) -> None:
        with pytest.raises(ValueError):
            fleet_dividend(1000.0, 0)


class TestPlanCadence:
    def test_bundles_star_and_clamped_values(self) -> None:
        plan = plan_cadence(lam=LAM, c=C, w=W, rho=RHO, delta=0.0001, t_max=10.0)
        assert isinstance(plan, CadencePlan)
        assert plan.n_star > 0
        assert plan.lower_bound == LAM * 0.0001
        assert plan.upper_bound == LAM * 10.0
        assert plan.lower_bound <= plan.n_opt <= plan.upper_bound
        assert math.isclose(plan.anchor_term, plan.exposure_term, rel_tol=1e-9)

    def test_propagates_infeasible(self) -> None:
        with pytest.raises(AnchorTechnologyInfeasible):
            plan_cadence(lam=LAM, c=C, w=W, rho=RHO, delta=10.0, t_max=1.0)

    def test_is_frozen_dataclass(self) -> None:
        plan = plan_cadence(lam=LAM, c=C, w=W, rho=RHO, delta=0.0001, t_max=10.0)
        with pytest.raises(AttributeError):
            plan.n_star = 1.0  # type: ignore[misc]
