from __future__ import annotations


def _cadence(
    *, lam: float, c: float, w: float, rho: float, M: int, delta: float, t_max: float
) -> int:
    """`waxseal cadence` (C4): wires `domain/cadence.py`'s closed-form
    optimum into the CLI. Opens no trail; every input is an operator-
    supplied measurement, not a guess (`domain/cadence.py`'s own docstring
    on why `w`/`rho`/`c` have no defaults).

    Exit codes are this command's own convention, not verify's 0/1/2/3
    (there is no trail here for those to describe): 0 = a feasible cadence
    was computed, 1 = infeasible (`delta > t_max`, a labelled domain
    conclusion, not a crash: the anchor technology, not the cadence, is
    what's wrong), 2 = an invalid measurement (e.g. `w <= 0`), where nothing was
    computed, the same convention `reconcile-tickets` already uses for a
    malformed operator input.
    """
    from waxseal.domain.cadence import AnchorTechnologyInfeasible, flatness_bound, plan_cadence

    try:
        plan = plan_cadence(lam=lam, c=c, w=w, rho=rho, M=M, delta=delta, t_max=t_max)
    except AnchorTechnologyInfeasible as e:
        # Rule 6 (fail-open must be labelled) applied to a pure computation:
        # printing a clamped-anyway number here would look like an answer
        # and hide that no N can meet this window. See the module docstring
        # on `clamp_to_feasible`.
        print(f"INFEASIBLE: {e}")
        print(
            "no cadence exists that meets this detection window — the ANCHOR "
            "TECHNOLOGY, not the cadence, does not meet this requirement; use "
            "a faster anchor technology or a larger --t-max"
        )
        return 1
    except ValueError as e:
        # lam/c/w/rho <= 0 or M < 1: an invalid operator-supplied
        # measurement, reported the same way reconcile-tickets reports a
        # malformed --issued: nothing computed, never a bogus number.
        print(f"unverifiable: {e} — nothing was computed")
        return 2

    # Rule 5 / the Ternary Evidence Principle, applied here as "a band, not a
    # point": w/rho are order-of-magnitude operator estimates, so N_opt on
    # its own reads as more precise than the inputs support. flatness_bound
    # gives the concrete cost of trusting the band instead of the point: 2x
    # off costs 25% more, 3x off costs ~67% more.
    band_low = plan.n_opt / 2.0
    band_high = plan.n_opt * 2.0
    print(f"N* (unclamped optimum): {plan.n_star:.6g}")
    print(f"N_opt (clamped, feasible): {plan.n_opt:.6g}")
    print(f"clamp bounds [lam*delta, lam*t_max]: [{plan.lower_bound:.6g}, {plan.upper_bound:.6g}]")
    print(
        f"balance at N* (equal by construction): "
        f"anchor_term={plan.anchor_term:.6g}, exposure_term={plan.exposure_term:.6g}"
    )
    print(
        f"recommended band around N_opt (order-of-magnitude estimate, NOT a "
        f"single point): [{band_low:.6g}, {band_high:.6g}] — a cadence 2x off "
        f"costs {flatness_bound(2.0):.6g}x optimal, 3x off costs "
        f"{flatness_bound(3.0):.6g}x optimal (flatness_bound)"
    )
    return 0
