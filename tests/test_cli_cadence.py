"""CLI: `waxseal cadence` — C4, wiring `domain/cadence.py`'s cost-optimal
anchoring math into a read-only subcommand. Unlike every other subcommand
here, it opens no trail at all: `N*` is pure arithmetic over operator-
supplied measurements (`lam`, `c`, `w`, `rho`, `delta`, `t_max`; `M` defaults
to 1, the same "no fleet sharing" structural default `domain/cadence.py`
itself uses), so there is no `path` positional and nothing on disk is ever
touched.

The bead is explicit that this prints a BAND, not a bare point: `N*` scales
as `(w*rho)^-1/2`, so a measurement off by 10x only moves the true optimum by
~3.2x and costs ~67% more per `flatness_bound` — a single number would read
as more precise than `w`/`rho` (operator estimates) can support.

Exit codes (this command's own convention — it is not verify-shaped, so
verify's 0/1/2/3 do not apply unchanged):
  0 = a feasible cadence was computed and printed.
  1 = infeasible (`delta > t_max`): a real, labelled domain conclusion —
      the anchor technology, not the cadence, cannot meet the operator's
      window. Mirrors how `install` uses 1 for "a real conflict exists",
      not a crash.
  2 = a supplied measurement was invalid (e.g. `lam <= 0`) — nothing was
      computed, same convention `reconcile-tickets` already uses for a
      malformed operator input.
  argparse's own usage-error exit (2) for a missing required flag — no
  defaults exist for `w`/`rho`/`c` to silently fall back to.
"""

from __future__ import annotations

import math
import re

import pytest

from waxseal.cli import main


def _floats_after(label: str, out: str) -> list[float]:
    line = next(line for line in out.splitlines() if label in line)
    return [float(x) for x in re.findall(r"-?\d+\.?\d*(?:[eE][-+]?\d+)?", line)]


class TestFeasibleCase:
    def test_prints_n_star_n_opt_band_and_balance_terms(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # Same LAM/C/W/RHO as tests/domain/test_cadence.py: N* ~= 63245.553,
        # chosen so the discrete "-1" correction is negligible. delta/t_max
        # picked so lam*delta=50000 < N* < lam*t_max=100000: N_opt == N*
        # unclamped, so this case demonstrates the band around an unclamped
        # optimum specifically.
        code = main(
            [
                "cadence",
                "--lam",
                "100000",
                "--c",
                "2.0",
                "--w",
                "1.0",
                "--rho",
                "0.0001",
                "--delta",
                "0.5",
                "--t-max",
                "1.0",
            ]
        )
        out = capsys.readouterr().out
        assert code == 0

        n_star_expected = math.sqrt(2 * 2.0 * 100000 / (1 * 1.0 * 0.0001))
        [n_star] = _floats_after("N* (unclamped", out)
        assert math.isclose(n_star, n_star_expected, rel_tol=1e-6)

        [n_opt] = _floats_after("N_opt (clamped", out)
        assert math.isclose(n_opt, n_star_expected, rel_tol=1e-6)

        lower, upper = _floats_after("clamp bounds", out)
        assert math.isclose(lower, 50000.0, rel_tol=1e-9)
        assert math.isclose(upper, 100000.0, rel_tol=1e-9)

        anchor_term, exposure_term = _floats_after("balance at N*", out)
        # The paper's balance property: the two cost terms are equal AT N*.
        assert math.isclose(anchor_term, exposure_term, rel_tol=1e-6)
        assert math.isclose(anchor_term, 3.1622776601683795, rel_tol=1e-6)

        band_line = next(line for line in out.splitlines() if "recommended band" in line)
        band_match = re.search(r"\[(-?\d+\.?\d*), (-?\d+\.?\d*)\]", band_line)
        assert band_match is not None
        band_low, band_high = (float(x) for x in band_match.groups())
        # n_opt itself was parsed from a `.6g`-rounded string, so compare the
        # band against the recomputed expected value at looser tolerance
        # rather than compounding two roundings.
        assert math.isclose(band_low, n_star_expected / 2.0, rel_tol=1e-3)
        assert math.isclose(band_high, n_star_expected * 2.0, rel_tol=1e-3)
        # flatness_bound(2) == 1.25, flatness_bound(3) == 5/3 — the concrete
        # "usable at order-of-magnitude precision" numbers the bead asks for.
        factor2, factor3 = (float(x) for x in re.findall(r"(\d+\.?\d*)x optimal", band_line))
        assert math.isclose(factor2, 1.25, rel_tol=1e-5)
        assert math.isclose(factor3, 5.0 / 3.0, rel_tol=1e-5)


class TestInfeasibleAnchorTechnology:
    def test_delta_over_t_max_names_the_anchor_technology_not_the_cadence(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        code = main(
            [
                "cadence",
                "--lam",
                "100000",
                "--c",
                "2.0",
                "--w",
                "1.0",
                "--rho",
                "0.0001",
                "--delta",
                "2.0",
                "--t-max",
                "1.0",
            ]
        )
        out = capsys.readouterr().out
        assert code == 1
        assert "INFEASIBLE" in out
        assert "anchor technology" in out.lower()
        assert "not" in out.lower() and "cadence" in out.lower()
        # No number that could be mistaken for a real N was printed.
        assert "N*" not in out
        assert "N_opt" not in out


class TestMissingRequiredFlag:
    @pytest.mark.parametrize("missing", ["--w", "--rho", "--c"])
    def test_missing_required_flag_is_a_usage_error_not_a_silent_default(
        self, missing: str
    ) -> None:
        args = [
            "cadence",
            "--lam",
            "100000",
            "--c",
            "2.0",
            "--w",
            "1.0",
            "--rho",
            "0.0001",
            "--delta",
            "0.5",
            "--t-max",
            "1.0",
        ]
        # Drop the flag and its value.
        idx = args.index(missing)
        del args[idx : idx + 2]
        with pytest.raises(SystemExit) as exc:
            main(args)
        assert exc.value.code == 2


class TestInvalidMeasurement:
    def test_non_positive_measurement_is_reported_not_crashed(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        code = main(
            [
                "cadence",
                "--lam",
                "100000",
                "--c",
                "2.0",
                "--w",
                "-1.0",
                "--rho",
                "0.0001",
                "--delta",
                "0.5",
                "--t-max",
                "1.0",
            ]
        )
        out = capsys.readouterr().out
        assert code == 2
        assert "w" in out
