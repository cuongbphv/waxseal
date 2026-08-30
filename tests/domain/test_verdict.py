"""Verdict join-semilattice (domain/verdict.py).

The exit-code trap this module exists to make unrepresentable: ``cli.py``'s
existing ``_combine()`` composes verify checks correctly today, but only
because of a comment ("Deliberately not ``max``") and writer discipline —
2 (unverifiable) is the larger exit code but the *weaker* finding, so
composing on exit codes with ``max()`` would let a real break (1) get
overridden by an unrelated unverifiable row (2). ``Verdict.join`` composes on
verdicts themselves, in their true severity order, so that trap has no seam
to hide in.
"""

from __future__ import annotations

import pytest

from waxseal.domain.verdict import Verdict

OK = Verdict.OK
UNVERIFIABLE = Verdict.UNVERIFIABLE
BROKEN = Verdict.BROKEN

ALL = (OK, UNVERIFIABLE, BROKEN)

# The full 3x3 join table, spelled out — not derived from the ranking under
# test. Severity order is OK < UNVERIFIABLE < BROKEN; join picks the
# stronger (more severe) of the two.
JOIN_TABLE: dict[tuple[Verdict, Verdict], Verdict] = {
    (OK, OK): OK,
    (OK, UNVERIFIABLE): UNVERIFIABLE,
    (OK, BROKEN): BROKEN,
    (UNVERIFIABLE, OK): UNVERIFIABLE,
    (UNVERIFIABLE, UNVERIFIABLE): UNVERIFIABLE,
    (UNVERIFIABLE, BROKEN): BROKEN,
    (BROKEN, OK): BROKEN,
    (BROKEN, UNVERIFIABLE): BROKEN,
    (BROKEN, BROKEN): BROKEN,
}


class TestJoinTable:
    @pytest.mark.parametrize(
        ("a", "b", "expected"),
        [
            (OK, OK, OK),
            (OK, UNVERIFIABLE, UNVERIFIABLE),
            (OK, BROKEN, BROKEN),
            (UNVERIFIABLE, OK, UNVERIFIABLE),
            (UNVERIFIABLE, UNVERIFIABLE, UNVERIFIABLE),
            (UNVERIFIABLE, BROKEN, BROKEN),
            (BROKEN, OK, BROKEN),
            (BROKEN, UNVERIFIABLE, BROKEN),
            (BROKEN, BROKEN, BROKEN),
        ],
    )
    def test_full_3x3(self, a: Verdict, b: Verdict, expected: Verdict) -> None:
        assert a.join(b) is expected

    def test_table_matches_the_literal_dict(self) -> None:
        # Belt and suspenders: the parametrize list above and this literal
        # dict were written independently; cross-check them against each
        # other and against the implementation.
        for (a, b), expected in JOIN_TABLE.items():
            assert a.join(b) is expected


class TestAssociative:
    @pytest.mark.parametrize("a", ALL)
    @pytest.mark.parametrize("b", ALL)
    @pytest.mark.parametrize("c", ALL)
    def test_full_3x3x3(self, a: Verdict, b: Verdict, c: Verdict) -> None:
        assert a.join(b.join(c)) == (a.join(b)).join(c)


class TestCommutative:
    @pytest.mark.parametrize("a", ALL)
    @pytest.mark.parametrize("b", ALL)
    def test_full_3x3(self, a: Verdict, b: Verdict) -> None:
        assert a.join(b) == b.join(a)


class TestIdempotent:
    @pytest.mark.parametrize("a", ALL)
    def test_join_with_self_is_self(self, a: Verdict) -> None:
        assert a.join(a) == a


class TestIdentity:
    @pytest.mark.parametrize("x", ALL)
    def test_ok_is_left_identity(self, x: Verdict) -> None:
        assert OK.join(x) == x

    @pytest.mark.parametrize("x", ALL)
    def test_ok_is_right_identity(self, x: Verdict) -> None:
        assert x.join(OK) == x


class TestBrokenJoinUnverifiableIsBroken:
    # Direct regression for the max()-on-exit-codes trap: BROKEN (exit 1) is
    # the stronger finding even though UNVERIFIABLE maps to the larger exit
    # code (2). join() must never be implemented by comparing exit codes.
    def test_broken_join_unverifiable_is_broken(self) -> None:
        assert Verdict.BROKEN.join(Verdict.UNVERIFIABLE) is Verdict.BROKEN
        assert Verdict.UNVERIFIABLE.join(Verdict.BROKEN) is Verdict.BROKEN


class TestExitCode:
    def test_ok_is_zero(self) -> None:
        assert Verdict.OK.to_exit_code() == 0

    def test_broken_is_one(self) -> None:
        assert Verdict.BROKEN.to_exit_code() == 1

    def test_unverifiable_is_two(self) -> None:
        assert Verdict.UNVERIFIABLE.to_exit_code() == 2

    def test_to_exit_code_does_not_preserve_severity_order(self) -> None:
        # UNVERIFIABLE is the WEAKER finding but maps to the LARGER exit
        # code. This is exactly why join() must never be implemented via
        # max() on exit codes.
        assert Verdict.UNVERIFIABLE.to_exit_code() > Verdict.BROKEN.to_exit_code()


class TestFromExitCode:
    # Exact inverse of to_exit_code — the one place int is allowed to mean a
    # Verdict again, confined to the CLI boundary.
    def test_zero_is_ok(self) -> None:
        assert Verdict.from_exit_code(0) is Verdict.OK

    def test_one_is_broken(self) -> None:
        assert Verdict.from_exit_code(1) is Verdict.BROKEN

    def test_two_is_unverifiable(self) -> None:
        assert Verdict.from_exit_code(2) is Verdict.UNVERIFIABLE

    @pytest.mark.parametrize("x", ALL)
    def test_round_trips_through_to_exit_code(self, x: Verdict) -> None:
        assert Verdict.from_exit_code(x.to_exit_code()) is x

    def test_invalid_code_raises_value_error(self) -> None:
        # Only 0/1/2 are ever produced; a 4th value reaching this function is
        # a bug elsewhere, not a value to coerce silently.
        with pytest.raises(ValueError, match="not a valid Verdict exit code"):
            Verdict.from_exit_code(3)
