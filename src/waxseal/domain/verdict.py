"""Verdict join-semilattice (pure; no I/O).

CLAUDE.md's ``cli/_common.py::_combine()`` composes verify checks by exit code
(0/1/2) and gets it right today only via a comment ("Deliberately not
``max``") plus writer discipline: 2 (unverifiable) is the numerically larger
exit code but the *weaker* finding, so ``max()`` over exit codes would let an
unrelated unverifiable row silently override a real break. That is
*procedural* safety standing where *structural* safety belongs (the same gap
F1 uses to fault ``lp()`` elsewhere in this project).

``Verdict`` closes it by making severity a property of the value itself,
never of its exit code. ``join`` is a join-semilattice on the total order
``OK < UNVERIFIABLE < BROKEN`` (BROKEN is the strongest/worst finding, OK is
the identity): commutative, associative, idempotent, unit ``OK``. It is
"take the more severe of two verdicts", never implemented via ``max()`` on
``to_exit_code()``, because that order does not match severity order (see
``to_exit_code`` below).
"""

from __future__ import annotations

import enum
from typing import Final


class Verdict(enum.Enum):
    """One verify check's finding: intact, unverifiable-by-name, or broken."""

    OK = "ok"
    UNVERIFIABLE = "unverifiable"
    BROKEN = "broken"

    def join(self, other: Verdict) -> Verdict:
        """The more severe of ``self`` and ``other``, under severity order
        ``OK < UNVERIFIABLE < BROKEN``, never under exit-code order."""
        return self if _SEVERITY[self] >= _SEVERITY[other] else other

    def to_exit_code(self) -> int:
        """CLI exit code for this verdict.

        Deliberately NOT severity-order-preserving: ``UNVERIFIABLE`` (the
        weaker finding) maps to 2, the numerically larger code, while
        ``BROKEN`` (the stronger finding) maps to 1. This asymmetry is
        exactly why ``join`` must operate on ``Verdict`` values in their true
        severity order and must never be implemented by comparing exit
        codes with ``max()``.
        """
        return _EXIT_CODE[self]

    @classmethod
    def from_exit_code(cls, code: int) -> Verdict:
        """Inverse of ``to_exit_code``: the CLI boundary's one seam where
        ``int`` is allowed to mean a verdict again.

        Only three exit codes exist (0, 1, 2). A fourth reaching here is a
        bug at the call site, not a value to coerce silently, so it raises
        rather than guessing.
        """
        try:
            return _FROM_EXIT_CODE[code]
        except KeyError:
            raise ValueError(f"not a valid Verdict exit code: {code!r}") from None


# Severity order, internal to this module and never conflated with exit-code
# order (see to_exit_code's docstring): OK is weakest/identity, BROKEN is
# strongest.
_SEVERITY: Final[dict[Verdict, int]] = {
    Verdict.OK: 0,
    Verdict.UNVERIFIABLE: 1,
    Verdict.BROKEN: 2,
}

_EXIT_CODE: Final[dict[Verdict, int]] = {
    Verdict.OK: 0,
    Verdict.BROKEN: 1,
    Verdict.UNVERIFIABLE: 2,
}

# Exact inverse of _EXIT_CODE, spelled out rather than derived, so a typo in
# one direction can't silently become "correct" by construction in the other.
_FROM_EXIT_CODE: Final[dict[int, Verdict]] = {
    0: Verdict.OK,
    1: Verdict.BROKEN,
    2: Verdict.UNVERIFIABLE,
}
