from __future__ import annotations

import contextlib
import functools
import sys
from dataclasses import dataclass
from datetime import UTC, datetime

from waxseal.domain.report import (
    CheckSummary,
)
from waxseal.domain.verdict import Verdict


def _survive_a_narrow_console() -> None:
    """Never let an encoding crash swallow a verification verdict.

    Console output on Windows still defaults to a legacy codepage (cp1252 on
    this project's own report of the 0.1.1 install bug), which cannot encode
    the em dashes and ellipses in these messages. Without this, `report` on
    such a console dies with UnicodeEncodeError *after* doing the work,
    the operator gets a traceback instead of the answer, and a non-zero exit
    that means nothing about the chain. Degrading a dash to an escape is a
    cosmetic loss; losing the verdict is not.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        encoding = getattr(stream, "encoding", None)
        if reconfigure is None or encoding is None:
            continue
        try:
            # Only touch a stream that genuinely cannot carry this output.
            # A capable console keeps its own error handling untouched.
            "— … ▶".encode(encoding)
        except (UnicodeEncodeError, LookupError):
            with contextlib.suppress(ValueError, OSError):
                reconfigure(errors="backslashreplace")


@dataclass(frozen=True, slots=True)
class _Check:
    """One verification dimension's verdict plus the line `verify` prints for
    it. `report` renders the same summary its own way, so each check is
    computed in exactly one place and cannot say two different things."""

    summary: CheckSummary
    line: str

    @property
    def verdict(self) -> Verdict:
        if not self.summary.ok:
            return Verdict.BROKEN
        return Verdict.UNVERIFIABLE if self.summary.unverifiable else Verdict.OK

    @property
    def exit_code(self) -> int:
        return self.verdict.to_exit_code()


def _combine(codes: list[int]) -> int:
    """Broken beats unverifiable beats intact.

    Structural, not conventional: each code is read back into the ``Verdict``
    it came from (domain/verdict.py) and combined with ``Verdict.join`` in
    true severity order, then converted back to an exit code. This is no
    longer merely "deliberately not ``max``": ``int`` only ever means
    anything at this one CLI boundary function, everywhere else the
    combination happens on ``Verdict`` values themselves.
    """
    verdicts = (Verdict.from_exit_code(code) for code in codes)
    return functools.reduce(Verdict.join, verdicts, Verdict.OK).to_exit_code()


def _default_now() -> datetime:
    # Rule 8: timestamps are injectable. This is only the seam's default,
    # `pinned_ts` is produced through a now_fn parameter so a test can pin an
    # exact time instead of sleeping or patching a module global.
    return datetime.now(UTC)
