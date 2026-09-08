"""The two names report.py and _report_render.py both need.

They lived in report.py, and the 0.1.6 split put the renderer's import at the
BOTTOM of report.py so the renderer could import them back - a cycle that held
only while report.py was always imported first. `import
waxseal.domain._report_render` on its own raised "partially initialized
module" while the whole suite stayed green (tests/architecture/
test_import_order.py). Both modules import from here now; report.py still
re-exports them, so `from waxseal.domain.report import CheckSummary` is
unchanged for the CLI.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

#: The reason string a receipts check reports when there is no `.receipts`
#: sidecar AT ALL. Defined here rather than in the CLI because this is the file
#: that has to keep "never measured" apart from "measured and clean" in the
#: document an auditor still has six months later -- the CLI only prints a line
#: on the day. `verify` imports it from here so the two surfaces cannot drift
#: into disagreeing about which state they are describing.
RECEIPTS_NOT_RECORDED_REASON: Final = "no_receipts_recorded"


@dataclass(frozen=True, slots=True)
class CheckSummary:
    """Outcome of a sidecar check. The absence of one of these (``None`` on
    the report) means the check was never run, never that it passed."""

    ok: bool
    checked: int
    reason: str | None = None
    # The third value the chain verdict has always had, made available to
    # sidecar checks too: this build could not read the thing by name (a pin
    # state from a newer waxseal, a timestamp token in a shape it does not
    # parse). Not a pass and not a break: exit 2, the same distinction that
    # keeps an unknown fingerprint from being called tampering.
    unverifiable: bool = False
    # Caveats that qualify an `ok`: a check that ran but could not cover
    # everything in front of it. These belong on the summary, not on the
    # caller's printed line, since `report` is the artifact an auditor still has
    # six months later, and a caveat only `verify` prints is a caveat that
    # never reaches them.
    notes: tuple[str, ...] = ()
