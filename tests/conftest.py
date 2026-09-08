"""Session-wide test configuration.

Why a run-summary line exists here: pytest's totals print "N passed, M
skipped" and stop, so a suite whose real-backend tests never ran looks, at a
glance, exactly like one where they passed. That is the collapse CLAUDE.md
rule 5 forbids — "not measured" rendered as green — turned on the test suite
itself. It is not hypothetical: eleven Postgres tamper-detection tests sat in
that total for a year (waxseal-fg4.2).

Fixing the configuration that caused those skips does not retire the problem,
because the database can always be absent tomorrow — the server suite went
from 0 to 43 such skips overnight when this machine slept, with no change to
any test. So the floor stays: whenever a skip labels itself UNMEASURED, the
count is named separately from the skip total, with the reason that says what
was not established and what would establish it.
"""

from __future__ import annotations

from typing import Any

# Any test module may opt a skip into this reporting by putting the word in
# its skip reason. Matching on the reason, not on a module path, so the line
# covers the next unmeasured dimension without this file learning about it.
UNMEASURED_MARKER = "UNMEASURED"


def pytest_terminal_summary(terminalreporter: Any) -> None:
    reasons: dict[str, int] = {}
    for report in terminalreporter.stats.get("skipped", []):
        longrepr = getattr(report, "longrepr", None)
        reason = (
            longrepr[2] if isinstance(longrepr, tuple) and len(longrepr) == 3 else str(longrepr)
        )
        if UNMEASURED_MARKER in reason:
            reasons[reason] = reasons.get(reason, 0) + 1
    if not reasons:
        return
    total = sum(reasons.values())
    terminalreporter.write_sep("=", "unmeasured", yellow=True, bold=True)
    terminalreporter.write_line(
        f"{total} test(s) UNMEASURED: not run, and therefore NOT passed. "
        "Counted here because the skip total above does not distinguish them."
    )
    for reason, count in sorted(reasons.items()):
        terminalreporter.write_line(f"  {count}x {reason.removeprefix('Skipped: ').strip()}")
