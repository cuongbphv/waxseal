"""Human-readable incident listing. Schema and window_status stay on incident.py."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Final

from waxseal.domain.incident import IncidentScan, window_status

_TIME_BASIS: Final = (
    "time basis: every moment below is CALLER-ASSERTED — recorded by the writer at the "
    "time, not measured or attested by waxseal"
)

_NO_RECORDS: Final = (
    "0 incident records on this trail — a count of RECORDED incidents, not evidence "
    "that none occurred"
)


def render_incidents(
    scan: IncidentScan,
    *,
    window: timedelta | None = None,
    now: datetime | None = None,
) -> list[str]:
    """Human-readable lines for a CLI or a notice, in ``domain.tickets``'s
    ``render_reconciliation`` style.

    The caller-asserted qualification is repeated ON EVERY STATUS LINE rather
    than stated once in a footer: a status line is the line that gets pasted
    into a ticket, quoted in a mail, or grepped out of a log six months later,
    and it has to carry its own basis with it.

    Both ``window`` and ``now`` are needed for a window reading. A window with
    no as-of moment measures nothing, and reaching for the process clock here
    is exactly what rule 8 forbids of domain code.

    This renderer's own vocabulary is deliberately free of "unreported",
    "missed", "late" and "breach". Each of those asserts a finding about a
    legal obligation, on evidence that includes a submission channel this
    process cannot see; ``tests/domain/test_incident.py`` holds their absence
    as a test, in the manner ``tests/test_cli_preflight.py`` holds the absence
    of an unscoped "tamper-proof".
    """
    lines = [_TIME_BASIS]
    if window is not None and now is not None:
        lines.append(
            f"reporting window as configured: {window.total_seconds() / 3600.0:.0f}h "
            f"from confirmed_at (Decree 142/2026/ND-CP Dieu 19(3)(c)); as of {now.isoformat()}"
        )

    if not scan.views:
        lines.append(_NO_RECORDS)
    else:
        lines.append(
            f"{len(scan.views)} incident record(s) on this trail, over "
            f"{sum(view.rows for view in scan.views)} row(s) — a restated incident "
            "appends a new row and the newest row wins as a whole record"
        )
        for view in scan.views:
            record = view.latest
            kinds = (
                ", ".join(record.consequence_kinds) if record.consequence_kinds else "none declared"
            )
            status = (
                repr(record.operating_status)
                if record.operating_status is not None
                else "not declared"
            )
            lines.append(
                f"{view.incident_id}: severity={record.severity!r}, "
                f"operating_status={status}, consequence_kinds=[{kinds}], "
                f"first_seq={view.first_seq}, newest_seq={view.latest_seq}, "
                f"rows={view.rows}"
            )
            if record.report_ref is None:
                lines.append(
                    "  no submission is recorded on this trail for it, which is not "
                    "evidence that no report was filed — waxseal has no channel to the "
                    "authority and records only what a writer wrote here"
                )
            else:
                lines.append(
                    f"  submission recorded on this trail: report_ref={record.report_ref!r}"
                )
            if window is not None and now is not None:
                reading = window_status(view, window=window, now=now)
                elapsed = (
                    "elapsed not measured"
                    if reading.elapsed_h is None
                    else f"{reading.elapsed_h:.1f}h from confirmed_at"
                )
                lines.append(
                    f"  {reading.status.value} by caller-asserted time ({elapsed}): "
                    f"{reading.reason}"
                )

    if scan.unreadable:
        lines.append(
            f"unreadable: {len(scan.unreadable)} entr"
            f"{'y' if len(scan.unreadable) == 1 else 'ies'} claim an incident payload but "
            f"could not be read (seqs: {list(scan.unreadable)}) — this listing is "
            "therefore incomplete, which is not the same as complete and clean"
        )
    return lines
