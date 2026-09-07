from __future__ import annotations

import json
from datetime import UTC, datetime

from waxseal.domain.report import (
    SCOPE_LINE,
)
from waxseal.domain.verdict import Verdict
from waxseal.log import AuditLog


def _incidents(
    log: AuditLog,
    *,
    window_h: float,
    as_of: str | None,
    since: str | None,
    as_json: bool,
) -> int:
    """`waxseal incidents`: what does this trail record about each serious
    incident, and where does each one sit against a reporting window?

    Read-only, and its exit-code range is `{0, 2, 3}` by construction. There
    is no exit 1 here, unlike `reconcile-tickets`, and the difference is not
    an oversight. That command's exit 1 rests on an exogenous authority
    positively asserting what should be present and on a comparison that is
    deterministic given the trail. Neither holds here: the window is a
    parameter the operator typed, the deadline is anchored to a moment the
    writer asserted, and the reading depends on a clock this process supplied.
    An exit 1 would be this library asserting that a legal obligation was not
    met — one of the three things `SCOPE_STATEMENT` says none of its output
    asserts. `preflight` is the precedent for reporting a reading rather than
    a verdict.

    Exit 2 is reserved for a row that claims the incident payload type and
    could not be read, because a listing missing a row is not a complete
    listing, and for input this build cannot interpret. A window reading of
    `unmeasured` on a row that DID parse stays exit 0: it is a reading, fully
    printed, with its own cause named.
    """
    from datetime import datetime, timedelta

    from waxseal.domain.incident import (
        IncidentScan,
        render_incidents,
        scan_incidents,
        window_status,
    )

    def _aware(raw: str, flag: str) -> datetime:
        """Offset-aware or nothing. Guessing a time zone for a bare local
        timestamp would invent the evidence the reading is built on."""
        parsed = datetime.fromisoformat(raw)
        if parsed.tzinfo is None:
            raise ValueError(f"{flag} must carry a UTC offset (e.g. ...+00:00 or ...Z)")
        return parsed

    if window_h <= 0:
        print(
            f"unverifiable: --report-window-h must be positive, got {window_h} "
            "— nothing was read"
        )
        return 2
    try:
        now = _aware(as_of, "--as-of") if as_of is not None else datetime.now(UTC)
        since_at = _aware(since, "--since") if since is not None else None
    except ValueError as e:
        print(f"unverifiable: {e} — nothing was read")
        return 2

    window = timedelta(hours=window_h)
    scan = scan_incidents(log.entries())

    # `--since` filters the LISTING, never the reading, and never silently.
    # A row whose own confirmation moment this build cannot read is kept and
    # labelled: a filter that drops what it cannot evaluate reports a shorter
    # list as if it were a complete one.
    unfiltered = scan
    unreadable_since: list[str] = []
    if since_at is not None:
        kept = []
        for view in scan.views:
            raw = view.latest.confirmed_at
            if raw is None:
                unreadable_since.append(view.incident_id)
                kept.append(view)
                continue
            try:
                if _aware(raw, "confirmed_at") >= since_at:
                    kept.append(view)
            except ValueError:
                unreadable_since.append(view.incident_id)
                kept.append(view)
        scan = IncidentScan(views=tuple(kept), unreadable=scan.unreadable)

    readings = {
        view.incident_id: window_status(view, window=window, now=now) for view in scan.views
    }
    no_report = sum(1 for view in scan.views if view.latest.report_ref is None)

    if as_json:
        print(
            json.dumps(
                {
                    "window_h": window_h,
                    "as_of": now.isoformat(),
                    "since": since_at.isoformat() if since_at is not None else None,
                    "time_basis": "caller_asserted",
                    "incidents": [
                        {
                            "incident_id": view.incident_id,
                            "system_id": view.latest.system_id,
                            "first_seq": view.first_seq,
                            "latest_seq": view.latest_seq,
                            "rows": view.rows,
                            "severity": view.latest.severity,
                            "consequence_kinds": list(view.latest.consequence_kinds),
                            "operating_status": view.latest.operating_status,
                            "detected_at": view.latest.detected_at,
                            "confirmed_at": view.latest.confirmed_at,
                            "report_ref": view.latest.report_ref,
                            "reported_at": view.latest.reported_at,
                            "status": readings[view.incident_id].status.value,
                            "reason": readings[view.incident_id].reason,
                            "elapsed_h": readings[view.incident_id].elapsed_h,
                        }
                        for view in scan.views
                    ],
                    "unreadable": list(scan.unreadable),
                    "since_not_applicable": unreadable_since,
                    "totals": {
                        "recorded": len(scan.views),
                        "no_report_recorded": no_report,
                        "unmeasured": sum(
                            1
                            for reading in readings.values()
                            if reading.status.value == "unmeasured"
                        ),
                    },
                    "note": (
                        "every time here is caller-asserted: the window is measured "
                        "from a confirmation moment a writer recorded, not from an "
                        "attested one. A count of RECORDED incidents is not evidence "
                        "that no others occurred, and 'no submission recorded' is a "
                        "fact about this trail, not about the authority's channel, "
                        "which this process cannot see"
                    ),
                    "scope": SCOPE_LINE,
                }
            )
        )
        return Verdict.UNVERIFIABLE.to_exit_code() if unfiltered.unreadable else 0

    for line in render_incidents(scan, window=window, now=now):
        print(line)
    for incident_id in unreadable_since:
        print(
            f"  --since could not be applied to {incident_id} (its confirmation "
            "moment is absent or unreadable) — listed rather than dropped, since "
            "a filter that hides what it cannot evaluate shortens the list "
            "without saying so"
        )
    print(SCOPE_LINE)
    return Verdict.UNVERIFIABLE.to_exit_code() if unfiltered.unreadable else 0
