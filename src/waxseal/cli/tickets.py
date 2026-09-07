from __future__ import annotations

import json

from waxseal.domain.verdict import Verdict
from waxseal.log import AuditLog


def _parse_issued_spec(spec: str) -> set[int]:
    """Parse ``--issued``: comma-separated non-negative ints and inclusive
    ``lo-hi`` ranges (e.g. ``"0-9,15,20-25"``). Raises ``ValueError`` on
    anything else, and the caller turns that into an unverifiable exit, never a
    guess at what the operator meant.
    """
    result: set[int] = set()
    for raw in spec.split(","):
        token = raw.strip()
        if not token:
            continue
        if "-" in token:
            lo_s, _, hi_s = token.partition("-")
            lo, hi = int(lo_s), int(hi_s)
            if hi < lo:
                raise ValueError(f"invalid range {token!r}: end before start")
            result.update(range(lo, hi + 1))
        else:
            result.add(int(token))
    return result


def _reconcile_tickets(
    log: AuditLog, *, issuer: str, lease_size: int, issued_spec: str | None, as_json: bool
) -> int:
    """`waxseal reconcile-tickets` (D2): does the issuer's own account of
    which admission tickets it granted match what actually reached the
    trail? A missing ticket is a POSITIVELY DETECTED drop, not the measured
    minimum `verify`'s `dropped_writes` reports elsewhere. Read-only: it
    only scans entries already on the trail (CLAUDE.md's CLI contract).
    """

    from waxseal.domain.tickets import reconcile_tickets, render_reconciliation, scan_tickets

    issued: set[int] | None = None
    if issued_spec is not None:
        try:
            issued = _parse_issued_spec(issued_spec)
        except ValueError as e:
            print(f"unverifiable: --issued is malformed ({e}) — nothing was checked")
            return 2

    scan = scan_tickets(log.entries(), issuer=issuer)
    try:
        result = reconcile_tickets(present=scan.present, issued=issued, lease_size=lease_size)
    except ValueError as e:
        print(f"unverifiable: {e} — nothing was checked")
        return 2

    # An entry that claimed a ticket payload but could not be parsed is
    # neither confirmed present nor confirmed absent. It can only ever
    # weaken the verdict, via Verdict.join's severity order, never silently
    # leave a BROKEN/OK verdict looking more certain than it is.
    verdict = result.verdict.join(Verdict.UNVERIFIABLE) if scan.unreadable else result.verdict

    if as_json:
        print(
            json.dumps(
                {
                    "issuer": issuer,
                    "measured": result.measured,
                    "verdict": verdict.value,
                    "lease_size": result.lease_size,
                    "missing": list(result.missing) if result.missing is not None else None,
                    "blind_spot_window": (
                        list(result.blind_spot_window)
                        if result.blind_spot_window is not None
                        else None
                    ),
                    "blind_spot_missing": (
                        list(result.blind_spot_missing)
                        if result.blind_spot_missing is not None
                        else None
                    ),
                    "blind_spot_bound": result.blind_spot_bound,
                    "unreadable": list(scan.unreadable),
                }
            )
        )
    else:
        for line in render_reconciliation(result, scan=scan):
            print(line)

    return verdict.to_exit_code()
