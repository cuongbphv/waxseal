"""Exogenous admission tickets (pure; no I/O).

D2: the one construction in the
paper's independent re-analysis that turns a dropped write into one
*positively detected*, the counterweight to the coverage-impossibility
theorem. Every drop metric elsewhere in this codebase, `dropped_writes`
(CLAUDE.md rule 5, `log.py`) included, is at best a MEASURED MINIMUM: a write dropped
before it ever reached a recorder leaves nothing to count, so the true count
can always be higher than what was measured. This module closes that for a
SPECIFIC write, at the cost of an exogenous authority: an issuer (a separate
process, NEVER waxseal itself. waxseal's job here is only to CARRY a ticket
in an entry's payload and RECONCILE it, never to mint one) hands out a
monotonically increasing ticket number per admitted action, in consecutive
"lease" blocks of size `L` so the round-trip to the issuer amortizes to `1/L`
per action instead of one per action.

A ticket the issuer confirms it issued, that never appears on the trail, is
not a measured minimum. It is a named, exact drop.

The reconciliation still cannot see everything, and must say so rather than
imply otherwise. The most recent lease window touched by the issuer's report
is still OPEN: nothing here can tell "the writer has not gotten to those
tickets yet" apart from "used, then lost" for tickets in that window, up to
`L - 1` of them (the model's assumption is that requesting a new lease and
consuming its first ticket are the writer's one atomic step, so at most the
remaining `L - 1` numbers in the newest window are ever ambiguous at a given
snapshot). `blind_spot_bound` states that structural limit unconditionally,
even when nothing is actually missing there this run, because a report that
omits it when nothing showed up would say "clean" about a window that was
never fully checkable. That would be the same collapse CLAUDE.md rule 5 names
elsewhere: unmeasured forced into looking like zero.

Issuer data unreachable this run is a THIRD state, never "0 drops": the
`Ticket*` result reuses `Verdict` (the seventh instance of the Ternary
Evidence Principle in this codebase; see CLAUDE.md's "Named principle").
`UNVERIFIABLE` when the issuer could not be asked, `BROKEN` when a
positively-detected drop was found in a CLOSED window, `OK` otherwise. `OK`
here never means "nothing could possibly be wrong", exactly as `verify`'s
`ok=True` coexists with `dropped_writes=None` (chain integrity and trail
completeness are independent facts). It means "no closed-window drop was
positively detected", and the blind-spot fields are the mandatory companion
fact a caller must render alongside it, never a footnote it can drop.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, Final

from waxseal.domain.header import Entry
from waxseal.domain.verdict import Verdict

TICKET_PAYLOAD_TYPE: Final = "application/vnd.waxseal.admission-ticket+json"


@dataclass(frozen=True, slots=True)
class Ticket:
    """One admission ticket, as handed out by an exogenous issuer and carried
    (never minted) in a waxseal entry's payload.

    ``issuer`` names the authority that granted it, so a trail carrying
    tickets from more than one issuer can still be reconciled per-issuer,
    each against its own independent monotonic sequence, since mixing two
    issuers' numbers into one sequence would make "missing" meaningless.
    """

    issuer: str
    ticket_id: int

    def __post_init__(self) -> None:
        if not isinstance(self.issuer, str) or not self.issuer:
            raise ValueError("issuer must be a non-empty string")
        if isinstance(self.ticket_id, bool) or not isinstance(self.ticket_id, int):
            raise ValueError("ticket_id must be an integer")
        if self.ticket_id < 0:
            raise ValueError("ticket_id must be non-negative")


def to_payload(ticket: Ticket) -> dict[str, Any]:
    """Plain-JSON dict for ``AuditLog.append`` (which canonicalizes it,
    see ``domain.canonical.canonical_json``). Built by hand, matching
    ``domain.decision.to_payload``, so the on-disk shape is owned here."""
    return {"issuer": ticket.issuer, "ticket_id": ticket.ticket_id}


def from_payload(payload: Any) -> Ticket:
    """Parse a ticket payload read back off the trail.

    Raises ``ValueError``, and only ``ValueError``, on anything malformed,
    matching ``domain.decision.from_payload``: a caller scanning a whole
    trail can label one row unreadable and keep going rather than aborting
    the scan over one bad row.
    """
    if not isinstance(payload, dict):
        raise ValueError("ticket payload must be a JSON object")
    return Ticket(
        issuer=payload.get("issuer"),  # type: ignore[arg-type]
        ticket_id=payload.get("ticket_id"),  # type: ignore[arg-type]
    )


@dataclass(frozen=True, slots=True)
class TicketScan:
    """Ticket numbers actually found on the trail for one issuer.

    ``unreadable`` carries the seq of every entry that claims
    ``TICKET_PAYLOAD_TYPE`` but could not be parsed, or whose payload bytes
    were not available to this reader (a header-only source), grouped
    apart from ``present`` rather than silently skipped, matching
    ``domain.report``'s ``decisions_malformed`` convention. A row here is
    neither confirmed present nor confirmed absent; it is unread.
    """

    present: frozenset[int]
    unreadable: tuple[int, ...]


def scan_tickets(entries: Iterable[Entry], *, issuer: str) -> TicketScan:
    """Which ticket numbers for ``issuer`` are actually present on the
    trail. Pure over already-read ``Entry`` values, so no I/O happens here;
    the caller (``cli/tickets.py``) is the one reading the trail."""
    present: set[int] = set()
    unreadable: list[int] = []
    for entry in entries:
        if entry.header.payload_type != TICKET_PAYLOAD_TYPE:
            continue
        if entry.payload is None:
            unreadable.append(entry.header.seq)
            continue
        try:
            ticket = from_payload(json.loads(entry.payload))
        except (ValueError, TypeError, UnicodeDecodeError):
            unreadable.append(entry.header.seq)
            continue
        if ticket.issuer != issuer:
            continue
        present.add(ticket.ticket_id)
    return TicketScan(present=frozenset(present), unreadable=tuple(unreadable))


@dataclass(frozen=True, slots=True)
class TicketReconciliation:
    """Issued-vs-present reconciliation for one issuer's ticket sequence.

    ``measured=False`` (issuer unreachable this run) makes every other
    field but ``lease_size``/``blind_spot_bound``/``verdict`` ``None``,
    never an empty tuple, which would silently read as "measured, zero
    drops" (CLAUDE.md rule 5).

    ``missing`` is the positively-detected drop list: issued, absent from
    the trail, in a lease window CLOSED by a higher window already having
    been issued. ``blind_spot_missing`` is the same shape but for the
    still-OPEN window and is deliberately NEVER folded into ``missing``,
    it names candidates, not confirmed drops.
    """

    measured: bool
    lease_size: int
    verdict: Verdict
    missing: tuple[int, ...] | None
    blind_spot_window: tuple[int, int] | None
    blind_spot_missing: tuple[int, ...] | None
    blind_spot_bound: int


def reconcile_tickets(
    *, present: Iterable[int], issued: Iterable[int] | None, lease_size: int
) -> TicketReconciliation:
    """Reconcile the issuer's ``issued`` ticket numbers against ``present``
    (what the trail actually carries).

    ``issued=None`` means the issuer could not be asked this run (down, or
    simply not queried), returns the unmeasured state, distinct from
    ``issued=()`` (the issuer WAS asked and reports nothing granted yet).
    Both ``present`` and ``issued`` are plain Python ``int`` collections:
    this module never talks to an issuer itself, cross-authority I/O is the
    caller's job (CLAUDE.md: waxseal carries and reconciles, never issues).
    """
    if lease_size < 1:
        raise ValueError("lease_size must be >= 1")
    blind_spot_bound = lease_size - 1

    if issued is None:
        return TicketReconciliation(
            measured=False,
            lease_size=lease_size,
            verdict=Verdict.UNVERIFIABLE,
            missing=None,
            blind_spot_window=None,
            blind_spot_missing=None,
            blind_spot_bound=blind_spot_bound,
        )

    issued_set = set(issued)
    for ticket_id in issued_set:
        if isinstance(ticket_id, bool) or not isinstance(ticket_id, int) or ticket_id < 0:
            raise ValueError("issued ticket numbers must be non-negative integers")

    if not issued_set:
        return TicketReconciliation(
            measured=True,
            lease_size=lease_size,
            verdict=Verdict.OK,
            missing=(),
            blind_spot_window=None,
            blind_spot_missing=(),
            blind_spot_bound=blind_spot_bound,
        )

    present_set = set(present)
    max_issued = max(issued_set)
    # The window containing the highest issued number is still open: a
    # higher window being issued is the only signal this scheme has that an
    # earlier window is done (the issuer, by assumption, only starts a new
    # lease once the previous one is exhausted): everything below it is a
    # CLOSED window and a missing ticket there is a positive detection.
    window_lo = (max_issued // lease_size) * lease_size
    window_hi = window_lo + lease_size - 1

    missing = tuple(sorted(t for t in issued_set if t < window_lo and t not in present_set))
    blind_spot_missing = tuple(
        sorted(t for t in issued_set if window_lo <= t <= window_hi and t not in present_set)
    )
    return TicketReconciliation(
        measured=True,
        lease_size=lease_size,
        verdict=Verdict.BROKEN if missing else Verdict.OK,
        missing=missing,
        blind_spot_window=(window_lo, window_hi),
        blind_spot_missing=blind_spot_missing,
        blind_spot_bound=blind_spot_bound,
    )


def render_reconciliation(
    result: TicketReconciliation, *, scan: TicketScan | None = None
) -> list[str]:
    """Human-readable lines for the CLI. The blind-spot bound is ALWAYS
    stated (even when nothing was missing there this run, even when
    unmeasured): a report must never let a quiet run read as "clean" about
    a window that was structurally never fully checkable (CLAUDE.md rule 5).

    ``scan`` (when given) adds the unreadable-entries line: a row that
    claims a ticket payload but could not be parsed is neither confirmed
    present nor confirmed absent, and must never be silently folded into
    either, matching ``domain.report``'s ``decisions_malformed`` handling.
    """
    lines = [
        f"lease_size={result.lease_size}; structural blind spot: up to "
        f"{result.blind_spot_bound} ticket(s) per open lease window can never be "
        "told apart from 'not yet used' by this reconciliation"
    ]

    if not result.measured:
        lines.append(
            "unmeasured: issuer data was not supplied this run (issuer unreachable, "
            "or simply not queried) — this is NOT the same as '0 drops' (CLAUDE.md "
            "rule 5); nothing was reconciled"
        )
        return lines

    if result.missing:
        lines.append(
            f"detected: {len(result.missing)} ticket(s) positively confirmed "
            f"dropped (issued by the issuer, never present on the trail): "
            f"{list(result.missing)}"
        )
    else:
        lines.append("no positively-detected drops in any closed lease window")

    if result.blind_spot_window is not None:
        lo, hi = result.blind_spot_window
        lines.append(
            f"open lease window [{lo}, {hi}] is not yet closed by a later lease — "
            f"up to {result.blind_spot_bound} of its tickets could be legitimately "
            "unused rather than dropped, and this run cannot tell them apart"
        )
        if result.blind_spot_missing:
            lines.append(
                "  candidates in that window, not on the trail (NOT counted as "
                f"detected drops): {list(result.blind_spot_missing)}"
            )
    else:
        lines.append("no tickets were reported as issued yet — nothing to reconcile")

    if scan is not None and scan.unreadable:
        lines.append(
            f"unreadable: {len(scan.unreadable)} entr"
            f"{'y' if len(scan.unreadable) == 1 else 'ies'} claim a ticket payload "
            f"but could not be parsed (seqs: {list(scan.unreadable)}) — treated as "
            "unverifiable, not as clean"
        )

    return lines
