"""AI incident record schema and window reading (pure; no I/O).

Decree 142/2026/NĐ-CP Điều 19(2)(a) obliges a deployer and a user to "kịp
thời ghi nhận sự cố" — to record a serious incident promptly — and Điều 19(4)
obliges them to keep the system log and the incident data for the authority's
verification. This module defines the evidence unit for that: a payload
schema carried by the existing envelope, shaped so it can fill form Mẫu AI01a
§II-§III of the same Decree, so the chain, the fingerprint registry and every
backend stay untouched (CLAUDE.md: changing payload schema never touches the
chain).

What the record proves and what it cannot
-----------------------------------------
It proves that an incident record with these contents sat at sequence n of a
chain whose history has not been edited since. It does NOT prove that a
report was filed with the authority. ``report_ref`` holds whatever receipt
the submission produced — a code from the one-stop Portal, or a reference
issued by the alternative electronic channel Điều 46(1) gives equal legal
effect to while the Portal is not yet operating — and ``None`` there means *no
submission is recorded on this trail*, never "not reported". waxseal has no
channel to the authority and cannot know the difference.

The reporting clock
-------------------
Điều 19(3)(a) runs 72 hours, and Điều 19(3)(b) five working days, from the
"thời điểm xác nhận sự cố", which Điều 19(3)(c) defines as the moment there
is enough initial information to establish that the incident actually
happened and is likely to originate in the AI system's fault — explicitly
not waiting for a complete technical root-cause investigation. That moment is
``confirmed_at`` (Mẫu AI01a §III.2), and it is a DIFFERENT fact from
``detected_at`` (§III.1). ``window_status`` is anchored on ``confirmed_at``
alone and returns ``unmeasured`` when it is absent: substituting the
detection moment would silently re-anchor a statutory clock onto the wrong
event, which is the kind of quiet re-interpretation this codebase exists to
refuse.

Timestamps are validated as non-empty strings and NOTHING more at
construction. Parsing them here would make a newer writer's timestamp shape
into "a bad row" — the beads v1.2.2 failure class. Parsing happens in the
reader, which reports what it cannot read as ``unmeasured``.

Append-only restatement
-----------------------
A submission normally happens after the incident is first logged, and the log
is append-only (CLAUDE.md). So a restatement appends a NEW row with the same
``incident_id``, and ``scan_incidents`` folds rows by that id with the LATEST
ROW WINNING AS A WHOLE RECORD. Not a field-wise merge: merging row 1's
severity into row 2's report reference would synthesise a record nobody ever
wrote and nobody ever signed. ``IncidentView.rows`` exposes how many rows
went into a view, so a restatement history is visible rather than hidden
behind its own result.
"""

from __future__ import annotations

import enum
import json
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Final

from waxseal.domain.header import Entry

INCIDENT_PAYLOAD_TYPE: Final = "application/vnd.waxseal.ai-incident.v1+json"


def _require_nonempty(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _optional_str(value: Any, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string or null")
    return value


@dataclass(frozen=True, slots=True)
class IncidentRecord:
    """One serious-incident record, shaped to fill Mẫu AI01a §II-§III.

    ``system_id`` is the system identifier the form calls "Mã định danh hệ
    thống (AI-ID)" (§II.2) — the code the one-stop Portal issues, or the
    provider's own internal identifier where none has been issued yet.

    ``severity``, ``consequence_kinds`` and ``operating_status`` are all
    recorded VERBATIM as the caller declared them, with no enum and no
    normalization, for the same reason ``DecisionRecord.risk_tier`` is a free
    string: the declaration is the caller's, and restating it in this build's
    vocabulary would put words in their mouth. ``consequence_kinds`` covers
    the §III.5 categories (tính mạng/sức khoẻ · tài sản · quyền con
    người/riêng tư · dịch vụ công/thiết yếu · an ninh quốc gia); an empty
    tuple means none were declared.

    ``summary`` is redacted free text (§III.4): it goes through the log's
    redactor before ``payload_hash`` is computed, like every other payload.
    """

    incident_id: str
    system_id: str
    # Mẫu AI01a §III.1, "Thời điểm phát hiện sự cố". Caller-asserted, stored
    # verbatim, and NOT the anchor of the reporting window — see confirmed_at.
    detected_at: str
    severity: str
    # Mẫu AI01a §III.2, "Thời điểm xác nhận mối liên hệ nhân quả với hệ thống
    # trí tuệ nhân tạo": the moment Điều 19(3)(c) defines and Điều 19(3)(a)/(b)
    # run their 72-hour and 5-working-day deadlines from. None means the
    # confirmation moment was not recorded, which is not the detection moment
    # and is never substituted by it (rule 5).
    confirmed_at: str | None = None
    summary: str | None = None
    consequence_kinds: tuple[str, ...] = ()
    operating_status: str | None = None
    # An opaque reference to a submission: a Portal receipt code, or a
    # reference from the alternative electronic channel Điều 46(1) permits
    # while the Portal is not yet operating. None means NO SUBMISSION IS
    # RECORDED ON THIS TRAIL — never "not reported". waxseal has no channel to
    # the authority and cannot tell the two apart.
    report_ref: str | None = None
    reported_at: str | None = None
    trace_id: str | None = None

    def __post_init__(self) -> None:
        _require_nonempty(self.incident_id, "incident_id")
        _require_nonempty(self.system_id, "system_id")
        _require_nonempty(self.detected_at, "detected_at")
        _require_nonempty(self.severity, "severity")
        for field in (
            "confirmed_at",
            "summary",
            "operating_status",
            "report_ref",
            "reported_at",
            "trace_id",
        ):
            _optional_str(getattr(self, field), field)
        if not isinstance(self.consequence_kinds, tuple):
            raise ValueError("consequence_kinds must be a tuple of non-empty strings")
        for kind in self.consequence_kinds:
            if not isinstance(kind, str) or not kind:
                raise ValueError("consequence_kinds must be a tuple of non-empty strings")


def to_payload(record: IncidentRecord) -> dict[str, Any]:
    """Plain-JSON dict for ``AuditLog.append``.

    Built by hand rather than ``dataclasses.asdict``, matching
    ``domain.decision.to_payload``, so the on-disk shape is owned here: a
    field added to the dataclass for internal use cannot leak into the hashed
    payload without someone editing this function. Every key is present
    always and every optional is an explicit ``null``: an omitted key cannot
    be told apart from a schema that never had the field, and "no submission
    is recorded" is exactly the fact an auditor needs to read (rule 5).
    """
    return {
        "incident_id": record.incident_id,
        "system_id": record.system_id,
        "detected_at": record.detected_at,
        "severity": record.severity,
        "confirmed_at": record.confirmed_at,
        "summary": record.summary,
        "consequence_kinds": list(record.consequence_kinds),
        "operating_status": record.operating_status,
        "report_ref": record.report_ref,
        "reported_at": record.reported_at,
        "trace_id": record.trace_id,
    }


def from_payload(payload: Any) -> IncidentRecord:
    """Parse an incident payload read back off the trail.

    Raises ``ValueError``, and only ``ValueError``, on anything malformed, so
    a caller auditing a whole trail can label one row unreadable and keep
    going. Unreadable is a third verdict, distinct from intact and from
    tampered: the chain check has its own answer about those bytes and this
    function must not pre-empt it.

    Keys this version does not know are ignored, not rejected: a newer writer
    must never make an older reader call the row broken.

    An absent ``consequence_kinds`` key and an explicit ``null`` both read as
    ``()``. For the question the form asks — which consequence categories were
    declared? — the two have the same answer, so there is no third state to
    keep apart here.
    """
    if not isinstance(payload, dict):
        raise ValueError("incident payload must be a JSON object")
    kinds_raw = payload.get("consequence_kinds")
    if kinds_raw is None:
        kinds: tuple[str, ...] = ()
    elif isinstance(kinds_raw, (list, tuple)):
        # tuple("tài sản") would silently become nine one-character "kinds",
        # so the list shape is checked rather than coerced.
        kinds = tuple(kinds_raw)
    else:
        raise ValueError("consequence_kinds must be a JSON list of non-empty strings")
    # Every remaining shape error surfaces from __post_init__, which already
    # raises ValueError.
    return IncidentRecord(
        incident_id=payload.get("incident_id"),  # type: ignore[arg-type]
        system_id=payload.get("system_id"),  # type: ignore[arg-type]
        detected_at=payload.get("detected_at"),  # type: ignore[arg-type]
        severity=payload.get("severity"),  # type: ignore[arg-type]
        confirmed_at=payload.get("confirmed_at"),
        summary=payload.get("summary"),
        consequence_kinds=kinds,
        operating_status=payload.get("operating_status"),
        report_ref=payload.get("report_ref"),
        reported_at=payload.get("reported_at"),
        trace_id=payload.get("trace_id"),
    )


@dataclass(frozen=True, slots=True)
class IncidentView:
    """Every row on the trail for one ``incident_id``, folded.

    ``latest`` is the newest row AS A WHOLE RECORD, never a field-wise merge
    of the rows before it. ``rows`` is the number of rows that went into this
    view, exposed rather than hidden: a view built from four rows is a
    restatement history an auditor should be able to see, and a caller that
    wants the rows themselves reads them off the trail by seq.
    """

    incident_id: str
    first_seq: int
    latest_seq: int
    rows: int
    latest: IncidentRecord


@dataclass(frozen=True, slots=True)
class IncidentScan:
    """Folded incident views, plus the rows that could not be read.

    ``unreadable`` carries the seq of every entry claiming
    ``INCIDENT_PAYLOAD_TYPE`` that could not be parsed, or whose payload bytes
    were not available to this reader (a header-only source), grouped apart
    from ``views`` rather than silently skipped — matching
    ``domain.tickets.TicketScan``. A row here is neither counted as an
    incident nor confirmed absent; it is unread, and a listing carrying one is
    not a complete listing.
    """

    views: tuple[IncidentView, ...]
    unreadable: tuple[int, ...]


def scan_incidents(entries: Iterable[Entry]) -> IncidentScan:
    """Fold the trail's incident rows by ``incident_id``, in chain order of
    first appearance.

    Pure over already-read ``Entry`` values, so no I/O happens here; the
    caller is the one reading the trail. Never raises: these payload bytes
    come off disk or off the wire, where the threat model says an attacker may
    have written them, and a scan that died on one hostile row would deny the
    caller every other row's evidence.
    """
    order: list[str] = []
    folded: dict[str, IncidentView] = {}
    unreadable: list[int] = []
    for entry in entries:
        if entry.header.payload_type != INCIDENT_PAYLOAD_TYPE:
            continue
        if entry.payload is None:
            unreadable.append(entry.header.seq)
            continue
        try:
            record = from_payload(json.loads(entry.payload))
        except (ValueError, TypeError, UnicodeDecodeError):
            unreadable.append(entry.header.seq)
            continue
        seq = entry.header.seq
        previous = folded.get(record.incident_id)
        if previous is None:
            order.append(record.incident_id)
            folded[record.incident_id] = IncidentView(
                incident_id=record.incident_id,
                first_seq=seq,
                latest_seq=seq,
                rows=1,
                latest=record,
            )
        else:
            folded[record.incident_id] = IncidentView(
                incident_id=previous.incident_id,
                first_seq=previous.first_seq,
                latest_seq=seq,
                rows=previous.rows + 1,
                latest=record,
            )
    return IncidentScan(
        views=tuple(folded[incident_id] for incident_id in order),
        unreadable=tuple(unreadable),
    )


class WindowStatus(enum.Enum):
    """What this trail records about one incident against a reporting window.

    Five values, and the fifth is the point. ``UNMEASURED`` is not a degraded
    ``NO_REPORT_RECORDED_PAST_WINDOW``: rendering "nothing was measurable
    here" as "no submission inside the window" invents a finding about a legal
    obligation out of a timestamp this build could not read, which is the
    collapse CLAUDE.md's "Named principle" forbids. Rendering it as
    ``WINDOW_OPEN`` would be the same collapse from the other side.

    Deliberately NOT ``domain.verdict.Verdict``: none of these five is a
    finding about chain integrity, and none of them carries an exit code.
    ``domain.archive.ArchiveState`` is the precedent — the same SHAPE (an
    enum, an exhaustive spelled-out table, a renderer that always states the
    weaker claim) with its own values.
    """

    REPORT_RECORDED_WITHIN_WINDOW = "report_recorded_within_window"
    REPORT_RECORDED_AFTER_WINDOW = "report_recorded_after_window"
    WINDOW_OPEN = "window_open"
    NO_REPORT_RECORDED_PAST_WINDOW = "no_report_recorded_past_window"
    UNMEASURED = "unmeasured"


@dataclass(frozen=True, slots=True)
class WindowReading:
    """One window reading: the status, why, and how many hours it measured.

    ``reason`` is required and carries a cause even on the measured statuses.
    An ``unmeasured`` label with no cause is only marginally better than
    silence — an operator who cannot tell which of seven causes they hit can
    act on none of them (CLAUDE.md's instance 10, the same discipline
    ``rfc3161_verify``'s ``signature_unchecked`` labels carry).

    ``elapsed_h`` is the hours from ``confirmed_at`` to the submission time
    when one is recorded, and to the as-of time when none is. ``None`` means
    nothing was measured — never zero hours.
    """

    status: WindowStatus
    reason: str
    elapsed_h: float | None


def _unmeasured(reason: str) -> WindowReading:
    return WindowReading(status=WindowStatus.UNMEASURED, reason=reason, elapsed_h=None)


def _parse_offset_aware(raw: str, field: str) -> datetime | str:
    """A parsed offset-aware datetime, or the reason it is not one.

    The reason never quotes the raw value back. The value came off the trail,
    where an attacker may have written it, and a renderer that echoes it hands
    that attacker a line of waxseal's own output to write; the field name and
    the shape problem are what an operator needs, and ``waxseal inspect``
    shows the bytes.
    """
    try:
        parsed = datetime.fromisoformat(raw)
    except (ValueError, TypeError):
        return (
            f"{field} is not an ISO-8601 timestamp this build can read, so nothing was "
            "measured against the window; a shape this reader does not know is a newer "
            "writer, never a bad row"
        )
    if parsed.tzinfo is None or parsed.tzinfo.utcoffset(parsed) is None:
        return (
            f"{field} carries no UTC offset, and an offset-naive moment cannot be "
            "compared with an offset-aware one without inventing a time zone for it, so "
            "nothing was measured against the window"
        )
    return parsed


def window_status(
    view: IncidentView, *, window: timedelta, now: datetime
) -> WindowReading:
    """What this trail records about ``view`` against a reporting ``window``.

    The anchor is ``confirmed_at`` — the Điều 19(3)(c) confirmation moment
    that Điều 19(3)(a)/(b) run their deadlines from — and never
    ``detected_at``. ``now`` is injected (CLAUDE.md rule 8) both so tests
    never sleep and so an operator can ask the question as of a stated moment
    rather than as of whenever the process happened to run.

    Reads, never adjudicates. Every status is a statement about what the trail
    records at caller-asserted times; whether an obligation was met is a
    determination for the operator and the authority, on evidence that
    includes the submission channel this process cannot see.

    Never raises: both timestamps come off the trail, where the threat model
    says an attacker may have written them, and every shape this build cannot
    read comes back as an ``unmeasured`` reading naming its own cause.
    ``window`` and ``now`` are the caller's own in-process values; an
    offset-naive ``now`` is still reported as unmeasured rather than compared,
    because comparing naive to aware raises in Python and a guessed time zone
    would be invented evidence.
    """
    if view.latest.confirmed_at is None:
        return _unmeasured(
            "confirmed_at is not recorded on this row, and the reporting window is "
            "anchored on the confirmation moment (Decree 142/2026/ND-CP Dieu 19(3)(c)); "
            "detected_at records a different fact and is never substituted for it"
        )
    confirmed = _parse_offset_aware(view.latest.confirmed_at, "confirmed_at")
    if isinstance(confirmed, str):
        return _unmeasured(confirmed)

    if view.latest.reported_at is None:
        if view.latest.report_ref is not None:
            return _unmeasured(
                "report_ref is recorded on this row while reported_at is not, so a "
                "submission is claimed on this trail but has no asserted time to place "
                "against the window"
            )
        if now.tzinfo is None or now.tzinfo.utcoffset(now) is None:
            return _unmeasured(
                "the as-of time carries no UTC offset, and an offset-naive moment cannot "
                "be compared with the offset-aware confirmed_at without inventing a time "
                "zone for it, so nothing was measured against the window"
            )
        if now < confirmed:
            return _unmeasured(
                "the as-of time is earlier than confirmed_at, so either the clock is "
                "skewed or the question was asked as of a moment before the confirmation; "
                "neither measures the window"
            )
        elapsed = now - confirmed
        if elapsed <= window:
            return WindowReading(
                status=WindowStatus.WINDOW_OPEN,
                reason=(
                    "no submission time is recorded on this trail and the window measured "
                    "from confirmed_at has not gone by as of the given time"
                ),
                elapsed_h=elapsed.total_seconds() / 3600.0,
            )
        return WindowReading(
            status=WindowStatus.NO_REPORT_RECORDED_PAST_WINDOW,
            reason=(
                "no submission time is recorded on this trail and the window measured "
                "from confirmed_at has gone by as of the given time; this states what "
                "the trail records, never that no report was filed"
            ),
            elapsed_h=elapsed.total_seconds() / 3600.0,
        )

    reported = _parse_offset_aware(view.latest.reported_at, "reported_at")
    if isinstance(reported, str):
        return _unmeasured(reported)
    if reported < confirmed:
        return _unmeasured(
            "reported_at is earlier than confirmed_at, a contradiction between two of "
            "the caller's own asserted times; a pair that cannot both hold is never "
            "read as a submission inside the window"
        )
    elapsed = reported - confirmed
    if elapsed <= window:
        # Điều 19(3)(a) says "trong thời hạn 72 giờ" — within the period, so
        # the boundary instant is inside it and the comparison is `<=`.
        return WindowReading(
            status=WindowStatus.REPORT_RECORDED_WITHIN_WINDOW,
            reason=(
                "a submission time is recorded on this trail and falls inside the window "
                "measured from confirmed_at"
            ),
            elapsed_h=elapsed.total_seconds() / 3600.0,
        )
    return WindowReading(
        status=WindowStatus.REPORT_RECORDED_AFTER_WINDOW,
        reason=(
            "a submission time is recorded on this trail and falls outside the window "
            "measured from confirmed_at; whether an obligation was met is a "
            "determination for the operator and the authority, never for this tool"
        ),
        elapsed_h=elapsed.total_seconds() / 3600.0,
    )


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
                ", ".join(record.consequence_kinds)
                if record.consequence_kinds
                else "none declared"
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
