"""Render helpers for AuditReport. Types and build_report stay on report.py."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Final

from waxseal.domain.report import RECEIPTS_NOT_RECORDED_REASON, CheckSummary
from waxseal.domain.witnessing import (
    WITNESS_INCONSISTENT,
    WITNESS_UNREACHABLE,
    WitnessVerdict,
)

_UNPARSEABLE_NOTE = (
    "rows whose payload this build could not parse as a decision record; "
    "that is a separate question from chain integrity, which `verify` answers"
)

# The receipts dimension's states, named rather than re-derived at each render
# site. `verify` has carried this three-way distinction since J2; `report`
# carried none of it, so the artifact that outlives the terminal was the one
# surface where receipt coverage was invisible.
_RECEIPTS_NOT_CHECKED: Final = "not_checked"
_RECEIPTS_NOT_RECORDED: Final = "not_recorded"
_RECEIPTS_PRESENT_EMPTY: Final = "present_empty"
_RECEIPTS_CHECKED: Final = "checked"
_RECEIPTS_BROKEN: Final = "broken"
_RECEIPTS_UNVERIFIABLE: Final = "unverifiable"

# The JSON half of the distinction. A consumer reading `state` never has to
# know the reason strings by heart, and `not_recorded` can never be diffed
# against `present_empty` as if both were "0 receipts, fine".
_RECEIPTS_JSON_NOTE: Final = (
    "state 'not_checked' means nobody looked; 'not_recorded' means there is no "
    "sidecar, so acknowledgment was never measured; 'present_empty' means the "
    "sidecar exists and covers no entry. None of the three is 'checked'."
)

# Only the three states a generic CheckSummary rendering would collapse are
# spelled out here; broken/unverifiable/checked fall through to
# `_summary_text`, which already says the right thing about them. The point of
# the table is that "no sidecar" and "sidecar with nothing in it" must not both
# render as some flavour of ok (rule 5, one sidecar over from dropped_writes).
_RECEIPTS_LABEL: Final[dict[str, str]] = {
    _RECEIPTS_NOT_CHECKED: "**not checked** (absence of a check is not a pass)",
    _RECEIPTS_NOT_RECORDED: (
        "**not recorded** — there is no `.receipts` sidecar beside this trail, so "
        "per-append acknowledgment by a second authority was never measured here. "
        "That is **not** the same claim as measured and clean."
    ),
    _RECEIPTS_PRESENT_EMPTY: (
        "sidecar present, **0 record(s)** — checked, and it held nothing to check. "
        "Not the same as no sidecar at all, and not coverage of any entry."
    ),
}

def _count_table(
    label: str, counts: Sequence[tuple[str, int]], *, truncate: int | None = None
) -> list[str]:
    if not counts:
        return []
    lines = ["", f"| {label} | Count |", "|---|---:|"]
    for name, count in counts:
        shown = f"{name[:truncate]}…" if truncate and len(name) > truncate else name
        lines.append(f"| `{shown}` | {count} |")
    return lines


def _incident_lines(
    total: int | None,
    no_report_recorded: int | None,
    by_severity: tuple[tuple[str, int], ...],
    malformed: tuple[int, ...],
) -> list[str]:
    """The incidents section, rendered even when the trail records none.

    Unlike the decisions section, which is omitted when empty, this one is
    always present. An absent section cannot be told apart from "none
    recorded" and "never scanned", and those are the two values the third
    state exists to separate — leaving the reader to infer which is exactly
    the collapse CLAUDE.md's "Named principle" is about.
    """
    lines = ["", "## Incidents", ""]
    if total is None:
        lines.append(
            "- Incident records: **not scanned**. The absence of a scan is "
            "not a count of zero."
        )
        return lines
    lines.append(
        f"- Incident records on this trail: **{total}** — a count of RECORDED "
        "incidents, not evidence that no others occurred."
    )
    lines += _count_table("Declared severity", by_severity)
    if no_report_recorded:
        lines.append(
            f"- **No submission recorded** for {no_report_recorded} incident(s): "
            "the latest row carries no submission reference. That is a fact "
            "about this trail, not about the authority's channel, which this "
            "process cannot see. For the reporting-window reading, run "
            "`waxseal incidents`."
        )
    if malformed:
        seqs = ", ".join(str(s) for s in malformed)
        lines.append(f"- Unparseable incident payloads at seq {seqs} — {_UNPARSEABLE_NOTE}.")
    return lines


def _intervention_lines(
    total: int | None,
    by_action: tuple[tuple[str, int], ...],
    malformed: tuple[int, ...],
) -> list[str]:
    """The human-intervention section, always rendered, for the same reason."""
    lines = ["", "## Human interventions", ""]
    if total is None:
        lines.append(
            "- Intervention records: **not scanned**. The absence of a scan "
            "is not a count of zero."
        )
        return lines
    lines.append(
        f"- Intervention records on this trail: **{total}** — a count of "
        "RECORDED interventions. A supervision mechanism switched off writes "
        "nothing, so no log witnesses its own absence."
    )
    lines += _count_table("Declared action", by_action)
    if malformed:
        seqs = ", ".join(str(s) for s in malformed)
        lines.append(f"- Unparseable intervention payloads at seq {seqs} — {_UNPARSEABLE_NOTE}.")
    return lines


def _witnesses_obj(
    verdicts: tuple[WitnessVerdict, ...] | None,
) -> list[dict[str, Any]] | None:
    if verdicts is None:
        return None
    return [
        {
            "name": v.name,
            "status": v.status,
            "checked": v.checked,
            "reason": v.reason,
            "broken_seq": v.broken_seq,
            "unreadable": v.unreadable,
        }
        for v in verdicts
    ]


def _witness_lines(verdicts: tuple[WitnessVerdict, ...] | None) -> list[str]:
    if verdicts is None:
        return ["- Witnesses: **not checked** (absence of a check is not a pass)"]
    if not verdicts:
        return ["- Witnesses: none configured"]
    lines = ["- Witnesses:"]
    for v in verdicts:
        if v.status == WITNESS_UNREACHABLE:
            lines.append(
                f"  - `{v.name}`: **unreachable** ({v.reason}) — not checked, "
                "which is not a pass"
            )
        elif v.status == WITNESS_INCONSISTENT:
            lines.append(
                f"  - `{v.name}`: **INCONSISTENT** at seq={v.broken_seq} "
                f"(`{v.reason}`) — the trail does not extend what this witness saw"
            )
        else:
            detail = f"checked {v.checked}"
            if v.reason is not None:
                detail += f", `{v.reason}` — holds nothing, so covers nothing"
            if v.unreadable:
                detail += f", {v.unreadable} record(s) unreadable by this build"
            lines.append(f"  - `{v.name}`: consistent ({detail})")
    return lines


def _summary_obj(summary: CheckSummary | None) -> dict[str, Any] | None:
    if summary is None:
        return None
    return _summary_fields(summary)


def _summary_fields(summary: CheckSummary) -> dict[str, Any]:
    return {
        "ok": summary.ok,
        "checked": summary.checked,
        "reason": summary.reason,
        "unverifiable": summary.unverifiable,
        "notes": list(summary.notes),
    }


def _receipts_state(summary: CheckSummary) -> str:
    """Which of the receipts dimension's states this summary is in.

    Order matters: a break outranks everything, and the two ok/checked=0 states
    are separated by the reason string, which is the ONLY thing that tells
    "there is no sidecar" from "the sidecar is empty".
    """
    if not summary.ok:
        return _RECEIPTS_BROKEN
    if summary.unverifiable:
        return _RECEIPTS_UNVERIFIABLE
    if summary.reason == RECEIPTS_NOT_RECORDED_REASON:
        return _RECEIPTS_NOT_RECORDED
    if summary.checked == 0:
        return _RECEIPTS_PRESENT_EMPTY
    return _RECEIPTS_CHECKED


def _receipts_obj(summary: CheckSummary | None) -> dict[str, Any]:
    """The summary plus the state NAMED, so a JSON consumer never has to infer
    absent-vs-empty from a reason string it would have to know by heart.

    Never `null`, unlike the other sidecars: a null would be a fourth way to
    say one of the three things `state` already says, and the one an
    unsuspecting consumer would read as "no data" rather than "nobody looked".
    """
    if summary is None:
        return {
            "state": _RECEIPTS_NOT_CHECKED,
            "note": _RECEIPTS_JSON_NOTE,
        }
    return {
        **_summary_fields(summary),
        "state": _receipts_state(summary),
        "note": _RECEIPTS_JSON_NOTE,
    }


def _receipts_text(summary: CheckSummary | None) -> str:
    if summary is None:
        return _RECEIPTS_LABEL[_RECEIPTS_NOT_CHECKED]
    state = _receipts_state(summary)
    if state in _RECEIPTS_LABEL:
        return _RECEIPTS_LABEL[state]
    # checked / broken / unverifiable: the generic rendering already keeps
    # those three apart, including the notes that qualify an `ok`.
    return _summary_text(summary)


def _summary_text(summary: CheckSummary | None) -> str:
    if summary is None:
        return "**not checked** (absence of a check is not a pass)"
    if not summary.ok:
        return f"**BROKEN**: `{summary.reason}` ({summary.checked} checked)"
    if summary.unverifiable:
        head = (
            f"**unverifiable**: `{summary.reason}` — this build could not read it "
            "by name, which is NOT evidence of tampering"
        )
    else:
        # A passing check can still carry a caveat worth printing: "the
        # sidecar exists and holds nothing" passes without having measured
        # anything, and a reader must not take it for coverage.
        head = f"ok ({summary.checked} checked)"
        if summary.reason is not None:
            head = f"{head} — `{summary.reason}`"
    return head + "".join(f"\n  - note: {note}" for note in summary.notes)
