"""Auditor report: what the trail contains and what was actually checked.

``verify`` answers one question: do the links hold. A supervisor, an internal
audit function, or an external assessor asks a wider one: what is in this
trail, over what period, how many decisions of which kind, how many had a
human in the loop, and (the part that is easy to leave out) which of those
questions nobody measured.

Pure and rendering-only: it computes nothing about integrity that
``verify_chain`` has not already decided, and it never repairs (rule 4).

Three distinctions survive into every rendering, because collapsing any one
of them produces a document more confident than its evidence:

- unverifiable-by-name is not tampering (the reason exit 2 exists);
- ``dropped_writes=None`` is "never measured", not "measured zero" (rule 5);
- a sidecar nobody checked is not a sidecar that passed.

This report states τ (the separation degree) and enumerates the authorities
counted, computed from a caller-supplied ``declared_topology`` via
``domain/separation``: two deployments with identical cryptography and
different τ are not comparably secure, so a report omitting τ would omit the
one quantity that varies between them. `None` (no topology declared) renders
as "not declared", never as `0` or `1` (rule 5). Closes conformance.md gap G1
(waxseal-mfi).
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any, Final

from waxseal.domain.decision import DECISION_PAYLOAD_TYPE, from_payload
from waxseal.domain.header import Entry
from waxseal.domain.separation import (
    SeparationTopology,
    counted_authorities,
    render_counted_authorities,
    separation_degree,
)
from waxseal.domain.verify import VerifyResult
from waxseal.domain.witnessing import (
    WITNESS_INCONSISTENT,
    WITNESS_UNREACHABLE,
    WitnessVerdict,
)

_UNPARSEABLE_NOTE = (
    "rows whose payload this build could not parse as a decision record; "
    "that is a separate question from chain integrity, which `verify` answers"
)

# The prose is frozen under this id. Clarifying the wording means issuing a
# NEW id, never editing this one in place: a control narrative that cites
# "waxseal-scope-v1" must still be able to say what those words were.
SCOPE_ID = "waxseal-scope-v1"

SCOPE_STATEMENT = (
    "This output attests hash-chain integrity and completeness measurements of "
    "RECORDED entries only. It does not attest that any obligation was met, that "
    "payload content is truthful, or that unrecorded events did not occur."
)

# The one-line form for a verdict-bearing CLI command, where the full
# paragraph would bury the verdict it qualifies.
SCOPE_LINE = (
    "scope: attests chain integrity of RECORDED entries only — not that an "
    "obligation was met, not that payload content is truthful, not that "
    "unrecorded events did not occur"
)


#: The reason string a receipts check reports when there is no `.receipts`
#: sidecar AT ALL. Defined here rather than in the CLI because this is the file
#: that has to keep "never measured" apart from "measured and clean" in the
#: document an auditor still has six months later -- the CLI only prints a line
#: on the day. `verify` imports it from here so the two surfaces cannot drift
#: into disagreeing about which state they are describing.
RECEIPTS_NOT_RECORDED_REASON: Final = "no_receipts_recorded"

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


@dataclass(frozen=True, slots=True)
class AuditReport:
    ok: bool
    checked: int
    broken_seq: int | None
    reason: str | None
    unverifiable: tuple[int, ...]
    dropped_writes: int | None
    drops_source: str | None
    entries_total: int
    first_ts: str | None
    last_ts: str | None
    by_payload_type: tuple[tuple[str, int], ...]
    by_fingerprint: tuple[tuple[str, int], ...]
    decisions_total: int
    decisions_malformed: tuple[int, ...]
    by_decision_type: tuple[tuple[str, int], ...]
    by_oversight_mode: tuple[tuple[str, int], ...]
    # Counted separately rather than as a mode named "unrecorded": an
    # institution may legitimately use that word as a mode, and "nobody wrote
    # down whether a human reviewed this" must never be readable as "a human
    # reviewed it and recorded 'unrecorded'".
    oversight_unrecorded: int
    anchors: CheckSummary | None
    attestations: CheckSummary | None
    pin: CheckSummary | None = None
    witnesses: tuple[WitnessVerdict, ...] | None = None
    # `None` means the receipts sidecar was never even looked for, which is a
    # THIRD state above the two the summary itself carries: "looked, no sidecar"
    # (RECEIPTS_NOT_RECORDED_REASON) and "looked, sidecar holds nothing" are
    # both ok=True/checked=0 and neither is coverage.
    receipts: CheckSummary | None = None
    # `None` means no `declared_topology` was supplied: "not declared", never
    # the smallest declared degree (1) or a bare 0 (rule 5). `counted_
    # authorities` is the enumeration a report must carry alongside the bare
    # number: τ is exactly the claim an assessor can check by asking who
    # operates what (conformance.md gap G1).
    separation_degree: int | None = None
    counted_authorities: tuple[tuple[str, int], ...] | None = None

    def to_json(self) -> str:
        return json.dumps(
            {
                "chain": {
                    "ok": self.ok,
                    "checked": self.checked,
                    "broken_seq": self.broken_seq,
                    "reason": self.reason,
                    "unverifiable_seqs": list(self.unverifiable),
                    "unverifiable_note": (
                        "unknown schema fingerprint — NOT evidence of tampering"
                    ),
                },
                "completeness": {
                    "dropped_writes": self.dropped_writes,
                    "drops_source": self.drops_source,
                    "note": (
                        "null means never measured, which is not the same as a "
                        "measured zero; a measured value is a lower bound"
                    ),
                },
                "inventory": {
                    "entries_total": self.entries_total,
                    "first_ts": self.first_ts,
                    "last_ts": self.last_ts,
                    "by_payload_type": dict(self.by_payload_type),
                    "by_fingerprint": dict(self.by_fingerprint),
                },
                "decisions": {
                    "total": self.decisions_total,
                    "by_decision_type": dict(self.by_decision_type),
                    "by_oversight_mode": dict(self.by_oversight_mode),
                    "oversight_unrecorded": self.oversight_unrecorded,
                    "unparseable_seqs": list(self.decisions_malformed),
                    "unparseable_note": _UNPARSEABLE_NOTE,
                },
                "anchors": _summary_obj(self.anchors),
                "attestations": _summary_obj(self.attestations),
                "receipts": _receipts_obj(self.receipts),
                "pin": _summary_obj(self.pin),
                "witnesses": _witnesses_obj(self.witnesses),
                "separation": {
                    "tau": self.separation_degree,
                    "counted_authorities": (
                        None
                        if self.counted_authorities is None
                        else [
                            {"name": name, "count": count}
                            for name, count in self.counted_authorities
                        ]
                    ),
                    "note": (
                        "null means no topology was declared, which is not the same "
                        "as a declared topology of degree 0 or 1"
                    ),
                },
                "scope": {"id": SCOPE_ID, "statement": SCOPE_STATEMENT},
            },
            indent=2,
            sort_keys=True,
        )

    def to_markdown(self) -> str:
        lines = ["# waxseal audit report", "", "## Chain integrity", ""]
        if not self.ok:
            lines.append(
                f"- **BROKEN** at seq={self.broken_seq}: `{self.reason}` "
                f"(verified {self.checked} row(s) before the break)"
            )
        else:
            lines.append(f"- Chain **intact**: {self.checked} row(s) verified")
        if self.unverifiable:
            seqs = ", ".join(str(s) for s in self.unverifiable)
            lines.append(
                f"- {len(self.unverifiable)} row(s) unverifiable by name at seq {seqs} "
                "— unknown schema fingerprint, **NOT** evidence of tampering. "
                "This build cannot reproduce the hash those rows were written "
                "with, and reporting them intact would be a claim it cannot make."
            )
        lines += ["", "## Completeness", ""]
        if self.dropped_writes is None:
            lines.append(
                "- Dropped writes: **not measured**. A write lost before it "
                "reached storage leaves no gap for `verify` to find, so this "
                "is a separate dimension from chain integrity and this trail "
                "carries no measurement of it."
            )
        else:
            lines.append(
                f"- Dropped writes: **>= {self.dropped_writes}** (measured minimum, "
                f"source: {self.drops_source})"
            )
        lines += ["", "## Inventory", "", f"- Entries: {self.entries_total}"]
        if self.first_ts is not None:
            lines.append(f"- Period covered: {self.first_ts} → {self.last_ts}")
        lines += _count_table("Payload type", self.by_payload_type)
        lines += _count_table("Schema fingerprint", self.by_fingerprint, truncate=12)

        if self.decisions_total or self.decisions_malformed:
            lines += ["", "## AI decisions", "", f"- Decisions: {self.decisions_total}"]
            lines += _count_table("Decision type", self.by_decision_type)
            lines += _count_table("Human oversight", self.by_oversight_mode)
            if self.oversight_unrecorded:
                lines.append(
                    f"- Oversight **not recorded**: {self.oversight_unrecorded} decision(s). "
                    "This is not the same claim as automated processing — it "
                    "means the record is silent on whether a person was involved."
                )
            if self.decisions_malformed:
                seqs = ", ".join(str(s) for s in self.decisions_malformed)
                lines.append(
                    f"- Unparseable decision payloads at seq {seqs} — {_UNPARSEABLE_NOTE}."
                )

        lines += ["", "## Sidecar checks", ""]
        lines.append(f"- Anchors: {_summary_text(self.anchors)}")
        lines.append(f"- Attestations: {_summary_text(self.attestations)}")
        lines.append(f"- Receipts: {_receipts_text(self.receipts)}")
        lines.append(f"- Pin: {_summary_text(self.pin)}")
        lines += _witness_lines(self.witnesses)

        lines += ["", "## Separation", ""]
        if self.separation_degree is None:
            lines.append(
                "- τ (separation degree): **not declared** — two deployments with "
                "identical cryptography and different τ are not comparably secure, "
                "and this trail's pin carries no `declared_topology` to measure it "
                "from"
            )
        else:
            breakdown = render_counted_authorities(self.counted_authorities)
            lines.append(f"- τ (separation degree): **{self.separation_degree}** ({breakdown})")

        # Last, so it qualifies everything above without displacing the
        # verdict a reader opened the document for.
        lines += ["", "## Scope", "", SCOPE_STATEMENT]
        return "\n".join(lines) + "\n"


def build_report(
    verify_result: VerifyResult,
    entries: Iterable[Entry],
    *,
    anchors: CheckSummary | None = None,
    attestations: CheckSummary | None = None,
    pin: CheckSummary | None = None,
    witnesses: tuple[WitnessVerdict, ...] | None = None,
    receipts: CheckSummary | None = None,
    declared_topology: SeparationTopology | None = None,
) -> AuditReport:
    """Summarize a trail. ``anchors``/``attestations``/``pin``/``witnesses``/
    ``receipts`` left at ``None`` mean those checks were not run, and the report
    says so rather than implying a pass. ``declared_topology`` left at ``None`` means
    no topology was declared for this trail, so τ renders as "not declared",
    never as ``0`` or ``1`` (rule 5)."""
    by_type: Counter[str] = Counter()
    by_fingerprint: Counter[str] = Counter()
    by_decision_type: Counter[str] = Counter()
    by_oversight: Counter[str] = Counter()
    malformed: list[int] = []
    oversight_unrecorded = 0
    decisions_total = 0
    total = 0
    first_ts: str | None = None
    last_ts: str | None = None

    for entry in entries:
        total += 1
        header = entry.header
        by_type[header.payload_type] += 1
        by_fingerprint[header.hash_version] += 1
        if first_ts is None:
            first_ts = header.ts
        last_ts = header.ts
        if header.payload_type != DECISION_PAYLOAD_TYPE:
            continue
        record = _parse_decision(entry)
        if record is None:
            malformed.append(header.seq)
            continue
        decisions_total += 1
        by_decision_type[record.decision_type] += 1
        if record.human_oversight is None:
            oversight_unrecorded += 1
        else:
            by_oversight[record.human_oversight.mode] += 1

    return AuditReport(
        ok=verify_result.ok,
        checked=verify_result.checked,
        broken_seq=verify_result.broken_seq,
        reason=verify_result.reason,
        unverifiable=verify_result.unverifiable,
        dropped_writes=verify_result.dropped_writes,
        drops_source=verify_result.drops_source,
        entries_total=total,
        first_ts=first_ts,
        last_ts=last_ts,
        by_payload_type=_ranked(by_type),
        by_fingerprint=_ranked(by_fingerprint),
        decisions_total=decisions_total,
        decisions_malformed=tuple(malformed),
        by_decision_type=_ranked(by_decision_type),
        by_oversight_mode=_ranked(by_oversight),
        oversight_unrecorded=oversight_unrecorded,
        anchors=anchors,
        attestations=attestations,
        pin=pin,
        witnesses=witnesses,
        receipts=receipts,
        separation_degree=separation_degree(declared_topology),
        counted_authorities=counted_authorities(declared_topology),
    )


def _parse_decision(entry: Entry) -> Any:
    if entry.payload is None:
        # Header-only reader: nothing here to parse. Grouped with malformed
        # because both mean "this report could not read the decision", and
        # the report must not imply it read one it did not.
        return None
    try:
        return from_payload(json.loads(entry.payload))
    except (ValueError, TypeError, UnicodeDecodeError):
        return None


def _ranked(counter: Counter[str]) -> tuple[tuple[str, int], ...]:
    """Most frequent first, ties broken by name, so two audits of the same
    trail must diff cleanly."""
    return tuple(sorted(counter.items(), key=lambda kv: (-kv[1], kv[0])))


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
