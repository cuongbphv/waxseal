"""Human-intervention record schema (pure; no I/O).

``DecisionRecord.human_oversight`` already records who stood between a model
and ONE outcome. This is the other shape the same obligation takes: an act of
supervision that is not an act on one decision — halting a system, revoking a
deployment, activating an emergency stop.

Scope, and it matters
---------------------
These rows evidence that intervention decisions were RETAINED UNALTERED,
which is what Decree 142/2026/NĐ-CP Điều 11(5) asks for in so many words —
during a transitional reclassification the provider and deployer "phải lưu
trữ đầy đủ nhật ký vận hành và các quyết định can thiệp để phục vụ công tác
thanh tra, kiểm tra" — and what Điều 15(2)(c)'s obligation to "thiết kế và
duy trì cơ chế giám sát và can thiệp của con người" needs evidence for.

They CANNOT evidence that no intervention mechanism was obstructed, which is
what Law on AI 134/2025/QH15 Điều 7(4) prohibits ("Cản trở, vô hiệu hóa hoặc
làm sai lệch cơ chế giám sát, can thiệp và kiểm soát của con người"). A
mechanism that was switched off writes nothing, and no log witnesses its own
absence. An intact chain of intervention rows is evidence about the rows that
exist, never about the ones an obstructed mechanism never produced. Nothing
in this module or its renderers may be read as the stronger claim.

No ``occurred_at``
------------------
Unlike an incident — which is discovered, confirmed and reported at three
separate moments, all of them before or after the row that describes them —
the intervention IS the act being recorded. The entry header's ``ts`` is its
time, so a second caller-asserted timestamp inside the payload would only
create a pair that can disagree.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, Final

from waxseal.domain.header import Entry

INTERVENTION_PAYLOAD_TYPE: Final = "application/vnd.waxseal.human-intervention.v1+json"


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
class InterventionRecord:
    """One recorded act of human supervision or intervention.

    ``actor_ref`` MUST be pseudonymous — a staff id, a role handle, a queue
    name — never a person's name or contact details, for the same reason
    ``DecisionRecord.human_oversight.reviewer_ref`` carries that rule: the
    trail is designed to be shared with auditors and cannot be selectively
    unredacted later, so a name written here is a name that stays written.
    This library CANNOT enforce that; it is stated here because the only
    place it can be enforced is the caller.

    ``action`` is a verbatim free string, no enum — institutions name their
    own controls, and a closed vocabulary would force a lossy mapping. One
    recommendation, not a requirement: Mẫu AI08a asks separately for the
    number of supervision interventions (§V.6, "Người/bộ phận có thẩm quyền
    giám sát, can thiệp và số lần can thiệp") and the number of emergency-stop
    activations (§V.9, "Số lần kích hoạt cơ chế dừng khẩn cấp"), so a deployer
    who wants those two counts to be readable off the trail should use a
    stable label for each rather than free prose that varies per row.

    ``decision_ref`` is the ``decision_id`` of the decision this acts on, not
    a seq: a ``decision_id`` survives export into a proof bundle and survives
    moving between trails, while a seq is trail-local and stops meaning
    anything the moment the row leaves its trail. ``None`` means the
    intervention is not tied to a recorded decision, which is legitimate —
    halting a whole system is not an act on one decision. A ``decision_ref``
    naming a decision that is not on this trail is NOT an error either: the
    decision may live on another trail or predate this one, and there is
    deliberately no cross-check here to call it broken.
    """

    intervention_id: str
    system_id: str
    actor_ref: str
    action: str
    decision_ref: str | None = None
    rationale: str | None = None
    trace_id: str | None = None

    def __post_init__(self) -> None:
        _require_nonempty(self.intervention_id, "intervention_id")
        _require_nonempty(self.system_id, "system_id")
        _require_nonempty(self.actor_ref, "actor_ref")
        _require_nonempty(self.action, "action")
        for field in ("decision_ref", "rationale", "trace_id"):
            _optional_str(getattr(self, field), field)


def to_payload(record: InterventionRecord) -> dict[str, Any]:
    """Plain-JSON dict for ``AuditLog.append``.

    Built by hand rather than ``dataclasses.asdict``, matching
    ``domain.decision.to_payload``, so the on-disk shape is owned here. Every
    optional is an explicit ``null``: an omitted key cannot be told apart from
    a schema that never had the field (rule 5).
    """
    return {
        "intervention_id": record.intervention_id,
        "system_id": record.system_id,
        "actor_ref": record.actor_ref,
        "action": record.action,
        "decision_ref": record.decision_ref,
        "rationale": record.rationale,
        "trace_id": record.trace_id,
    }


def from_payload(payload: Any) -> InterventionRecord:
    """Parse an intervention payload read back off the trail.

    Raises ``ValueError``, and only ``ValueError``, on anything malformed, so
    a caller auditing a whole trail can label one row unreadable and keep
    going. Keys this version does not know are ignored, not rejected: a newer
    writer must never make an older reader call the row broken.
    """
    if not isinstance(payload, dict):
        raise ValueError("intervention payload must be a JSON object")
    # Every shape error surfaces from __post_init__, which already raises
    # ValueError.
    return InterventionRecord(
        intervention_id=payload.get("intervention_id"),  # type: ignore[arg-type]
        system_id=payload.get("system_id"),  # type: ignore[arg-type]
        actor_ref=payload.get("actor_ref"),  # type: ignore[arg-type]
        action=payload.get("action"),  # type: ignore[arg-type]
        decision_ref=payload.get("decision_ref"),
        rationale=payload.get("rationale"),
        trace_id=payload.get("trace_id"),
    )


@dataclass(frozen=True, slots=True)
class InterventionScan:
    """Intervention rows found on the trail, plus the rows that could not be
    read.

    ``records`` pairs each row's seq with its record, in chain order, and is
    deliberately NOT folded by ``intervention_id``: two rows carrying one id
    are two acts a caller labelled alike, never one act restated. (That is the
    opposite of ``domain.incident``, where a submission recorded after the
    fact IS a restatement of one incident.)

    ``unreadable`` carries the seq of every entry claiming
    ``INTERVENTION_PAYLOAD_TYPE`` that could not be parsed, or whose payload
    bytes were not available to this reader, grouped apart rather than
    silently skipped — matching ``domain.tickets.TicketScan``.
    """

    records: tuple[tuple[int, InterventionRecord], ...]
    unreadable: tuple[int, ...]


def scan_interventions(entries: Iterable[Entry]) -> InterventionScan:
    """Every intervention row on the trail, in chain order.

    Pure over already-read ``Entry`` values, so no I/O happens here; the
    caller is the one reading the trail. Never raises: these payload bytes
    come off disk or off the wire, where the threat model says an attacker may
    have written them, and a scan that died on one hostile row would deny the
    caller every other row's evidence.
    """
    records: list[tuple[int, InterventionRecord]] = []
    unreadable: list[int] = []
    for entry in entries:
        if entry.header.payload_type != INTERVENTION_PAYLOAD_TYPE:
            continue
        if entry.payload is None:
            unreadable.append(entry.header.seq)
            continue
        try:
            record = from_payload(json.loads(entry.payload))
        except (ValueError, TypeError, UnicodeDecodeError):
            unreadable.append(entry.header.seq)
            continue
        records.append((entry.header.seq, record))
    return InterventionScan(records=tuple(records), unreadable=tuple(unreadable))
