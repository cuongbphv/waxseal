"""AI decision record schema (pure; no I/O).

An agent's tool calls say what the machine *did*. A regulated institution is
asked a different question: on what basis was this particular decision about
this particular customer made, by which model, under whose oversight. That is
the evidence unit this module defines: a payload schema carried by the
existing envelope, so the chain, the fingerprint registry, and every backend
stay untouched (CLAUDE.md: changing payload schema never touches the chain).

Two rules shape the serialization:

- **Unmeasured is not absent.** Optional fields serialize as explicit
  ``null`` rather than being omitted. An omitted key cannot be told apart
  from a schema that never had the field, and "nobody recorded who reviewed
  this" is exactly the fact an auditor needs to be able to read (rule 5).
- **Unknown is not an error.** ``decision_type`` and ``human_oversight.mode``
  are free strings recorded verbatim. A vocabulary this build has not seen is
  a newer writer, not a bad row, and rejecting it here would recreate the
  beads-v1.2.2 failure class one layer down.

What is validated is only what makes a record *evidence at all*: the
identifiers are non-empty and ``input_commitment`` is a real digest. A record
that commits to nothing is worse than no record: it looks like proof and is
not.

Two later fields, ``risk_tier`` and ``classification_ref``, were appended as
optional keys without moving ``DECISION_PAYLOAD_TYPE`` off ``.v1``. That
leaves one subtlety worth stating: a row written before the fields existed has
the key *absent*, while a writer that had the field and declared nothing
writes the key *present and null*, and both parse to ``None`` here. For the
question an auditor asks — was a tier declared for this decision? — the two
have the same answer, so both count as undeclared and there is no third
counter.

``input_commitment`` is a hash of the (already redacted) model input, not the
input itself, so the trail carries no customer data. Note the standard limit
of any hash commitment: over a low-entropy input (an account number, a small
enum) it is a *confirmable* commitment, since someone who can guess the input can
check the guess. Commit to a redacted or salted form when that matters.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Any, Final

DECISION_PAYLOAD_TYPE: Final = "application/vnd.waxseal.ai-decision.v1+json"

_SHA256_HEX: Final = re.compile(r"\A[0-9a-f]{64}\Z")


def _require_nonempty(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _require_digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _SHA256_HEX.match(value):
        raise ValueError(f"{field} must be 64 lowercase hex characters (a SHA-256 digest)")
    return value


def _optional_str(value: Any, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string or null")
    return value


@dataclass(frozen=True, slots=True)
class ModelRef:
    """Which model produced the decision. ``digest`` pins the exact weights or
    artifact when the deployer can compute one; ``None`` means unpinned, which
    is a weaker claim and is recorded as such rather than guessed."""

    name: str
    version: str
    digest: str | None = None

    def __post_init__(self) -> None:
        _require_nonempty(self.name, "name")
        _require_nonempty(self.version, "version")
        if self.digest is not None:
            _require_digest(self.digest, "digest")


@dataclass(frozen=True, slots=True)
class HumanOversight:
    """Who, if anyone, stood between the model and the outcome.

    ``mode`` is deliberately an open string: institutions name their controls
    differently and a closed enum would force a lossy mapping. The whole
    object being ``None`` on a record means oversight was never recorded,
    which is not the same claim as ``mode="automated"`` (oversight was
    recorded, and there was none).

    ``reviewer_ref`` must be a pseudonymous reference (a staff id, a queue
    handle), never a person's name or contact details: the trail is designed
    to be shared with auditors and cannot be selectively unredacted later.
    """

    mode: str
    reviewer_ref: str | None = None
    action: str | None = None

    def __post_init__(self) -> None:
        _require_nonempty(self.mode, "mode")
        _optional_str(self.reviewer_ref, "reviewer_ref")
        _optional_str(self.action, "action")


@dataclass(frozen=True, slots=True)
class DecisionRecord:
    decision_id: str
    decision_type: str
    system_id: str
    model: ModelRef
    input_commitment: str
    outcome: str
    rationale: str | None = None
    policy_version: str | None = None
    confidence: float | None = None
    human_oversight: HumanOversight | None = None
    # Pseudonymous handle for the affected party. Never a name, account
    # number, or anything else that identifies them directly: see the
    # reviewer_ref note above.
    subject_ref: str | None = None
    trace_id: str | None = None
    # The provider's OWN risk classification, which Law on AI No. 134/2025/QH15
    # Điều 10(1) assigns to the provider, not to a verifier. Recorded verbatim
    # and never adjudicated here: a free string for the same reason
    # HumanOversight.mode is one — institutions name their own tiers ("cao",
    # "high", "tier-2", "trung bình") and a closed enum forces a lossy mapping.
    # Normalizing "cao" to "high" would be waxseal deciding a classification
    # the law does not give it. None means no tier was declared on this record,
    # which is a different claim from any tier and must never render as the
    # lowest one (rule 5).
    risk_tier: str | None = None
    # Opaque, pseudonymous pointer to the risk-classification dossier that
    # Decree 142/2026/NĐ-CP Điều 12 requires providers of high- and
    # medium-risk systems to keep for the system's whole operating life: a
    # dossier id and version, never a filesystem path with a person's name in
    # it (the subject_ref note above applies here too). None means no dossier
    # reference was recorded.
    classification_ref: str | None = None

    def __post_init__(self) -> None:
        _require_nonempty(self.decision_id, "decision_id")
        _require_nonempty(self.decision_type, "decision_type")
        _require_nonempty(self.system_id, "system_id")
        _require_digest(self.input_commitment, "input_commitment")
        _require_nonempty(self.outcome, "outcome")
        if not isinstance(self.model, ModelRef):
            raise ValueError("model must be a ModelRef")
        if self.human_oversight is not None and not isinstance(
            self.human_oversight, HumanOversight
        ):
            raise ValueError("human_oversight must be a HumanOversight or None")
        for field in (
            "rationale",
            "policy_version",
            "subject_ref",
            "trace_id",
            # No special empty-string rule: the analogue is rationale and
            # policy_version, which accept "". _require_nonempty is for a
            # field that is mandatory once its object exists.
            "risk_tier",
            "classification_ref",
        ):
            _optional_str(getattr(self, field), field)
        if self.confidence is not None:
            # NaN/inf are rejected rather than stored: json.dumps writes them
            # as bare NaN/Infinity, which is not JSON, so the payload would
            # hash perfectly well and be unreadable to any conforming auditor
            # tool, which is a silently useless record.
            if isinstance(self.confidence, bool) or not isinstance(self.confidence, (int, float)):
                raise ValueError("confidence must be a number between 0 and 1, or null")
            if not math.isfinite(self.confidence) or not 0.0 <= self.confidence <= 1.0:
                raise ValueError("confidence must be a number between 0 and 1, or null")


def to_payload(record: DecisionRecord) -> dict[str, Any]:
    """Plain-JSON dict for ``AuditLog.append``.

    Built by hand rather than ``dataclasses.asdict`` so the on-disk shape is
    owned here: a field added to the dataclass for internal use cannot leak
    into the hashed payload without someone editing this function.
    """
    oversight = record.human_oversight
    return {
        "decision_id": record.decision_id,
        "decision_type": record.decision_type,
        "system_id": record.system_id,
        "model": {
            "name": record.model.name,
            "version": record.model.version,
            "digest": record.model.digest,
        },
        "input_commitment": record.input_commitment,
        "outcome": record.outcome,
        "rationale": record.rationale,
        "policy_version": record.policy_version,
        "confidence": record.confidence,
        "human_oversight": (
            None
            if oversight is None
            else {
                "mode": oversight.mode,
                "reviewer_ref": oversight.reviewer_ref,
                "action": oversight.action,
            }
        ),
        "subject_ref": record.subject_ref,
        "trace_id": record.trace_id,
        # Appended without moving DECISION_PAYLOAD_TYPE off .v1. The media
        # type's version is for a change an old reader cannot tolerate — a new
        # required field, a changed meaning, a removal — and an optional key
        # defaulting to None is none of those: the chain hashes only the
        # header, an old payload read by this build yields None through
        # .get(), and this build's extra keys are ignored by an older reader
        # (test_unknown_extra_keys_are_ignored_not_rejected). Same call as
        # AnchorRecord.nonce in adapters/anchors.py, added as None = "not
        # recorded" with no format break, for the beads-v1.2.2 reason.
        "risk_tier": record.risk_tier,
        "classification_ref": record.classification_ref,
    }


def from_payload(payload: Any) -> DecisionRecord:
    """Parse a decision payload read back off the trail.

    Raises ``ValueError``, and only ``ValueError``, on anything malformed,
    so a caller auditing a whole trail can label one row unparseable and keep
    going. Unparseable is a third verdict, distinct from intact and from
    tampered: the chain check has its own answer about those bytes and this
    function must not pre-empt it.

    Keys this version does not know are ignored, not rejected: a newer writer
    must never make an older reader call the row broken.
    """
    if not isinstance(payload, dict):
        raise ValueError("decision payload must be a JSON object")
    model = payload.get("model")
    if not isinstance(model, dict):
        raise ValueError("decision payload is missing a model object")
    oversight_raw = payload.get("human_oversight")
    if oversight_raw is not None and not isinstance(oversight_raw, dict):
        raise ValueError("human_oversight must be an object or null")
    confidence = payload.get("confidence")
    if confidence is not None:
        if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
            raise ValueError("confidence must be a number or null")
        confidence = float(confidence)
    # Every remaining shape error surfaces from the dataclasses' own
    # __post_init__ validation, which already raises ValueError.
    return DecisionRecord(
        decision_id=payload.get("decision_id"),  # type: ignore[arg-type]
        decision_type=payload.get("decision_type"),  # type: ignore[arg-type]
        system_id=payload.get("system_id"),  # type: ignore[arg-type]
        model=ModelRef(
            name=model.get("name"),  # type: ignore[arg-type]
            version=model.get("version"),  # type: ignore[arg-type]
            digest=model.get("digest"),
        ),
        input_commitment=payload.get("input_commitment"),  # type: ignore[arg-type]
        outcome=payload.get("outcome"),  # type: ignore[arg-type]
        rationale=payload.get("rationale"),
        policy_version=payload.get("policy_version"),
        confidence=confidence,
        human_oversight=(
            None
            if oversight_raw is None
            else HumanOversight(
                mode=oversight_raw.get("mode"),  # type: ignore[arg-type]
                reviewer_ref=oversight_raw.get("reviewer_ref"),
                action=oversight_raw.get("action"),
            )
        ),
        subject_ref=payload.get("subject_ref"),
        trace_id=payload.get("trace_id"),
        risk_tier=payload.get("risk_tier"),
        classification_ref=payload.get("classification_ref"),
    )
