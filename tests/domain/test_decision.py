"""Tests for the AI decision record schema (domain/decision.py).

The record is the evidence unit an auditor reads: which system, which model,
what it decided, on what committed input, under whose oversight. Two rules
from CLAUDE.md drive the shape of these tests:

- rule 5 (None != 0, unmeasured != absent): an optional field that was never
  measured is serialized as an explicit ``null``, so a reader can tell
  "nobody recorded oversight" from "this schema had no such field".
- unknown is never an error: an oversight mode or decision type this build
  has never seen is recorded verbatim, not rejected and not normalized.
"""

from __future__ import annotations

import json

import pytest

from waxseal.domain.decision import (
    DECISION_PAYLOAD_TYPE,
    DecisionRecord,
    HumanOversight,
    ModelRef,
    from_payload,
    to_payload,
)

HEX64 = "a" * 64


def minimal() -> DecisionRecord:
    return DecisionRecord(
        decision_id="d-1",
        decision_type="transaction_approval",
        system_id="aml-agent",
        model=ModelRef(name="risk-llm", version="2026.08"),
        input_commitment=HEX64,
        outcome="approve",
    )


class TestPayloadShape:
    def test_payload_type_names_the_schema_and_its_version(self) -> None:
        # A generic application/json would name neither producer nor schema
        # (the DSSE rule AuditLog.append already enforces).
        assert DECISION_PAYLOAD_TYPE == "application/vnd.waxseal.ai-decision.v1+json"

    def test_required_fields_round_trip(self) -> None:
        assert from_payload(to_payload(minimal())) == minimal()

    def test_every_field_round_trips_when_populated(self) -> None:
        record = DecisionRecord(
            decision_id="d-2",
            decision_type="aml_screening",
            system_id="aml-agent",
            model=ModelRef(name="risk-llm", version="2026.08", digest="b" * 64),
            input_commitment=HEX64,
            outcome="escalate",
            rationale="sanctions list near-match",
            policy_version="aml-policy-7",
            confidence=0.91,
            human_oversight=HumanOversight(
                mode="reviewed", reviewer_ref="analyst-42", action="confirmed"
            ),
            subject_ref="cust-pseudo-9f",
            trace_id="trace-abc",
        )
        assert from_payload(to_payload(record)) == record

    def test_unmeasured_optionals_serialize_as_explicit_null(self) -> None:
        # rule 5: absent and unmeasured must not look alike. An omitted key
        # would be indistinguishable from a schema that never had the field.
        payload = to_payload(minimal())
        for key in ("rationale", "policy_version", "confidence", "human_oversight",
                    "subject_ref", "trace_id"):
            assert key in payload, key
            assert payload[key] is None, key

    def test_model_digest_null_is_preserved_not_dropped(self) -> None:
        payload = to_payload(minimal())
        assert payload["model"] == {"name": "risk-llm", "version": "2026.08", "digest": None}

    def test_payload_is_json_serializable_with_plain_types(self) -> None:
        # AuditLog canonicalizes with json.dumps; a dataclass leaking through
        # would raise there instead of here, far from the cause.
        json.dumps(to_payload(minimal()))


class TestUnknownIsNotAnError:
    def test_unrecognized_decision_type_is_recorded_verbatim(self) -> None:
        record = DecisionRecord(
            decision_id="d-3",
            decision_type="some_future_workflow",
            system_id="s",
            model=ModelRef(name="m", version="v"),
            input_commitment=HEX64,
            outcome="deny",
        )
        assert to_payload(record)["decision_type"] == "some_future_workflow"

    def test_unrecognized_oversight_mode_is_recorded_verbatim(self) -> None:
        record = DecisionRecord(
            decision_id="d-4",
            decision_type="t",
            system_id="s",
            model=ModelRef(name="m", version="v"),
            input_commitment=HEX64,
            outcome="approve",
            human_oversight=HumanOversight(mode="four_eyes_committee"),
        )
        assert to_payload(record)["human_oversight"]["mode"] == "four_eyes_committee"


class TestValidation:
    # An audit record that commits to nothing is worse than no record at all:
    # it looks like evidence and proves nothing. These reject at write time,
    # where the caller can still fix it, rather than at audit time.

    @pytest.mark.parametrize(
        "field", ["decision_id", "decision_type", "system_id", "outcome"]
    )
    def test_empty_required_string_is_rejected(self, field: str) -> None:
        kwargs = {
            "decision_id": "d",
            "decision_type": "t",
            "system_id": "s",
            "model": ModelRef(name="m", version="v"),
            "input_commitment": HEX64,
            "outcome": "approve",
            field: "",
        }
        with pytest.raises(ValueError, match=field):
            DecisionRecord(**kwargs)  # type: ignore[arg-type]

    def test_empty_model_name_or_version_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="name"):
            ModelRef(name="", version="v")
        with pytest.raises(ValueError, match="version"):
            ModelRef(name="m", version="")

    def test_empty_oversight_mode_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="mode"):
            HumanOversight(mode="")

    @pytest.mark.parametrize(
        "bad", ["", "abc", "A" * 64, "g" * 64, HEX64 + "a", " " + "a" * 63]
    )
    def test_input_commitment_must_be_64_lowercase_hex(self, bad: str) -> None:
        with pytest.raises(ValueError, match="input_commitment"):
            DecisionRecord(
                decision_id="d",
                decision_type="t",
                system_id="s",
                model=ModelRef(name="m", version="v"),
                input_commitment=bad,
                outcome="approve",
            )

    @pytest.mark.parametrize("bad", ["", "xyz", "A" * 64, "b" * 63])
    def test_model_digest_when_present_must_be_64_lowercase_hex(self, bad: str) -> None:
        with pytest.raises(ValueError, match="digest"):
            ModelRef(name="m", version="v", digest=bad)

    @pytest.mark.parametrize("bad", [-0.01, 1.01, float("nan"), float("inf")])
    def test_confidence_outside_zero_to_one_is_rejected(self, bad: float) -> None:
        # NaN/inf are rejected too: json.dumps emits them as bare NaN/Infinity,
        # which is not valid JSON, so the payload would be unreadable by any
        # conforming auditor tool while still hashing fine.
        with pytest.raises(ValueError, match="confidence"):
            DecisionRecord(
                decision_id="d",
                decision_type="t",
                system_id="s",
                model=ModelRef(name="m", version="v"),
                input_commitment=HEX64,
                outcome="approve",
                confidence=bad,
            )

    def test_confidence_at_the_bounds_is_accepted(self) -> None:
        for value in (0.0, 1.0):
            record = DecisionRecord(
                decision_id="d",
                decision_type="t",
                system_id="s",
                model=ModelRef(name="m", version="v"),
                input_commitment=HEX64,
                outcome="approve",
                confidence=value,
            )
            assert record.confidence == value

    @pytest.mark.parametrize(
        "field", ["rationale", "policy_version", "subject_ref", "trace_id"]
    )
    def test_optional_string_fields_reject_non_strings(self, field: str) -> None:
        # These land verbatim in the hashed payload; a stray object would
        # either break json.dumps at append time or serialize into something
        # nobody intended to commit to.
        with pytest.raises(ValueError, match=field):
            DecisionRecord(
                decision_id="d",
                decision_type="t",
                system_id="s",
                model=ModelRef(name="m", version="v"),
                input_commitment=HEX64,
                outcome="approve",
                **{field: {"nested": "object"}},  # type: ignore[arg-type]
            )

    def test_reviewer_ref_and_action_reject_non_strings(self) -> None:
        with pytest.raises(ValueError, match="reviewer_ref"):
            HumanOversight(mode="reviewed", reviewer_ref=42)  # type: ignore[arg-type]
        with pytest.raises(ValueError, match="action"):
            HumanOversight(mode="reviewed", action=["confirmed"])  # type: ignore[arg-type]

    def test_model_must_be_a_modelref_not_a_bare_string(self) -> None:
        with pytest.raises(ValueError, match="model"):
            DecisionRecord(
                decision_id="d",
                decision_type="t",
                system_id="s",
                model="risk-llm",  # type: ignore[arg-type]
                input_commitment=HEX64,
                outcome="approve",
            )

    def test_human_oversight_must_be_the_dataclass_not_a_dict(self) -> None:
        with pytest.raises(ValueError, match="human_oversight"):
            DecisionRecord(
                decision_id="d",
                decision_type="t",
                system_id="s",
                model=ModelRef(name="m", version="v"),
                input_commitment=HEX64,
                outcome="approve",
                human_oversight={"mode": "reviewed"},  # type: ignore[arg-type]
            )

    @pytest.mark.parametrize("bad", [True, False, "high", None.__class__])
    def test_non_numeric_confidence_is_rejected_at_construction(self, bad: object) -> None:
        # bool first: it is an int subclass, so True would otherwise be
        # silently recorded as a confidence of 1.0.
        with pytest.raises(ValueError, match="confidence"):
            DecisionRecord(
                decision_id="d",
                decision_type="t",
                system_id="s",
                model=ModelRef(name="m", version="v"),
                input_commitment=HEX64,
                outcome="approve",
                confidence=bad,  # type: ignore[arg-type]
            )

    def test_record_is_immutable(self) -> None:
        with pytest.raises(Exception):  # noqa: B017 - FrozenInstanceError
            minimal().outcome = "deny"  # type: ignore[misc]


class TestFromPayloadRejectsMalformed:
    # from_payload parses attacker-reachable bytes off the trail. It raises a
    # single, catchable ValueError so a caller (report, iter_decisions) can
    # label the row malformed instead of dying mid-audit.

    @pytest.mark.parametrize(
        "payload",
        [
            {},
            {"decision_id": "d"},
            "not a dict",
            [1, 2, 3],
            None,
            {**{k: v for k, v in to_payload(minimal()).items() if k != "model"}},
        ],
    )
    def test_structurally_wrong_payload_raises_valueerror(self, payload: object) -> None:
        with pytest.raises(ValueError):
            from_payload(payload)  # type: ignore[arg-type]

    def test_model_of_the_wrong_type_raises_valueerror(self) -> None:
        payload = to_payload(minimal())
        payload["model"] = "risk-llm"
        with pytest.raises(ValueError):
            from_payload(payload)

    def test_human_oversight_of_the_wrong_type_raises_valueerror(self) -> None:
        payload = to_payload(minimal())
        payload["human_oversight"] = "reviewed"
        with pytest.raises(ValueError):
            from_payload(payload)

    def test_non_string_required_field_raises_valueerror(self) -> None:
        payload = to_payload(minimal())
        payload["decision_id"] = 7
        with pytest.raises(ValueError):
            from_payload(payload)

    def test_non_numeric_confidence_raises_valueerror(self) -> None:
        payload = to_payload(minimal())
        payload["confidence"] = "high"
        with pytest.raises(ValueError):
            from_payload(payload)

    def test_bool_confidence_is_rejected(self) -> None:
        # bool is an int subclass in Python; True would silently become 1.0.
        payload = to_payload(minimal())
        payload["confidence"] = True
        with pytest.raises(ValueError):
            from_payload(payload)

    def test_integer_confidence_is_accepted_as_float(self) -> None:
        payload = to_payload(minimal())
        payload["confidence"] = 1
        assert from_payload(payload).confidence == 1.0

    def test_unknown_extra_keys_are_ignored_not_rejected(self) -> None:
        # A newer writer's field must not make an older reader call the row
        # broken (the beads-v1.2.2 failure class, applied to the payload).
        payload = to_payload(minimal())
        payload["future_field"] = {"anything": True}
        assert from_payload(payload) == minimal()
