"""Tests for S3 Object Lock (WORM) retention on sealed segments — J1.

The fake client extends ``tests/adapters/test_s3.py``'s ``FakeS3Client``
rather than introducing a second mocking style: the Object Lock surface is
three more methods on the same object, not a different kind of double.

The headline property under test is the ternary: ``worm_unknown`` must never
be reported as ``worm_locked``. Every "could not tell" path — no permission
to ask, a 200 that does not answer, an unrecognized retention mode, the
``s3`` extra absent — is asserted to land on UNKNOWN, and the whole
``WormState`` surface is swept for the one string that would be a lie.
"""

import base64
import hashlib
import sys
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from tests.adapters.test_s3 import FakeClientError, FakeS3Client
from waxseal.adapters.s3 import (
    _STORAGE_REFUSAL_PROMISE,
    _WORM_LABEL,
    RETENTION_MODE_STRENGTH,
    RETENTION_MODES,
    SegmentUpload,
    WormReport,
    WormRetention,
    WormState,
    WormStrength,
    WormSubject,
    bucket_worm_state,
    object_worm_state,
    render_worm_state,
    upload_sealed_segment,
)

NOW = datetime(2026, 8, 31, 12, 0, 0, tzinfo=UTC)
FUTURE = NOW + timedelta(days=365)
PAST = NOW - timedelta(days=1)


def now_fn() -> datetime:
    return NOW


class FakeWormS3Client(FakeS3Client):
    """``FakeS3Client`` plus the three Object Lock read/write surfaces.

    ``retention``/``lock_config`` are set by the test to whatever the real
    API would answer; an ``Exception`` value is raised instead of returned,
    which is how the no-permission and no-configuration paths are driven.
    """

    def __init__(
        self,
        *,
        retention: Any = None,
        lock_config: Any = None,
    ) -> None:
        super().__init__()
        self.retention = retention
        self.lock_config = lock_config
        self.put_kwargs: dict[str, Any] = {}

    def put_object(self, *, Bucket: str, Key: str, Body: bytes, **kwargs: Any) -> dict[str, Any]:
        self.put_kwargs = dict(kwargs)
        return super().put_object(Bucket=Bucket, Key=Key, Body=Body, **kwargs)

    def get_object_retention(self, **kwargs: Any) -> Any:
        if isinstance(self.retention, Exception):
            raise self.retention
        return self.retention

    def get_object_lock_configuration(self, **kwargs: Any) -> Any:
        if isinstance(self.lock_config, Exception):
            raise self.lock_config
        return self.lock_config


def retained(mode: str = "COMPLIANCE", until: datetime = FUTURE) -> dict[str, Any]:
    return {"Retention": {"Mode": mode, "RetainUntilDate": until}}


COMPLIANCE = WormRetention(mode="COMPLIANCE", retain_until=FUTURE)


class TestWormRetentionIsOperatorDeclared:
    """No default policy and no default trust anchor — same discipline as
    ``--tsa-ca-file``. An operator who did not name a mode and a date does
    not get one guessed for them."""

    def test_both_documented_modes_are_accepted(self) -> None:
        for mode in ("GOVERNANCE", "COMPLIANCE"):
            assert WormRetention(mode=mode, retain_until=FUTURE).mode == mode

    def test_the_mode_allowlist_is_exactly_the_two_documented_modes(self) -> None:
        assert sorted(RETENTION_MODES) == ["COMPLIANCE", "GOVERNANCE"]

    def test_an_unknown_mode_is_refused_rather_than_sent_to_s3(self) -> None:
        with pytest.raises(ValueError, match="retention mode"):
            WormRetention(mode="WORM", retain_until=FUTURE)

    def test_a_lowercase_mode_is_refused_rather_than_normalized(self) -> None:
        # Guessing the operator meant COMPLIANCE is inventing policy. S3's
        # enum is uppercase; anything else is the caller's bug to see.
        with pytest.raises(ValueError, match="retention mode"):
            WormRetention(mode="compliance", retain_until=FUTURE)

    def test_a_naive_retain_until_is_refused(self) -> None:
        # A retention date whose zone is a guess is worse than no retention:
        # it silently locks for the wrong span.
        with pytest.raises(ValueError, match="timezone-aware"):
            WormRetention(mode="COMPLIANCE", retain_until=datetime(2027, 1, 1))  # noqa: DTZ001

    def test_a_non_datetime_retain_until_is_refused(self) -> None:
        # put_object's ObjectLockRetainUntilDate is a datetime; a string here
        # would only fail at the AWS boundary, far from the caller.
        with pytest.raises(ValueError, match="datetime"):
            WormRetention(mode="COMPLIANCE", retain_until="2027-01-01")  # type: ignore[arg-type]


class TestUploadSetsRetention:
    def test_retention_is_sent_with_the_documented_parameter_names(self) -> None:
        client = FakeWormS3Client(retention=retained())
        result = upload_sealed_segment(
            client,
            bucket="audit",
            key="seg/0.jsonl",
            body=b"x",
            retention=COMPLIANCE,
            now_fn=now_fn,
        )
        assert result.uploaded is True
        assert client.put_kwargs["ObjectLockMode"] == "COMPLIANCE"
        assert client.put_kwargs["ObjectLockRetainUntilDate"] == FUTURE

    def test_a_content_md5_accompanies_a_retention_put(self) -> None:
        # boto3 put_object: "The Content-MD5 or x-amz-sdk-checksum-algorithm
        # header is required for any request to upload an object with a
        # retention period configured using Amazon S3 Object Lock."
        client = FakeWormS3Client(retention=retained())
        upload_sealed_segment(
            client,
            bucket="audit",
            key="seg/0.jsonl",
            body=b"x",
            retention=COMPLIANCE,
            now_fn=now_fn,
        )
        assert client.put_kwargs["ContentMD5"] == base64.b64encode(
            hashlib.md5(b"x", usedforsecurity=False).digest()
        ).decode()

    def test_no_retention_asked_for_sends_no_lock_parameters(self) -> None:
        client = FakeWormS3Client(retention=FakeClientError("NoSuchObjectLockConfiguration"))
        upload_sealed_segment(client, bucket="audit", key="seg/0.jsonl", body=b"x", now_fn=now_fn)
        assert "ObjectLockMode" not in client.put_kwargs
        assert "ContentMD5" not in client.put_kwargs

    def test_the_segment_body_is_actually_stored(self) -> None:
        client = FakeWormS3Client(retention=retained())
        upload_sealed_segment(
            client,
            bucket="audit",
            key="seg/0.jsonl",
            body=b"seg",
            retention=COMPLIANCE,
            now_fn=now_fn,
        )
        assert client.get_object(Bucket="audit", Key="seg/0.jsonl")["Body"].read() == b"seg"

    def test_a_failed_put_propagates_rather_than_reporting_a_worm_state(self) -> None:
        # Nothing was uploaded, so there is no object whose WORM state could
        # be reported at all: inventing one would be the lie rule 5 forbids.
        client = FakeWormS3Client(retention=retained())

        def put_object(**kwargs: Any) -> dict[str, Any]:
            raise FakeClientError("AccessDenied")

        client.put_object = put_object  # type: ignore[method-assign]
        with pytest.raises(FakeClientError, match="AccessDenied"):
            upload_sealed_segment(
                client, bucket="audit", key="seg/0.jsonl", body=b"x", retention=COMPLIANCE
            )


class TestWormLocked:
    """The ONE path that may report LOCKED: asked, answered, allowlisted
    mode, and a retain-until still in the future."""

    def test_a_compliance_retention_in_the_future_is_locked(self) -> None:
        report = object_worm_state(
            FakeWormS3Client(retention=retained("COMPLIANCE")),
            bucket="audit",
            key="k",
            now_fn=now_fn,
        )
        assert report.state is WormState.LOCKED
        assert "COMPLIANCE" in report.detail

    def test_a_governance_retention_in_the_future_is_locked(self) -> None:
        report = object_worm_state(
            FakeWormS3Client(retention=retained("GOVERNANCE")),
            bucket="audit",
            key="k",
            now_fn=now_fn,
        )
        assert report.state is WormState.LOCKED

    def test_upload_reports_locked_when_the_object_comes_back_retained(self) -> None:
        result = upload_sealed_segment(
            FakeWormS3Client(retention=retained()),
            bucket="audit",
            key="k",
            body=b"x",
            retention=COMPLIANCE,
            now_fn=now_fn,
        )
        assert result.worm.state is WormState.LOCKED

    def test_a_version_id_is_passed_through_when_given(self) -> None:
        # Object Lock protects an object VERSION; asking about the wrong
        # version answers a different question than the one asked.
        seen: dict[str, Any] = {}
        client = FakeWormS3Client(retention=retained())

        def get_object_retention(**kwargs: Any) -> Any:
            seen.update(kwargs)
            return retained()

        client.get_object_retention = get_object_retention  # type: ignore[method-assign]
        object_worm_state(client, bucket="audit", key="k", version_id="v1", now_fn=now_fn)
        assert seen["VersionId"] == "v1"


class TestWormUnlocked:
    """Asked, and the answer was a definite no. A definite no is a label,
    never a failure and never silence."""

    def test_a_bucket_without_object_lock_is_a_definite_no(self) -> None:
        report = object_worm_state(
            FakeWormS3Client(retention=FakeClientError("NoSuchObjectLockConfiguration")),
            bucket="audit",
            key="k",
            now_fn=now_fn,
        )
        assert report.state is WormState.UNLOCKED

    def test_an_expired_retention_is_a_definite_no(self) -> None:
        # The retention period ran out: storage will accept an overwrite
        # again, so the WORM claim has genuinely lapsed.
        report = object_worm_state(
            FakeWormS3Client(retention=retained("COMPLIANCE", PAST)),
            bucket="audit",
            key="k",
            now_fn=now_fn,
        )
        assert report.state is WormState.UNLOCKED
        assert "expired" in report.detail

    def test_a_retain_until_exactly_now_is_no_longer_retained(self) -> None:
        report = object_worm_state(
            FakeWormS3Client(retention=retained("COMPLIANCE", NOW)),
            bucket="audit",
            key="k",
            now_fn=now_fn,
        )
        assert report.state is WormState.UNLOCKED

    def test_every_not_configured_code_in_the_allowlist_reads_as_unlocked(self) -> None:
        for code in ("NoSuchObjectLockConfiguration", "ObjectLockConfigurationNotFoundError"):
            report = object_worm_state(
                FakeWormS3Client(retention=FakeClientError(code)),
                bucket="audit",
                key="k",
                now_fn=now_fn,
            )
            assert report.state is WormState.UNLOCKED, code


class TestWormUnknown:
    """Every path that could not answer. None of them may read as locked,
    and none of them may read as unlocked either — a false alarm and false
    confidence are both the collapse CLAUDE.md rule 5 forbids."""

    def test_no_permission_to_ask_is_unknown_not_unlocked(self) -> None:
        report = object_worm_state(
            FakeWormS3Client(retention=FakeClientError("AccessDenied")),
            bucket="audit",
            key="k",
            now_fn=now_fn,
        )
        assert report.state is WormState.UNKNOWN
        assert "AccessDenied" in report.detail

    def test_a_403_by_status_code_is_unknown(self) -> None:
        report = object_worm_state(
            FakeWormS3Client(retention=FakeClientError("403")),
            bucket="audit",
            key="k",
            now_fn=now_fn,
        )
        assert report.state is WormState.UNKNOWN

    def test_a_200_that_omits_retention_is_unknown(self) -> None:
        # GetObjectRetention documents Retention as required in a 200. A 200
        # without it did not answer the question.
        report = object_worm_state(
            FakeWormS3Client(retention={}), bucket="audit", key="k", now_fn=now_fn
        )
        assert report.state is WormState.UNKNOWN

    def test_an_unrecognized_retention_mode_is_unknown(self) -> None:
        # An allowlist, not "!= something bad": a mode this build has never
        # heard of cannot be recomputed into a guarantee (the unknown
        # fingerprint rule, applied to storage).
        report = object_worm_state(
            FakeWormS3Client(retention=retained("FUTUREMODE")),
            bucket="audit",
            key="k",
            now_fn=now_fn,
        )
        assert report.state is WormState.UNKNOWN
        assert "FUTUREMODE" in report.detail

    def test_a_missing_retain_until_date_is_unknown(self) -> None:
        report = object_worm_state(
            FakeWormS3Client(retention={"Retention": {"Mode": "COMPLIANCE"}}),
            bucket="audit",
            key="k",
            now_fn=now_fn,
        )
        assert report.state is WormState.UNKNOWN

    def test_a_non_datetime_retain_until_date_is_unknown(self) -> None:
        report = object_worm_state(
            FakeWormS3Client(
                retention={"Retention": {"Mode": "COMPLIANCE", "RetainUntilDate": "?"}}
            ),
            bucket="audit",
            key="k",
            now_fn=now_fn,
        )
        assert report.state is WormState.UNKNOWN

    def test_a_naive_retain_until_date_from_the_wire_is_unknown(self) -> None:
        # Comparing a naive datetime against an aware "now" raises; guessing
        # its zone would turn an unanswerable question into a verdict.
        report = object_worm_state(
            FakeWormS3Client(retention=retained("COMPLIANCE", datetime(2027, 1, 1))),  # noqa: DTZ001
            bucket="audit",
            key="k",
            now_fn=now_fn,
        )
        assert report.state is WormState.UNKNOWN

    def test_a_retention_reply_that_is_not_a_mapping_is_unknown(self) -> None:
        report = object_worm_state(
            FakeWormS3Client(retention={"Retention": "locked"}),
            bucket="audit",
            key="k",
            now_fn=now_fn,
        )
        assert report.state is WormState.UNKNOWN

    def test_a_reply_that_is_not_a_mapping_at_all_is_unknown(self) -> None:
        report = object_worm_state(
            FakeWormS3Client(retention="fine"), bucket="audit", key="k", now_fn=now_fn
        )
        assert report.state is WormState.UNKNOWN

    def test_an_exception_with_no_error_payload_is_unknown_not_a_crash(self) -> None:
        report = object_worm_state(
            FakeWormS3Client(retention=RuntimeError("socket closed")),
            bucket="audit",
            key="k",
            now_fn=now_fn,
        )
        assert report.state is WormState.UNKNOWN
        assert "socket closed" in report.detail

    def test_a_client_without_the_object_lock_api_is_unknown(self) -> None:
        # An injected client from an older SDK or an S3-compatible service
        # may simply not have the method. That is "could not ask".
        report = object_worm_state(
            FakeS3Client(), bucket="audit", key="k", now_fn=now_fn
        )
        assert report.state is WormState.UNKNOWN
        assert "get_object_retention" in report.detail

    def test_the_default_now_fn_needs_no_injection(self) -> None:
        # Rule 8: injectable, not mandatory. The real clock puts FUTURE in
        # the future for any plausible run date, so this stays deterministic.
        report = object_worm_state(
            FakeWormS3Client(retention=retained()), bucket="audit", key="k"
        )
        assert report.state is WormState.LOCKED


class TestExtraAbsentIsItsOwnLabelledState:
    """boto3 lives in the ``s3`` extra (CLAUDE.md rule 1). Its absence is a
    deployment condition, so the question was never asked — UNKNOWN, with a
    label (rule 6), never a crash and never a silent skip."""

    def test_a_missing_s3_extra_reports_unknown_and_uploads_nothing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setitem(sys.modules, "boto3", None)
        result = upload_sealed_segment(
            None, bucket="audit", key="k", body=b"x", retention=COMPLIANCE, now_fn=now_fn
        )
        assert result.uploaded is False
        assert result.worm.state is WormState.UNKNOWN
        assert "s3" in result.worm.detail and "boto3" in result.worm.detail

    def test_a_missing_s3_extra_does_not_raise_importerror(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setitem(sys.modules, "boto3", None)
        upload_sealed_segment(None, bucket="audit", key="k", body=b"x", now_fn=now_fn)

    def test_an_installed_s3_extra_builds_the_default_client(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        built = FakeWormS3Client(retention=retained())

        class FakeBoto3:
            def client(self, name: str) -> Any:
                assert name == "s3"
                return built

        monkeypatch.setitem(sys.modules, "boto3", FakeBoto3())
        result = upload_sealed_segment(
            None, bucket="audit", key="k", body=b"x", retention=COMPLIANCE, now_fn=now_fn
        )
        assert result.uploaded is True
        assert result.worm.state is WormState.LOCKED
        assert built.get_object(Bucket="audit", Key="k")["Body"].read() == b"x"


class TestBucketWormState:
    """"Is Object Lock configured on this bucket" is a DIFFERENT question
    from "is this object version retained" — J4's preflight asks the former
    to name the mechanism, and it gets its own ternary rather than being
    folded into the object answer."""

    def test_an_enabled_compliance_bucket_is_locked(self) -> None:
        client = FakeWormS3Client(
            lock_config={
                "ObjectLockConfiguration": {
                    "ObjectLockEnabled": "Enabled",
                    "Rule": {"DefaultRetention": {"Mode": "COMPLIANCE", "Days": 3650}},
                }
            }
        )
        report = bucket_worm_state(client, bucket="audit")
        assert report.state is WormState.LOCKED
        assert "COMPLIANCE" in report.detail

    def test_an_enabled_bucket_without_a_default_rule_is_still_locked(self) -> None:
        # Object Lock is on; per-object retention (what upload sets) is the
        # mechanism. No default rule is not "no lock".
        report = bucket_worm_state(
            FakeWormS3Client(
                lock_config={"ObjectLockConfiguration": {"ObjectLockEnabled": "Enabled"}}
            ),
            bucket="audit",
        )
        assert report.state is WormState.LOCKED

    def test_a_bucket_with_no_lock_configuration_is_a_definite_no(self) -> None:
        report = bucket_worm_state(
            FakeWormS3Client(lock_config=FakeClientError("ObjectLockConfigurationNotFoundError")),
            bucket="audit",
        )
        assert report.state is WormState.UNLOCKED

    def test_no_permission_to_ask_the_bucket_is_unknown(self) -> None:
        report = bucket_worm_state(
            FakeWormS3Client(lock_config=FakeClientError("AccessDenied")), bucket="audit"
        )
        assert report.state is WormState.UNKNOWN

    def test_an_unrecognized_enabled_value_is_unknown(self) -> None:
        # Valid Values documents exactly one: "Enabled". Anything else is a
        # reply this build cannot interpret.
        report = bucket_worm_state(
            FakeWormS3Client(
                lock_config={"ObjectLockConfiguration": {"ObjectLockEnabled": "Suspended"}}
            ),
            bucket="audit",
        )
        assert report.state is WormState.UNKNOWN

    def test_a_200_that_omits_the_configuration_is_unknown(self) -> None:
        report = bucket_worm_state(FakeWormS3Client(lock_config={}), bucket="audit")
        assert report.state is WormState.UNKNOWN

    def test_a_configuration_that_is_not_a_mapping_is_unknown(self) -> None:
        report = bucket_worm_state(
            FakeWormS3Client(lock_config={"ObjectLockConfiguration": "Enabled"}), bucket="audit"
        )
        assert report.state is WormState.UNKNOWN

    def test_a_client_without_the_bucket_lock_api_is_unknown(self) -> None:
        report = bucket_worm_state(FakeS3Client(), bucket="audit")
        assert report.state is WormState.UNKNOWN
        assert "get_object_lock_configuration" in report.detail


ALL_TRIPLES = [
    (subject, state, strength)
    for subject in WormSubject
    for state in WormState
    for strength in WormStrength
]


def finding(
    subject: WormSubject,
    state: WormState,
    strength: WormStrength,
    detail: str = "d",
) -> WormReport | None:
    """The report for this triple, or ``None`` when it is not representable.

    ``WormReport`` refuses a strength on anything but an in-force retention, so
    the renderable surface is discovered here rather than listed by hand: a new
    state or a new strength shows up in these sweeps without anyone
    remembering to add it.
    """
    try:
        return WormReport(subject=subject, state=state, strength=strength, detail=detail)
    except ValueError:
        return None


REPRESENTABLE = [triple for triple in ALL_TRIPLES if finding(*triple) is not None]


class TestReportRefusesIncoherentFindings:
    """A strength belongs to a retention that is in force. Anything else would
    let a finding that established nothing carry the strong claim."""

    def test_only_a_locked_finding_may_carry_a_strength(self) -> None:
        for subject, state, strength in ALL_TRIPLES:
            report = finding(subject, state, strength)
            if state is WormState.LOCKED or strength is WormStrength.UNESTABLISHED:
                assert report is not None, (subject, state, strength)
            else:
                assert report is None, (subject, state, strength)

    def test_the_refusal_names_both_halves_of_the_mismatch(self) -> None:
        with pytest.raises(ValueError, match="worm_unlocked.*strength_irreversible"):
            WormReport(
                subject=WormSubject.OBJECT_VERSION,
                state=WormState.UNLOCKED,
                strength=WormStrength.IRREVERSIBLE,
                detail="d",
            )


class TestRendering:
    """J4's preflight prints these lines. They must name the mechanism and
    its scope — DESIGN.md §11: no output prints a tamper-proof claim without
    naming what it covers."""

    def test_every_representable_finding_has_a_label(self) -> None:
        # Exhaustive over the FULL PRODUCT with no silent default: a fourth
        # state, a third subject, or a fourth strength fails here rather than
        # rendering as a blank line or inheriting somebody else's claim.
        for subject, state, strength in ALL_TRIPLES:
            report = finding(subject, state, strength)
            if report is None:
                continue
            lines = render_worm_state(report)
            assert lines, (subject, state, strength)
            text = " ".join(lines)
            assert subject.value in text, (subject, state, strength)
            assert state.value in text, (subject, state, strength)
            assert strength.value in text, (subject, state, strength)

    def test_the_label_map_covers_the_representable_surface_and_nothing_else(self) -> None:
        assert set(_WORM_LABEL) == set(REPRESENTABLE)

    def test_the_irreversible_object_line_scopes_its_claim(self) -> None:
        lines = render_worm_state(
            WormReport(
                subject=WormSubject.OBJECT_VERSION,
                state=WormState.LOCKED,
                strength=WormStrength.IRREVERSIBLE,
                detail="COMPLIANCE",
            )
        )
        text = " ".join(lines)
        assert "refused" in text.lower()
        assert "retention period" in text.lower()

    def test_the_unlocked_line_says_checked_and_false_for_both_subjects(self) -> None:
        for subject in WormSubject:
            text = " ".join(
                render_worm_state(
                    WormReport(
                        subject=subject,
                        state=WormState.UNLOCKED,
                        strength=WormStrength.UNESTABLISHED,
                        detail="d",
                    )
                )
            )
            assert "tamper-evident only" in text, subject

    def test_the_unknown_line_refuses_both_binary_readings_for_both_subjects(self) -> None:
        for subject in WormSubject:
            text = " ".join(
                render_worm_state(
                    WormReport(
                        subject=subject,
                        state=WormState.UNKNOWN,
                        strength=WormStrength.UNESTABLISHED,
                        detail="d",
                    )
                )
            )
            assert "not" in text.lower(), subject
            assert "unmeasured" in text.lower(), subject

    def test_the_detail_is_always_carried_into_the_output(self) -> None:
        for triple in REPRESENTABLE:
            report = finding(*triple, detail="BECAUSE-X")
            assert report is not None
            assert "BECAUSE-X" in " ".join(render_worm_state(report)), triple

    def test_only_the_irreversible_object_finding_promises_storage_refusal(self) -> None:
        # The invariant over the WHOLE renderable surface, not over the one
        # function I happened to be thinking about: exactly ONE of the ten
        # findings may promise that storage refuses a write. Asserted against
        # the named promise constant AND against the bare phrase, so neither a
        # copy of the sentence nor a paraphrase of it can spread quietly.
        for marker in (_STORAGE_REFUSAL_PROMISE, "REFUSED by storage"):
            promising = [
                triple
                for triple in REPRESENTABLE
                if marker in " ".join(render_worm_state(finding(*triple)))  # type: ignore[arg-type]
            ]
            assert promising == [
                (WormSubject.OBJECT_VERSION, WormState.LOCKED, WormStrength.IRREVERSIBLE)
            ], marker

    def test_no_bypassable_finding_claims_storage_level_protection(self) -> None:
        # The defect in one line: GOVERNANCE is retained but overridable by the
        # account's own operator, so no bypassable finding may read as a
        # storage guarantee, and every one of them must name the escape hatch
        # rather than leaving an operator to infer it.
        bypassable = [t for t in REPRESENTABLE if t[2] is WormStrength.BYPASSABLE]
        assert bypassable, "the bypassable strength must be renderable at all"
        for triple in bypassable:
            text = " ".join(render_worm_state(finding(*triple)))  # type: ignore[arg-type]
            assert "REFUSED by storage" not in text, triple
            assert "s3:BypassGovernanceRetention" in text, triple
            assert "BYPASSABLE" in text, triple

    def test_the_three_locked_strengths_are_three_different_sentences(self) -> None:
        # The SENTENCE, with the grep prefix stripped off. Comparing whole
        # lines would pass on prefixes alone while three identical claims sat
        # underneath them — which is the shape of the bug being fixed, so the
        # test must not be satisfiable by the prefix.
        for subject in WormSubject:
            sentences = {
                render_worm_state(finding(subject, WormState.LOCKED, strength))[  # type: ignore[arg-type]
                    0
                ].split(": ", 1)[1]
                for strength in WormStrength
            }
            assert len(sentences) == len(WormStrength), subject

    def test_only_object_level_findings_talk_about_this_object_version(self) -> None:
        for triple in REPRESENTABLE:
            text = " ".join(render_worm_state(finding(*triple)))  # type: ignore[arg-type]
            if triple[0] is WormSubject.BUCKET:
                assert "this object version" not in text, triple

    def test_every_locked_bucket_line_disclaims_object_retention_at_every_strength(self) -> None:
        # The J1 invariant must survive the widening: adding the strength axis
        # tripled the bucket/locked labels, and all three must still refuse the
        # object-level reading.
        for strength in WormStrength:
            text = " ".join(
                render_worm_state(finding(WormSubject.BUCKET, WormState.LOCKED, strength))  # type: ignore[arg-type]
            )
            assert "does NOT establish" in text, strength
            assert "REFUSED by storage" not in text, strength


class TestUnknownCanNeverPrintAsLocked:
    """The falsifiability receipt that matters most. Not "we checked the
    obvious cases" — a sweep over every non-answering reply this adapter can
    receive, asserting the locked token appears in none of them."""

    UNANSWERING: tuple[Any, ...] = (
        FakeClientError("AccessDenied"),
        FakeClientError("403"),
        FakeClientError(""),
        FakeClientError("SomeCodeInventedIn2031"),
        RuntimeError("socket closed"),
        {},
        "fine",
        {"Retention": "locked"},
        {"Retention": {"Mode": "FUTUREMODE", "RetainUntilDate": FUTURE}},
        {"Retention": {"Mode": "COMPLIANCE"}},
        {"Retention": {"Mode": "COMPLIANCE", "RetainUntilDate": "?"}},
    )

    def test_no_unanswering_reply_yields_locked(self) -> None:
        for reply in self.UNANSWERING:
            report = object_worm_state(
                FakeWormS3Client(retention=reply), bucket="audit", key="k", now_fn=now_fn
            )
            assert report.state is WormState.UNKNOWN, reply

    def test_no_unanswering_reply_renders_the_locked_token(self) -> None:
        for reply in self.UNANSWERING:
            report = object_worm_state(
                FakeWormS3Client(retention=reply), bucket="audit", key="k", now_fn=now_fn
            )
            text = " ".join(render_worm_state(report))
            assert WormState.LOCKED.value not in text, reply

    def test_the_extra_absent_path_never_renders_the_locked_token(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setitem(sys.modules, "boto3", None)
        result = upload_sealed_segment(None, bucket="audit", key="k", body=b"x", now_fn=now_fn)
        assert WormState.LOCKED.value not in " ".join(render_worm_state(result.worm))

    def test_an_upload_that_could_not_confirm_reports_unknown_not_locked(self) -> None:
        # The PUT with ObjectLockMode SUCCEEDED here. Reporting "locked" off
        # the back of a successful request instead of a successful CHECK is
        # exactly the write-time-trust lie this library exists to refuse.
        result = upload_sealed_segment(
            FakeWormS3Client(retention=FakeClientError("AccessDenied")),
            bucket="audit",
            key="k",
            body=b"x",
            retention=COMPLIANCE,
            now_fn=now_fn,
        )
        assert result.uploaded is True
        assert result.worm.state is WormState.UNKNOWN


class TestResultShape:
    """J3 calls this from the rotation flow and preflight (J4) surfaces the
    state. Both read the result; neither may need to reach into internals."""

    def test_the_upload_result_carries_key_uploaded_and_worm(self) -> None:
        result = upload_sealed_segment(
            FakeWormS3Client(retention=retained()),
            bucket="audit",
            key="seg/7.jsonl",
            body=b"x",
            retention=COMPLIANCE,
            now_fn=now_fn,
        )
        assert isinstance(result, SegmentUpload)
        assert result.key == "seg/7.jsonl"
        assert isinstance(result.worm, WormReport)

    def test_the_report_is_immutable(self) -> None:
        report = WormReport(
            subject=WormSubject.OBJECT_VERSION,
            state=WormState.UNKNOWN,
            strength=WormStrength.UNESTABLISHED,
            detail="d",
        )
        with pytest.raises(AttributeError):
            report.state = WormState.LOCKED  # type: ignore[misc]


LOCKED_BUCKET_CONFIG = {
    "ObjectLockConfiguration": {
        "ObjectLockEnabled": "Enabled",
        "Rule": {"DefaultRetention": {"Mode": "COMPLIANCE", "Days": 7}},
    }
}


class TestBucketEvidenceNeverClaimsObjectRetention:
    """A bucket-level answer must never render as an object-level guarantee.

    "Object Lock is enabled on the bucket" and "this object version carries a
    retention period" are two claims of different strength: AWS protects "only
    the version that's specified in the request", so bucket configuration
    establishes nothing about any particular segment. preflight (J4) prints
    these lines, and an operator who read the object-version guarantee off
    bucket evidence would believe a segment is WORM-protected when nothing
    has established it — the same false confidence as beads v1.2.2.

    A ternary that is correct per-value can still lie through its renderer.
    """

    def test_a_locked_bucket_does_not_claim_this_object_version_is_retained(self) -> None:
        text = " ".join(
            render_worm_state(
                bucket_worm_state(
                    FakeWormS3Client(lock_config=LOCKED_BUCKET_CONFIG), bucket="audit"
                )
            )
        )
        assert "this object version" not in text

    def test_a_locked_bucket_does_not_promise_storage_refuses_an_overwrite(self) -> None:
        # The refusal promise is the object-level guarantee. A bucket merely
        # being configured to allow locking promises no refusal for anything.
        text = " ".join(
            render_worm_state(
                bucket_worm_state(
                    FakeWormS3Client(lock_config=LOCKED_BUCKET_CONFIG), bucket="audit"
                )
            )
        )
        assert "REFUSED by storage" not in text

    def test_a_locked_bucket_says_outright_that_it_establishes_no_object_retention(self) -> None:
        text = " ".join(
            render_worm_state(
                bucket_worm_state(
                    FakeWormS3Client(lock_config=LOCKED_BUCKET_CONFIG), bucket="audit"
                )
            )
        )
        assert "does NOT establish" in text

    def test_bucket_and_object_locked_lines_are_not_the_same_claim(self) -> None:
        bucket = " ".join(
            render_worm_state(
                bucket_worm_state(
                    FakeWormS3Client(lock_config=LOCKED_BUCKET_CONFIG), bucket="audit"
                )
            )
        )
        obj = " ".join(
            render_worm_state(
                object_worm_state(
                    FakeWormS3Client(retention=retained()), bucket="audit", key="k", now_fn=now_fn
                )
            )
        )
        assert bucket != obj


# The exact clause the strong line must keep. Weakening it into something vague
# enough to be true of GOVERNANCE too would "fix" this bug by destroying the
# one line in the module that carries a real guarantee.
UNDILUTED = "an overwrite or delete is REFUSED by storage"


class TestGovernanceRetentionIsNotAStorageGuarantee:
    """GOVERNANCE is retained but BYPASSABLE, and the two must not share a line.

    AWS: a COMPLIANCE-retained version "can't be overwritten or deleted by any
    user, including the root user"; a GOVERNANCE-retained one is overridable by
    a caller holding ``s3:BypassGovernanceRetention`` who sends
    ``x-amz-bypass-governance-retention:true``. So the storage-refusal promise
    is false under GOVERNANCE against exactly the adversary an archive is kept
    against — the account's own operator, who is also the party that could
    tamper.

    This is the same collapse ``WormSubject`` was introduced to fix, one level
    down: two claims of different strength sharing one state value.
    """

    def governance(self) -> WormReport:
        return object_worm_state(
            FakeWormS3Client(retention=retained(mode="GOVERNANCE")),
            bucket="audit",
            key="k",
            now_fn=now_fn,
        )

    def compliance(self) -> WormReport:
        return object_worm_state(
            FakeWormS3Client(retention=retained(mode="COMPLIANCE")),
            bucket="audit",
            key="k",
            now_fn=now_fn,
        )

    def test_a_governance_retention_does_not_promise_storage_refuses_an_overwrite(self) -> None:
        assert "REFUSED by storage" not in " ".join(render_worm_state(self.governance()))

    def test_a_governance_retention_names_the_bypass_that_makes_it_weaker(self) -> None:
        text = " ".join(render_worm_state(self.governance()))
        assert "s3:BypassGovernanceRetention" in text
        assert "x-amz-bypass-governance-retention:true" in text

    def test_a_governance_retention_is_still_locked_and_not_unlocked(self) -> None:
        # It IS retained. Calling it unlocked would be a different lie:
        # worm_unlocked means "asked, and the answer was a definite no".
        assert self.governance().state is WormState.LOCKED

    def test_the_two_modes_are_told_apart_by_the_report_not_by_its_prose(self) -> None:
        # A caller branching on the state alone got the strong promise for the
        # weak mode. The strength is a field, so no one has to parse `detail`.
        assert self.governance().strength is WormStrength.BYPASSABLE
        assert self.compliance().strength is WormStrength.IRREVERSIBLE

    def test_the_strength_reaches_the_rendered_prefix_for_grep(self) -> None:
        assert render_worm_state(self.governance())[0].startswith(
            "object_version/worm_locked/strength_bypassable: "
        )
        assert render_worm_state(self.compliance())[0].startswith(
            "object_version/worm_locked/strength_irreversible: "
        )

    def test_the_compliance_line_keeps_its_promise_undiluted(self) -> None:
        text = " ".join(render_worm_state(self.compliance()))
        assert UNDILUTED in text
        assert "including the account's root user" in text

    def test_the_two_modes_do_not_render_the_same_line(self) -> None:
        assert render_worm_state(self.governance()) != render_worm_state(self.compliance())

    def test_an_expired_governance_retention_is_unlocked_with_no_strength(self) -> None:
        report = object_worm_state(
            FakeWormS3Client(retention=retained(mode="GOVERNANCE", until=PAST)),
            bucket="audit",
            key="k",
            now_fn=now_fn,
        )
        assert report.state is WormState.UNLOCKED
        assert report.strength is WormStrength.UNESTABLISHED

    def test_an_upload_under_governance_reports_the_weaker_strength(self) -> None:
        result = upload_sealed_segment(
            FakeWormS3Client(retention=retained(mode="GOVERNANCE")),
            bucket="audit",
            key="k",
            body=b"x",
            retention=WormRetention(mode="GOVERNANCE", retain_until=FUTURE),
            now_fn=now_fn,
        )
        assert result.worm.strength is WormStrength.BYPASSABLE
        assert "REFUSED by storage" not in " ".join(render_worm_state(result.worm))


class TestRetentionModeStrengthIsTheSingleSourceOfTruth:
    """The allowlist is derived from the strength table, so a mode cannot be
    admitted without someone stating what it promises."""

    def test_the_allowlist_is_exactly_the_keys_of_the_strength_table(self) -> None:
        assert frozenset(RETENTION_MODE_STRENGTH) == RETENTION_MODES

    def test_every_documented_mode_declares_a_real_strength(self) -> None:
        for mode, strength in RETENTION_MODE_STRENGTH.items():
            assert strength is not WormStrength.UNESTABLISHED, mode

    def test_the_two_documented_modes_map_to_the_aws_documented_strengths(self) -> None:
        assert RETENTION_MODE_STRENGTH == {
            "COMPLIANCE": WormStrength.IRREVERSIBLE,
            "GOVERNANCE": WormStrength.BYPASSABLE,
        }

    def test_an_operator_declaration_exposes_its_strength_as_a_value(self) -> None:
        # waxseal does not overrule the operator's compliance decision — both
        # modes stay declarable — but the weaker one must never READ as the
        # stronger one anywhere, including here.
        assert WormRetention(mode="COMPLIANCE", retain_until=FUTURE).strength is (
            WormStrength.IRREVERSIBLE
        )
        assert WormRetention(mode="GOVERNANCE", retain_until=FUTURE).strength is (
            WormStrength.BYPASSABLE
        )


class TestBucketDefaultRetentionCarriesItsStrength:
    """``bucket_worm_state`` reads a default-retention Mode, so it can classify
    the strength NEW objects inherit — while still establishing nothing about
    any stored version."""

    def bucket(self, rule: Any) -> WormReport:
        config: dict[str, Any] = {"ObjectLockConfiguration": {"ObjectLockEnabled": "Enabled"}}
        if rule is not None:
            config["ObjectLockConfiguration"]["Rule"] = rule
        return bucket_worm_state(FakeWormS3Client(lock_config=config), bucket="audit")

    def test_a_compliance_default_is_irreversible(self) -> None:
        report = self.bucket({"DefaultRetention": {"Mode": "COMPLIANCE", "Days": 7}})
        assert report.state is WormState.LOCKED
        assert report.strength is WormStrength.IRREVERSIBLE

    def test_a_governance_default_is_bypassable_and_says_so(self) -> None:
        report = self.bucket({"DefaultRetention": {"Mode": "GOVERNANCE", "Days": 7}})
        assert report.state is WormState.LOCKED
        assert report.strength is WormStrength.BYPASSABLE
        assert "s3:BypassGovernanceRetention" in " ".join(render_worm_state(report))

    def test_an_unreadable_default_rule_establishes_no_strength(self) -> None:
        # Enabled is still enabled; no mode was read, so no strength was
        # established. That is a value, not an omission (rule 5).
        report = self.bucket(None)
        assert report.state is WormState.LOCKED
        assert report.strength is WormStrength.UNESTABLISHED

    def test_an_unrecognized_default_mode_establishes_no_strength(self) -> None:
        report = self.bucket({"DefaultRetention": {"Mode": "FUTUREMODE", "Days": 7}})
        assert report.strength is WormStrength.UNESTABLISHED
