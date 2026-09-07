"""Object Lock / WORM (Workstream J1)
----------------------------------
The lower half of this module puts a SEALED segment under S3 Object Lock
retention, so that storage can REFUSE an overwrite instead of merely letting
the chain detect one afterwards. This is the scoped half of the "tamper-proof"
claim (DESIGN.md §11): it covers an archived object version, never the live
tail and never write-time honesty -- and, since the two retention modes hold
against different adversaries, only a COMPLIANCE-mode retention covers it
against the account's own operator.

VERIFIED 31/08/2026 against official AWS documentation. The plan carried all
of this as "[Unverified - semantics Object Lock compliance mode from AWS
documentation, re-check when starting this bead]"; these are the claims that
re-check settled, each with the page that settled it:

* Retention modes -- S3 User Guide, "Locking objects with Object Lock"
  (docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock-overview.html).
  COMPLIANCE: "a protected object version can't be overwritten or deleted by
  any user, including the root user in your AWS account... its retention mode
  can't be changed, and its retention period can't be shortened"; the only
  documented escape is deleting the AWS account. GOVERNANCE: overridable by a
  caller holding ``s3:BypassGovernanceRetention`` who also sends
  ``x-amz-bypass-governance-retention:true``. So only COMPLIANCE is a WORM
  guarantee against the account's own operator -- which is exactly why the
  OPERATOR declares the mode here and this library ships no default. That
  asymmetry is now ENFORCED and not merely documented: see the ``WormStrength``
  paragraph below. The first version of this half stated it here in prose and
  then printed one sentence for both modes.
* A retention period can be EXTENDED by anyone holding
  ``s3:PutObjectRetention``, and never shortened (same page). Both directions
  matter to a verifier: "locked" can silently become "locked for longer",
  but never "locked for less".
* Legal hold is independent of the retention period and has no expiry: it
  keeps protecting an object after the retention period ends, and removing it
  does not end an in-force retention period (same page).
* Versioning -- "Object Lock works only in buckets that have S3 Versioning
  enabled", and a retention period protects "only the version that's
  specified in the request" (same page). That is why ``version_id`` is
  threaded through the checks: asking about the wrong version answers a
  different question than the one asked.
* ``put_object`` parameter types -- boto3 S3 client reference for
  ``put_object``, cross-checked against botocore's own S3 service model (api
  version 2006-03-01, shapes ``ObjectLockMode`` /
  ``ObjectLockRetainUntilDate`` / ``ObjectLockLegalHoldStatus``):
  ``ObjectLockMode`` is a string enum ``GOVERNANCE | COMPLIANCE``;
  ``ObjectLockRetainUntilDate`` is a *timestamp* (``timestampFormat:
  iso8601``), i.e. a ``datetime`` and not a string;
  ``ObjectLockLegalHoldStatus`` is a string enum ``ON | OFF``.
* Same ``put_object`` page: "The ``Content-MD5`` or
  ``x-amz-sdk-checksum-algorithm`` header is required for any request to
  upload an object with a retention period configured using Amazon S3 Object
  Lock." A retention PUT here therefore carries ``ContentMD5``. That MD5 is
  an API-mandated transport integrity header, NOT a security digest and NOT
  the chain's hash -- the chain is SHA-256 over the header (SPEC.md).
* Which API answers WHICH question -- two different questions, deliberately
  not merged into one answer. ``get_object_lock_configuration`` answers "is
  Object Lock configured on this BUCKET" (response ``ObjectLockConfiguration``
  carrying ``ObjectLockEnabled``, whose only documented valid value is
  ``Enabled``, plus an optional default-retention ``Rule``).
  ``get_object_retention`` answers "is THIS object version retained"
  (response ``Retention.Mode`` + ``Retention.RetainUntilDate``, both
  documented as required in a 200). A bucket with Object Lock configured
  still says nothing about whether a given object version got a retention
  period, so ``bucket_worm_state`` is never used to answer for an object.
  That asymmetry is enforced rather than merely documented: every
  ``WormReport`` carries a ``WormSubject``, so bucket evidence structurally
  cannot print the object-version guarantee. The first version of this module
  keyed the label on state alone and did exactly that -- a ternary can be
  correct in every value and still lie in its renderer.
* Which ADVERSARY a lock holds against -- the same lesson, one level down, and
  the reason ``_WORM_LABEL`` is keyed on the (subject, state, strength) TRIPLE
  rather than the pair. Adding ``WormSubject`` left COMPLIANCE and GOVERNANCE
  sharing ``OBJECT_VERSION``/``LOCKED`` and therefore sharing one sentence, so
  a bypassable GOVERNANCE retention printed "an overwrite or delete is REFUSED
  by storage" -- false against precisely the account operator the archive
  exists to constrain, and invisible to any caller branching on the state.
  ``WormStrength`` is ``WormSubject``'s shape applied to that axis: a required
  field with no default, an exhaustive table keyed on it, and
  ``RETENTION_MODE_STRENGTH`` replacing the flat mode allowlist so a mode
  cannot be admitted without declaring what it promises.

CORRECTION to the plan, measured while verifying: the plan and its bead state
that Object Lock "must be enabled at bucket creation". The S3 User Guide
page "Configuring S3 Object Lock" documents BOTH "Enable Object Lock when
creating a new S3 general purpose bucket" AND "Enable Object Lock on an
existing S3 bucket" (via ``put-object-lock-configuration``), so the
creation-time-only claim is wrong. What IS irreversible is the other
direction: "After you enable Object Lock on a bucket, you can't disable
Object Lock or suspend versioning for that bucket." No code here depends on
the creation-time claim either way.

STILL [Unverified], and load-bearing for the ternary: the exact error code S3
returns for "this bucket/object has no Object Lock configuration". The
``GetObjectRetention`` and ``GetObjectLockConfiguration`` API reference pages
document no error responses at all, and botocore's S3 service model declares
no modeled errors for either operation, so ``_NOT_CONFIGURED_CODES`` below is
a best-effort allowlist of the commonly observed codes and NOT a documented
one. Being wrong there is safe BY CONSTRUCTION rather than by luck: that
allowlist is the only thing that can produce ``UNLOCKED``, and any code
missing from it falls through to ``UNKNOWN``. A bad guess therefore costs an
honest "could not tell", never a false "locked" and never a false "not
locked". This label stays until someone confirms the codes against a live
bucket.
"""

from __future__ import annotations

import enum
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final

from waxseal.adapters.s3._errors import _describe, _error_code


class WormSubject(enum.Enum):
    """WHICH question a ``WormReport`` answers.

    Not a fourth ternary value and not a severity: the ternary is unchanged.
    This records the SUBJECT the three states are about, because the two
    questions this module can ask have different strengths and must never
    share one sentence. AWS protects "only the version that's specified in
    the request", so ``BUCKET`` evidence establishes nothing about any
    particular object version. Carrying the subject in the report is what
    makes that impossible to lose on the way to the renderer -- the first
    version of this module proved a per-value-correct ternary can still lie
    through a shared label.

    Required, with no default: a default subject would let a future call site
    inherit the wrong claim silently, which is the whole failure being fixed.
    """

    OBJECT_VERSION = "object_version"
    BUCKET = "bucket"


class WormState(enum.Enum):
    """Whether a sealed segment is actually under WORM retention.

    The EIGHTH instance of the Ternary Evidence Principle in this codebase
    (CLAUDE.md, "Named principle"). Deliberately NOT ``domain.verdict.Verdict``,
    even though the shape is the same three-valued one: ``Verdict``'s values
    carry severity and CLI exit codes, and neither of the two possible
    mappings for a bucket without Object Lock is honest. ``BROKEN`` (exit 1)
    would say "tampered" about a bucket that is merely not configured for
    WORM -- a false alarm, and migration 060's collapse exactly. ``OK`` would
    say the WORM claim holds when it does not -- false confidence, beads
    v1.2.2's collapse exactly. So this reuses ``Verdict``'s VOCABULARY and
    shape (an enum, an exhaustive spelled-out map, a render function that
    always states the weaker claim) while keeping its own three values.

    ``UNKNOWN`` is not a degraded ``UNLOCKED``. "Nobody asked, or nobody was
    allowed to ask" is a third fact, and printing it as either binary is the
    one lie a tamper-evidence mechanism must never tell.
    """

    LOCKED = "worm_locked"
    UNLOCKED = "worm_unlocked"
    UNKNOWN = "worm_unknown"


class WormStrength(enum.Enum):
    """HOW STRONG an in-force retention is -- against WHICH adversary.

    Not a fourth ``WormState`` and not a severity: the ternary is unchanged.
    This is ``WormSubject``'s move applied to the other axis. ``WormSubject``
    exists because the same three states asked about two different SUBJECTS
    produced a false guarantee; this exists because ``LOCKED`` covered two
    retention modes of different STRENGTH, and AWS documents them as different
    in exactly the way the threat model cares about. COMPLIANCE cannot be
    overwritten or deleted by any user "including the root user in your AWS
    account"; GOVERNANCE is overridable by a caller holding
    ``s3:BypassGovernanceRetention`` who sends
    ``x-amz-bypass-governance-retention:true`` -- i.e. by the account's own
    operator, the party an archive is kept against. Printing one promise for
    both told an operator that storage would refuse a write it would in fact
    accept.

    Required on every ``WormReport``, with no default, for ``WormSubject``'s
    reason: a default would let a call site inherit the stronger claim
    silently, which is the whole failure being fixed.

    ``UNESTABLISHED`` is a value, not an absence (the ``human_oversight.mode``
    idiom in ``domain/decision.py``: "unrecorded" is a value). It is the
    honest answer wherever this finding asserts no retention strength -- there
    is no retention (``UNLOCKED``), the retention question went unmeasured
    (``UNKNOWN``), or a retention is in force but its mode was not read.
    """

    IRREVERSIBLE = "strength_irreversible"
    BYPASSABLE = "strength_bypassable"
    UNESTABLISHED = "strength_unestablished"


# The two modes AWS documents for Object Lock retention, each mapped to WHAT IT
# PROMISES. A mapping and not a bare set, so a mode cannot be added to the
# allowlist without someone stating the strength it confers -- the defect this
# replaces was a flat set whose two members reached one ``LOCKED`` return and
# one sentence. Still an ALLOWLIST, not a check against known-bad values: a
# mode invented after this build shipped must read as UNKNOWN, never be waved
# through as a guarantee. Same reasoning as an unknown hash_version being
# unverifiable rather than recomputed.
RETENTION_MODE_STRENGTH: Final[dict[str, WormStrength]] = {
    "COMPLIANCE": WormStrength.IRREVERSIBLE,
    "GOVERNANCE": WormStrength.BYPASSABLE,
}

# Derived, never a second literal: the allowlist and the strength table cannot
# drift apart if there is only one of them.
RETENTION_MODES: Final[frozenset[str]] = frozenset(RETENTION_MODE_STRENGTH)

# [Unverified] -- see the module docstring. Neither the S3 API reference nor
# botocore's service model documents the error code for "no Object Lock
# configuration here", so this list is observed, not documented. It is the
# ONLY path to UNLOCKED, and anything absent from it degrades to UNKNOWN, so a
# wrong entry costs honesty about uncertainty and never a wrong verdict.
_NOT_CONFIGURED_CODES: Final[frozenset[str]] = frozenset(
    {
        "NoSuchObjectLockConfiguration",
        "ObjectLockConfigurationNotFoundError",
        "InvalidRequest",
    }
)

# The one documented valid value of ObjectLockEnabled. An allowlist again:
# "Suspended", or anything else a future API returns, is a reply this build
# cannot interpret, not a reply meaning "off".
_LOCK_ENABLED_VALUES: Final[frozenset[str]] = frozenset({"Enabled"})


def _utcnow() -> datetime:
    # Injectable via now_fn (CLAUDE.md rule 8): comparing a retain-until date
    # against the clock is the one time-dependent decision here, and tests
    # must be able to pin both sides of it without sleeping.
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class WormRetention:
    """The retention the OPERATOR declares for a sealed segment.

    Both fields are required and neither has a default. waxseal invents no
    retention policy, exactly as it ships no default trust anchor for
    ``--tsa-ca-file``: a retention period is a compliance decision with a
    cost (COMPLIANCE mode cannot be shortened by anyone, including the
    account root), so guessing one is not a convenience.

    Both documented modes stay accepted. GOVERNANCE is a legitimate compliance
    decision and waxseal does not overrule the operator who made it; what
    waxseal must never do is let the weaker mode read as the stronger one, so
    ``strength`` exposes the difference as a value rather than leaving it to be
    inferred from the mode string at each call site.
    """

    mode: str
    retain_until: datetime

    @property
    def strength(self) -> WormStrength:
        """What this declaration will actually promise once it is in force."""
        return RETENTION_MODE_STRENGTH[self.mode]

    def __post_init__(self) -> None:
        if self.mode not in RETENTION_MODES:
            raise ValueError(
                f"retention mode must be one of {sorted(RETENTION_MODES)}, got {self.mode!r}"
            )
        if not isinstance(self.retain_until, datetime):
            raise ValueError("retain_until must be a datetime (put_object takes a timestamp)")
        if self.retain_until.tzinfo is None:
            # A retention date whose zone is a guess locks for the wrong span
            # and nothing downstream can tell it did.
            raise ValueError("retain_until must be timezone-aware")


@dataclass(frozen=True, slots=True)
class WormReport:
    """One WORM answer: the ternary state plus why it came out that way.

    ``detail`` is never optional. A bare ``UNKNOWN`` gives an operator
    nothing to act on, and "no permission to ask" and "the SDK is not
    installed" call for different fixes (CLAUDE.md rule 6: a degradation is
    recorded in the output, never swallowed).

    ``subject`` and ``strength`` are the two axes that stop the ternary from
    lying through its renderer: WHICH question was answered, and HOW STRONG
    the answer is. Both are required, both are read straight off the report by
    a caller, and neither may be recovered by parsing ``detail`` -- free text
    is not an interface.
    """

    subject: WormSubject
    state: WormState
    strength: WormStrength
    detail: str

    def __post_init__(self) -> None:
        # A strength is a property of a retention that is IN FORCE. "Not
        # retained" and "could not tell" have no strength to report, and
        # letting either carry IRREVERSIBLE would smuggle the strong claim
        # into a finding that established nothing. Refusing the combination
        # here is what keeps _WORM_LABEL exhaustive over the states that can
        # actually exist rather than over invented prose for ones that cannot.
        if self.state is not WormState.LOCKED and self.strength is not WormStrength.UNESTABLISHED:
            raise ValueError(
                f"a {self.state.value} finding cannot carry {self.strength.value}: "
                "only an in-force retention has a strength"
            )


def _unretained_by_configuration(exc: Exception) -> bool:
    return _error_code(exc) in _NOT_CONFIGURED_CODES


def object_worm_state(
    client: Any,
    *,
    bucket: str,
    key: str,
    version_id: str | None = None,
    now_fn: Callable[[], datetime] = _utcnow,
) -> WormReport:
    """Is THIS object version actually under an in-force Object Lock retention?

    Asks ``get_object_retention`` -- the API that answers about an object,
    not ``get_object_lock_configuration``, which answers about a bucket.

    Every return below is either UNLOCKED (asked, and the answer was a
    definite no) or UNKNOWN (could not tell), except the single LOCKED return,
    which is reachable only with an allowlisted mode AND a timezone-aware
    retain-until date still in the future. There is no fall-through and no
    default: a reply this build cannot parse leaves via UNKNOWN.
    """
    ask = getattr(client, "get_object_retention", None)
    if ask is None:
        # An older SDK or an S3-compatible service may not implement it. That
        # is "could not ask", which is not "not locked".
        return WormReport(
            subject=WormSubject.OBJECT_VERSION,
            state=WormState.UNKNOWN,
            strength=WormStrength.UNESTABLISHED,
            detail="the injected client has no get_object_retention method, so the "
            "retention state of this object version could not be asked for",
        )

    kwargs: dict[str, Any] = {"Bucket": bucket, "Key": key}
    if version_id is not None:
        # Retention protects a VERSION; omitting it asks about the current one.
        kwargs["VersionId"] = version_id
    try:
        reply = ask(**kwargs)
    except Exception as exc:
        if _unretained_by_configuration(exc):
            return WormReport(
                subject=WormSubject.OBJECT_VERSION,
                state=WormState.UNLOCKED,
                strength=WormStrength.UNESTABLISHED,
                detail=f"S3 reports no Object Lock retention for this object ({_describe(exc)})",
            )
        # AccessDenied lands here, and must: a caller without
        # s3:GetObjectRetention has learned nothing about the object.
        return WormReport(
            subject=WormSubject.OBJECT_VERSION,
            state=WormState.UNKNOWN,
            strength=WormStrength.UNESTABLISHED,
            detail=f"the retention question could not be answered ({_describe(exc)})",
        )

    if not isinstance(reply, dict):
        return WormReport(
            subject=WormSubject.OBJECT_VERSION,
            state=WormState.UNKNOWN,
            strength=WormStrength.UNESTABLISHED,
            detail=f"get_object_retention returned {type(reply).__name__}, not a mapping",
        )
    retention = reply.get("Retention")
    if not isinstance(retention, dict):
        # GetObjectRetention documents Retention as required in a 200. A 200
        # without it did not answer the question, so neither do we.
        return WormReport(
            subject=WormSubject.OBJECT_VERSION,
            state=WormState.UNKNOWN,
            strength=WormStrength.UNESTABLISHED,
            detail="the reply carried no Retention block, which a 200 is documented to "
            "require, so it did not answer whether this version is retained",
        )

    mode = retention.get("Mode")
    if mode not in RETENTION_MODES:
        return WormReport(
            subject=WormSubject.OBJECT_VERSION,
            state=WormState.UNKNOWN,
            strength=WormStrength.UNESTABLISHED,
            detail=f"retention mode {mode!r} is not one of {sorted(RETENTION_MODES)}; this "
            "build cannot say what protection it confers",
        )
    retain_until = retention.get("RetainUntilDate")
    if not isinstance(retain_until, datetime):
        return WormReport(
            subject=WormSubject.OBJECT_VERSION,
            state=WormState.UNKNOWN,
            strength=WormStrength.UNESTABLISHED,
            detail=f"RetainUntilDate is {type(retain_until).__name__}, not a timestamp, so "
            "the retention period could not be placed on a clock",
        )
    if retain_until.tzinfo is None:
        # Guessing the zone would turn an unanswerable question into a verdict.
        return WormReport(
            subject=WormSubject.OBJECT_VERSION,
            state=WormState.UNKNOWN,
            strength=WormStrength.UNESTABLISHED,
            detail="RetainUntilDate arrived without a timezone, so it cannot be compared "
            "against now without inventing one",
        )

    now = now_fn()
    if retain_until <= now:
        return WormReport(
            subject=WormSubject.OBJECT_VERSION,
            state=WormState.UNLOCKED,
            strength=WormStrength.UNESTABLISHED,
            detail=f"the {mode} retention period expired at {retain_until.isoformat()}; "
            "storage will accept an overwrite of this version again",
        )
    # The mode is allowlisted above, so its strength is known here. Carrying it
    # on the report rather than only inside `detail` is the point: a caller
    # branching on LOCKED alone once got the COMPLIANCE promise for a
    # GOVERNANCE retention, which the account's own operator can bypass.
    return WormReport(
        subject=WormSubject.OBJECT_VERSION,
        state=WormState.LOCKED,
        strength=RETENTION_MODE_STRENGTH[mode],
        detail=f"{mode} retention in force until {retain_until.isoformat()}",
    )


def bucket_worm_state(client: Any, *, bucket: str) -> WormReport:
    """Is Object Lock configured on this BUCKET?

    A different question from ``object_worm_state``'s, kept separate on
    purpose: Object Lock being enabled on a bucket does not mean any given
    object version got a retention period, so this answer must never be used
    to answer for an object. The archive path asks this one directly. Naming
    WORM as one of the two mechanisms that can raise an anchor into scoped
    proof (DESIGN.md §11) is as far as `waxseal preflight` (J4) goes on its
    own: it opens no network connection and holds no storage credentials, so
    it never calls this function itself — that would require a `--bucket`
    flag and real S3 access this bead deliberately left unbuilt.
    """
    ask = getattr(client, "get_object_lock_configuration", None)
    if ask is None:
        return WormReport(
            subject=WormSubject.BUCKET,
            state=WormState.UNKNOWN,
            strength=WormStrength.UNESTABLISHED,
            detail="the injected client has no get_object_lock_configuration method, so "
            "the bucket's Object Lock configuration could not be asked for",
        )
    try:
        reply = ask(Bucket=bucket)
    except Exception as exc:
        if _unretained_by_configuration(exc):
            return WormReport(
                subject=WormSubject.BUCKET,
                state=WormState.UNLOCKED,
                strength=WormStrength.UNESTABLISHED,
                detail=f"S3 reports no Object Lock configuration on {bucket!r} "
                f"({_describe(exc)})",
            )
        return WormReport(
            subject=WormSubject.BUCKET,
            state=WormState.UNKNOWN,
            strength=WormStrength.UNESTABLISHED,
            detail=f"the bucket's Object Lock configuration could not be read "
            f"({_describe(exc)})",
        )

    config = reply.get("ObjectLockConfiguration") if isinstance(reply, dict) else None
    if not isinstance(config, dict):
        return WormReport(
            subject=WormSubject.BUCKET,
            state=WormState.UNKNOWN,
            strength=WormStrength.UNESTABLISHED,
            detail="the reply carried no ObjectLockConfiguration block, which a 200 is "
            "documented to require, so it did not answer whether the bucket locks",
        )
    enabled = config.get("ObjectLockEnabled")
    if enabled not in _LOCK_ENABLED_VALUES:
        return WormReport(
            subject=WormSubject.BUCKET,
            state=WormState.UNKNOWN,
            strength=WormStrength.UNESTABLISHED,
            detail=f"ObjectLockEnabled is {enabled!r}, not one of "
            f"{sorted(_LOCK_ENABLED_VALUES)}; this build cannot interpret that reply",
        )

    rule = config.get("Rule")
    default = rule.get("DefaultRetention") if isinstance(rule, dict) else None
    mode = default.get("Mode") if isinstance(default, dict) else None
    if mode in RETENTION_MODES:
        # A bucket default names the mode NEW objects inherit, so its strength
        # is a real fact worth reporting -- but it is still bucket evidence and
        # still establishes no retention on any stored version. Both halves are
        # kept: the strength is carried, and the label refuses the object-level
        # reading at every strength.
        return WormReport(
            subject=WormSubject.BUCKET,
            state=WormState.LOCKED,
            strength=RETENTION_MODE_STRENGTH[mode],
            detail=f"Object Lock is enabled on {bucket!r} with a {mode} default retention",
        )
    # Enabled without a readable default rule is still enabled: per-object
    # retention (what upload_sealed_segment sets) is the mechanism, and a
    # bucket default is only a convenience on top of it. No mode was read, so
    # no strength was established -- which is a value here, not an omission.
    return WormReport(
        subject=WormSubject.BUCKET,
        state=WormState.LOCKED,
        strength=WormStrength.UNESTABLISHED,
        detail=f"Object Lock is enabled on {bucket!r}; no default retention rule was "
        "readable, so per-object retention is the only mechanism in play",
    )

# The ONE sentence in this module that promises storage-level refusal, named so
# that a test can sweep the whole label surface and assert exactly one finding
# is allowed to say it. Two findings of different strength sharing this
# sentence is precisely the defect this constant exists to make detectable.
_STORAGE_REFUSAL_PROMISE: Final[str] = (
    "an overwrite or delete is REFUSED by storage rather than merely detected afterwards "
    "by the chain, and refused for EVERY principal including the account's root user"
)

# Exhaustive over every (subject, state, strength) a WormReport can legally
# hold, spelled out rather than derived (matching domain.verdict's _EXIT_CODE
# tables) and keyed by all three: a missing key raises KeyError in
# render_worm_state instead of quietly rendering the wrong claim. The table has
# been widened twice by the same bug in two different clothes.
#
#   Keying on state ALONE was the first: bucket_worm_state's LOCKED printed
#   object_worm_state's guarantee, telling an operator a segment was
#   WORM-protected on evidence that established no such thing. WormSubject
#   fixed it.
#
#   Keying on (subject, state) was the second: COMPLIANCE and GOVERNANCE both
#   reached OBJECT_VERSION/LOCKED and shared one sentence, so a GOVERNANCE
#   retention -- which the account's own operator can bypass with
#   s3:BypassGovernanceRetention -- printed a storage-refusal promise that is
#   false against exactly that operator. WormStrength fixes it, the same way.
#
# Every line names its own SCOPE, because DESIGN.md §11 forbids printing a
# tamper-proof claim without saying what it covers -- and the strength axis
# says WHO it covers it against, which is half of what a scope is.
_WORM_LABEL: Final[dict[tuple[WormSubject, WormState, WormStrength], str]] = {
    (WormSubject.OBJECT_VERSION, WormState.LOCKED, WormStrength.IRREVERSIBLE): (
        "S3 Object Lock retention is IN FORCE on this object version, in an irreversible "
        "mode ({detail}). For the retention period, " + _STORAGE_REFUSAL_PROMISE + ". "
        "Scope: this object version only, only until the retain-until date, and it says "
        "nothing about whether what was written was true (DESIGN.md §11)."
    ),
    (WormSubject.OBJECT_VERSION, WormState.LOCKED, WormStrength.BYPASSABLE): (
        "S3 Object Lock retention is in force on this object version, but in a BYPASSABLE "
        "mode ({detail}). This is NOT a storage-level guarantee: a caller holding "
        "s3:BypassGovernanceRetention who sends x-amz-bypass-governance-retention:true can "
        "delete or overwrite this version before the retain-until date, and that caller is "
        "the account's own operator — precisely the party an archive is kept against. The "
        "retention is real and raises the cost of a quiet overwrite, but this segment stays "
        "tamper-evident by the chain rather than tamper-proof by storage (DESIGN.md §11)."
    ),
    (WormSubject.OBJECT_VERSION, WormState.LOCKED, WormStrength.UNESTABLISHED): (
        "S3 Object Lock retention is in force on this object version, but its STRENGTH was "
        "not established ({detail}). The documented modes differ in the way that decides "
        "this claim — one is refused for every principal including the account root, the "
        "other is overridable by an operator holding s3:BypassGovernanceRetention — so a "
        "mode this build did not read licenses no storage-level claim at all. Retained, "
        "strength unmeasured: that is a third answer, not a quiet vote for either "
        "(CLAUDE.md rule 5)."
    ),
    (WormSubject.OBJECT_VERSION, WormState.UNLOCKED, WormStrength.UNESTABLISHED): (
        "checked, and no S3 Object Lock retention is in force ({detail}). This segment is "
        "tamper-evident only: an overwrite would be detected by the chain, not refused by "
        "storage. This is a measured answer, not a failure."
    ),
    (WormSubject.OBJECT_VERSION, WormState.UNKNOWN, WormStrength.UNESTABLISHED): (
        "could not determine whether S3 Object Lock retention is in force ({detail}). This "
        "is NOT 'locked' and NOT 'unlocked': the WORM claim is unmeasured this run and "
        "must be rendered as unmeasured, never collapsed into either binary (CLAUDE.md "
        "rule 5). Silence is not confidence, and it is not an alarm either."
    ),
    (WormSubject.BUCKET, WormState.LOCKED, WormStrength.IRREVERSIBLE): (
        "S3 Object Lock is CONFIGURED on this bucket, and its default retention mode is "
        "the irreversible one ({detail}). Bucket-level evidence ONLY: it does NOT "
        "establish that any particular object version carries a retention period, because "
        "Object Lock protects only the version named in the request and a default governs "
        "what NEW objects inherit, not what stored ones already have. No segment may be "
        "called WORM-protected on this evidence — ask object_worm_state about the object "
        "version that matters."
    ),
    (WormSubject.BUCKET, WormState.LOCKED, WormStrength.BYPASSABLE): (
        "S3 Object Lock is CONFIGURED on this bucket, but its default retention mode is "
        "the BYPASSABLE one ({detail}): retention inherited from that default is "
        "overridable by an operator holding s3:BypassGovernanceRetention. Bucket-level "
        "evidence ONLY, and the weaker of the two strengths — it does NOT establish that "
        "any particular object version carries a retention period, and it would promise no "
        "refusal against the account's own operator even if one did. Ask object_worm_state "
        "about the object version that matters."
    ),
    (WormSubject.BUCKET, WormState.LOCKED, WormStrength.UNESTABLISHED): (
        "S3 Object Lock is CONFIGURED on this bucket; no default retention mode was "
        "readable, so no retention strength is established here either ({detail}). "
        "Bucket-level evidence ONLY: it does NOT establish that any particular object "
        "version carries a retention period. Per-object retention is the mechanism in "
        "play — ask object_worm_state about the object version that matters."
    ),
    (WormSubject.BUCKET, WormState.UNLOCKED, WormStrength.UNESTABLISHED): (
        "checked, and this bucket has no S3 Object Lock configuration ({detail}). "
        "Retention cannot be set without it, so nothing stored here is under retention: "
        "segments archived to this bucket are tamper-evident only. This is a measured "
        "answer, not a failure."
    ),
    (WormSubject.BUCKET, WormState.UNKNOWN, WormStrength.UNESTABLISHED): (
        "could not determine whether S3 Object Lock is configured on this bucket "
        "({detail}). This is NOT 'configured' and NOT 'unconfigured': unmeasured this "
        "run, and it must be rendered as unmeasured rather than collapsed into either "
        "binary (CLAUDE.md rule 5). Silence is not confidence, and it is not an alarm "
        "either."
    ),
}


def render_worm_state(report: WormReport) -> list[str]:
    """Human-readable lines for the CLI, in ``domain.tickets``'s style.

    Prefixed with the subject, the state AND the strength, so the ten possible
    findings are distinguishable in a log by grep and can never be told apart
    only by prose. The archive path prints these — `waxseal preflight` (J4)
    does not call this function; it names WORM as a mechanism without
    checking bucket/object state (no network access, no storage
    credentials). Only the ``OBJECT_VERSION``/``LOCKED``/``IRREVERSIBLE``
    line claims storage-level immutability for a segment, and it carries its
    scope inline; the ``BUCKET``/``LOCKED`` lines disclaim the object-level
    reading and the ``BYPASSABLE`` lines disclaim the refusal promise, each
    explicitly.
    """
    return [
        f"{report.subject.value}/{report.state.value}/{report.strength.value}: "
        + _WORM_LABEL[(report.subject, report.state, report.strength)].format(
            detail=report.detail
        )
    ]
