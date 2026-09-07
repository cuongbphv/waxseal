from __future__ import annotations

import json
import os
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from waxseal.adapters.anchors import AnchorRecord
from waxseal.adapters.remote import RemoteError
from waxseal.adapters.rfc3161_verify import (
    SIGNATURE_INVALID,
    SIGNATURE_UNCHECKED,
    SignatureCheck,
)
from waxseal.cli._common import _Check
from waxseal.domain.report import (
    RECEIPTS_NOT_RECORDED_REASON,
    CheckSummary,
)
from waxseal.domain.rfc3161 import NONCE_MISMATCH, RECEIPT_IMPRINT_MISMATCH
from waxseal.domain.separation import (
    SeparationTopology,
    counted_authorities,
    render_counted_authorities,
    render_separation_degree,
    separation_degree,
)
from waxseal.domain.verdict import Verdict
from waxseal.domain.witnessing import WitnessVerdict
from waxseal.log import AuditLog

# The only two RFC 3161 outcomes that mean "checked and false" rather than
# "not readable here": the token commits to bytes other than the record it
# sits beside. Everything else is a format this build cannot read.
_RECEIPT_CHECKED_FALSE: Final = frozenset({RECEIPT_IMPRINT_MISMATCH, NONCE_MISMATCH})


def _tau_line(topology: SeparationTopology | None) -> str:
    """The τ line `verify` prints, always, even with no `--pin` at all
    (rule 5: "not declared" must never be a silent absence, the same
    discipline `_print_drop_count` gives dropped_writes). `report`'s own
    rendering goes through `build_report`/`AuditReport` instead, so the two
    surfaces share the same domain functions without sharing this string.
    """
    degree = separation_degree(topology)
    rendered = render_separation_degree(degree)
    if degree is None:
        return f"τ (separation degree): {rendered}"
    breakdown = render_counted_authorities(counted_authorities(topology))
    return f"τ (separation degree): {rendered} ({breakdown})"


def _print_drop_count(trail: Path | None) -> None:
    # Completeness, not integrity (CLAUDE.md rule 5): this never changes
    # the caller's exit code. No sidecar means "never measured" (unchanged
    # output, matching the pre-M5 behavior), not a printed "0". A URL target
    # has no local sidecar location at all, the same as "never measured".
    if trail is None:
        return
    from waxseal.adapters.drops import read_drop_count

    count = read_drop_count(trail)
    if count is not None:
        print(f"dropped_writes >= {count} (measured minimum, from {trail}.drops)")


# Rule 5, one sidecar over from `.drops`: no `.receipts` file at all is "not
# recorded", never "checked, found nothing" and never a failure. Printed on
# every run, including the runs where nothing was recorded, because an
# absence an operator only sees by asking is an absence they will not see.
_RECEIPTS_ABSENT_LINE: Final = (
    "receipts: not recorded (no .receipts sidecar — per-append acknowledgment "
    "was never measured here, which is NOT the same as measured and clean)"
)

# A summary alone cannot carry absent-vs-empty: both are `ok=True, checked=0`.
# The reason string and the line above are what keep them apart, so the two are
# defined once, together, instead of rebuilt at each return.
_RECEIPTS_NOT_RECORDED: Final = CheckSummary(
    # The reason string lives in domain/report.py, because `report` renders
    # this same state into the artifact an auditor keeps and must not print it
    # as a flavour of "ok". Shared, never re-spelled: two surfaces agreeing by
    # coincidence is how absent quietly becomes clean.
    ok=True,
    checked=0,
    reason=RECEIPTS_NOT_RECORDED_REASON,
)

# SPEC.md section 19's honest limit, printed rather than filed in a doc: the
# sidecar is as attacker-writable as the trail beside it, so this check is
# worth exactly what it defeats and no more.
_RECEIPTS_LIMIT_NOTE: Final = (
    "the sidecar is as attacker-writable as the trail beside it — a rewrite "
    "that curates BOTH passes this check; only the server's own receipt chain "
    "(REMOTE.md section 10) catches that"
)


def _receipts_check(log: AuditLog, trail: Path | None) -> _Check:
    """Reconcile the `.receipts` sidecar against the trail as it stands now.

    A receipt is a second authority's write-time acknowledgment that entry
    `seq` carried `entry_hash`, so an edit to any acknowledged entry is
    contradicted from the very next append onward rather than at the next
    checkpoint — the rewrite window falls from the anchor cadence to one entry.

    Not gated behind a flag, unlike `--anchors`: there is nothing external to
    contact and nothing to pay for, and the absent case has to print anyway.
    """
    from waxseal.adapters.receipts import read_receipts, receipts_path
    from waxseal.domain.receipts import ReceiptRecord, reconcile_receipts

    if trail is None:
        # A URL target has no local sidecar location at all, the same state as
        # never having recorded one.
        return _Check(_RECEIPTS_NOT_RECORDED, _RECEIPTS_ABSENT_LINE)
    try:
        sidecar = read_receipts(trail)
    except OSError as e:
        # An environment fact, not a record-level finding: this build has no
        # coverage here, which is exit 2 and a label, never tampering.
        return _Check(
            CheckSummary(ok=True, checked=0, reason=None, unverifiable=True),
            f"receipts: {receipts_path(trail)} could not be read ({e}) — "
            "unverifiable, NOT evidence of tampering",
        )
    if not sidecar.present:
        return _Check(_RECEIPTS_NOT_RECORDED, _RECEIPTS_ABSENT_LINE)

    # entry_hashes() materializes the whole trail, so it is only paid for when
    # there is at least one readable record to compare against.
    hashes = (
        log.entry_hashes()
        if any(isinstance(line, ReceiptRecord) for line in sidecar.lines)
        else []
    )
    result = reconcile_receipts(hashes, sidecar)
    notes: list[str] = []
    if result.unreadable_versions:
        versions = ", ".join(sorted(set(result.unreadable_versions)))
        notes.append(
            f"{len(result.unreadable_versions)} record(s) in an unreadable format "
            f"version ({versions}) — unverifiable by name, NOT evidence of tampering"
        )
    if result.verdict is Verdict.BROKEN:
        where = (
            f"seq={result.broken_seq}"
            if result.broken_seq is not None
            # A malformed record names no trustworthy seq: the field that would
            # have named one is the field that failed to parse.
            else f"line {result.broken_line}"
        )
        line = f"RECEIPTS BROKEN at {where}: {result.reason}"
    elif result.checked:
        line = f"receipts ok (checked={result.checked}, latest=seq {result.latest_seq})"
        notes.append(_RECEIPTS_LIMIT_NOTE)
    else:
        line = (
            "receipts: sidecar present, 0 record(s) — checked, found nothing "
            "(NOT the same as no sidecar at all)"
        )
    for note in notes:
        line += f"\n  note: {note}"
    return _Check(
        CheckSummary(
            ok=result.verdict is not Verdict.BROKEN,
            checked=result.checked,
            reason=result.reason,
            unverifiable=result.verdict is Verdict.UNVERIFIABLE,
            notes=tuple(notes),
        ),
        line,
    )


def _anchor_check(log: AuditLog, trail: Path, *, tsa_ca_file: Path | None = None) -> _Check:
    """Check the `.anchors` sidecar against the trail as it stands now.

    ``tsa_ca_file`` turns on the OPTIONAL signature dimension
    (`adapters/rfc3161_verify.py`). It is opt-in for the same reason
    ``--anchors`` itself is: a dimension the operator did not engage is not
    part of this run's verdict, and `verify` must not start exiting 2 on
    every healthy trail whose TSA nobody named a bundle for -- the argument
    ``_receipt_verdict`` already makes for a pending OpenTimestamps proof.
    What it must never do is engage the dimension and then come back 0
    without an answer, so once a bundle IS named every unchecked token is
    exit 2 with a label naming its cause.
    """

    from waxseal.adapters.anchors import read_anchor_records
    from waxseal.domain.checkpoint import verify_checkpoint

    try:
        sidecar = read_anchor_records(trail)
    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        # The sidecar is as attacker-writable as the trail it anchors
        # (same threat model as attest.py's sidecar): malformed bytes are a
        # verdict, never a crash (fail-closed rule, verify_membership/
        # verify_checkpoint's own contract).
        return _Check(
            CheckSummary(ok=False, checked=0, reason="malformed_anchor"),
            "ANCHOR BROKEN: malformed_anchor",
        )

    records = sidecar.records
    if not records and not sidecar.unreadable_versions:
        # Absence is not failure (CLAUDE.md rule 5: unmeasured != 0/ok).
        return _Check(
            CheckSummary(ok=True, checked=0, reason="no_anchors_recorded"),
            "no anchors found (anchor coverage unmeasured)",
        )

    hashes = log.entry_hashes()
    for record in records:
        cp = record.checkpoint
        reason = verify_checkpoint(hashes, cp)
        if reason is not None:
            return _Check(
                CheckSummary(ok=False, checked=0, reason=reason),
                f"ANCHOR BROKEN at seq={cp.seq}: {reason}",
            )

    notes: list[str] = []
    receipts = [_receipt_verdict(record) for record in records]
    broken_receipt = next((r for r in receipts if r.status == _RECEIPT_BROKEN), None)
    if broken_receipt is not None:
        return _Check(
            CheckSummary(ok=False, checked=len(records), reason=broken_receipt.reason),
            f"ANCHOR BROKEN: {broken_receipt.note}",
        )
    notes.extend(r.note for r in receipts if r.note is not None)
    unverifiable_receipts = [r for r in receipts if r.status == _RECEIPT_UNVERIFIABLE]

    signature_checks = _signature_checks(records, tsa_ca_file)
    signature_verdict = Verdict.OK
    if tsa_ca_file is None:
        # Not engaged, so not part of the verdict -- but never silent either
        # (rule 6). One line, sourced from the adapter so the remedy it names
        # cannot drift from the one the engaged path prints.
        if signature_checks:
            notes.append(
                f"{len(signature_checks)} RFC 3161 receipt(s): {signature_checks[0][1].label}"
            )
    else:
        notes.extend(f"seq={seq}: {check.label}" for seq, check in signature_checks)
        for _, check in signature_checks:
            signature_verdict = signature_verdict.join(check.verdict)
        if signature_verdict is Verdict.BROKEN:
            broken_signature = next(
                check for _, check in signature_checks if check.verdict is Verdict.BROKEN
            )
            return _Check(
                CheckSummary(
                    ok=False,
                    checked=len(records),
                    reason=SIGNATURE_INVALID,
                    notes=tuple(notes),
                ),
                f"ANCHOR BROKEN: {broken_signature.label}",
            )

    bound = sum(1 for r in records if r.checkpoint.agg_commit is not None)
    if bound:
        # The CLI holds no seal key, so the chain-shape claim of a v2 record
        # is checked and its aggregate claim is not. Rule 6: an unperformed
        # check is stated, never left to look like a performed one.
        notes.append(
            f"{bound} record(s) carry a forward-secure aggregate binding, NOT checked "
            "here (no seal key available to the CLI — use "
            "AuditLog.verify_anchored_aggregates)"
        )
    if sidecar.unreadable_versions:
        versions = ", ".join(sorted(set(sidecar.unreadable_versions)))
        notes.append(
            f"{len(sidecar.unreadable_versions)} record(s) in an unreadable format "
            f"version ({versions}) — unverifiable by name, NOT evidence of tampering"
        )

    line = (
        f"anchors ok (checked={len(records)}, latest=seq {records[-1].checkpoint.seq})"
        if records
        else "no readable anchors found (anchor coverage unmeasured)"
    )
    for note in notes:
        line += f"\n  note: {note}"

    # Two different ways this build can lack coverage, both exit 2 and both
    # named: a record version it cannot read, and a receipt format it cannot
    # read. Neither is evidence of tampering.
    reason = None
    if sidecar.unreadable_versions:
        reason = "unreadable_record_version"
    elif unverifiable_receipts:
        reason = unverifiable_receipts[0].reason
    elif signature_verdict is Verdict.UNVERIFIABLE:
        # Engaged and unanswerable: the third way this build can lack
        # coverage, and the only one an operator can fix by installing
        # something. Still not evidence of tampering.
        reason = SIGNATURE_UNCHECKED
    return _Check(
        CheckSummary(
            ok=True,
            checked=len(records),
            reason=reason,
            unverifiable=bool(
                sidecar.unreadable_versions
                or unverifiable_receipts
                or signature_verdict is Verdict.UNVERIFIABLE
            ),
            notes=tuple(notes),
        ),
        line,
    )


def _signature_checks(
    records: Sequence[AnchorRecord], tsa_ca_file: Path | None
) -> list[tuple[int, SignatureCheck]]:
    """The signature dimension for every record carrying a readable RFC 3161
    receipt. A receipt whose base64 or DER this build cannot read is skipped:
    ``_receipt_verdict`` already reported it as unverifiable, and reporting it
    twice under two vocabularies would double-count one fact."""
    from waxseal.adapters.rfc3161_verify import verify_token_signature
    from waxseal.domain import rfc3161

    checks: list[tuple[int, SignatureCheck]] = []
    for record in records:
        receipt = record.receipt
        if receipt is None or not receipt.startswith(rfc3161.RECEIPT_PREFIX):
            continue
        der = rfc3161.decode_receipt(receipt)
        if der is None:
            continue
        checks.append((record.checkpoint.seq, verify_token_signature(der, ca_file=tsa_ca_file)))
    return checks


def _observed_anchor_sinks(trail: Path) -> int:
    """How many distinct EXTERNAL anchor sinks this run actually sees
    recorded in the `.anchors` sidecar: the "observed" half of a
    declared-vs-observed separation comparison (waxseal-7tk.3.2).

    ``"file"`` (``FileAnchorSink.name``) is excluded: it is the local
    baseline this same sidecar always carries, explicitly not an independent
    witness per this module's own docstring, so counting it would let a
    trail anchor "to itself" and still look separated. A second, small read
    of the sidecar rather than a refactor of ``_anchor_check`` to return this
    count too (cheap, and this codebase already tolerates the same
    duplication in ``_report``'s witness handling.

    A sidecar this build cannot parse yields ``0``, the same as an empty one:
    ``_anchor_check`` already reports the malformed sidecar as its own
    ANCHOR BROKEN finding, and an unreadable file is not evidence that any
    external sink exists.
    """

    from waxseal.adapters.anchors import read_anchor_records

    try:
        records = read_anchor_records(trail).records
    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        return 0
    return len({r.sink for r in records if r.sink != "file"})


def _observed_anchor_records(trail: Path) -> tuple[AnchorRecord, ...]:
    """The `.anchors` sidecar's own records, for the ``anchor_staleness``
    comparison ``_pin_check`` runs against a declared ``max_anchor_age_s``
    (waxseal-7tk.4.1). A third read of the sidecar in this same call is
    accepted duplication in this codebase, per ``_observed_anchor_sinks``'s
    own docstring, not a refactor forced on this bead.

    A sidecar this build cannot parse yields ``()``, same treatment
    ``_observed_anchor_sinks`` gives it: ``_anchor_check`` already reports
    the malformed sidecar as its own ANCHOR BROKEN finding (exit 1), so this
    value only matters when that dimension is otherwise clean.
    """

    from waxseal.adapters.anchors import read_anchor_records

    try:
        return read_anchor_records(trail).records
    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        return ()


def _observed_anchor_unreadable(trail: Path) -> bool:
    """Whether the `.anchors` sidecar held any record in a format this build
    cannot read at all, for the ``anchor_policy_downgrade`` comparison
    (waxseal-7tk.5.1, W5/F2). A fourth read of the sidecar in this same
    call is accepted duplication in this codebase, per
    ``_observed_anchor_sinks``'s own docstring.

    A sidecar this build cannot even parse as JSON is the OPPOSITE case from
    ``_observed_anchor_sinks``/``_observed_anchor_records``: those two feed
    comparisons that only matter once the trail's anchor dimension is
    otherwise clean, so "0"/"()" is a safe default because ``_anchor_check``
    already reports the parse failure as its own ANCHOR BROKEN (exit 1)
    finding. This value feeds a DIFFERENT question, "can we say there is
    truly no binding", and catastrophic parse failure is the strongest
    possible instance of "cannot corroborate": a whole sidecar this build
    could not read might just as easily have carried a binding as not.
    Returning ``True`` here is the conservative (rule 5) choice, even though
    in practice the run's exit code is already forced to 1 by
    ``_anchor_check`` in that same case, making this value moot for the
    combined exit code, it still keeps this helper's own answer honest.
    """

    from waxseal.adapters.anchors import read_anchor_records

    try:
        return bool(read_anchor_records(trail).unreadable_versions)
    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        return True


_RECEIPT_CHECKED: Final = "checked"
_RECEIPT_BROKEN: Final = "broken"
_RECEIPT_UNVERIFIABLE: Final = "unverifiable"
_RECEIPT_NOTED: Final = "noted"
_RECEIPT_ABSENT: Final = "absent"


@dataclass(frozen=True, slots=True)
class _ReceiptVerdict:
    status: str
    note: str | None = None
    reason: str | None = None


def _receipt_verdict(record: AnchorRecord) -> _ReceiptVerdict:
    """What this build can say about one anchor record's receipt.

    Five outcomes, and the distinctions between them are the whole point:

    - ``absent``    the record carries no receipt at all (FileAnchorSink has
      none to give). Nothing was claimed, so nothing is checked or faulted.
    - ``checked``   an RFC 3161 token that structurally attests this exact
      checkpoint frame. Still not "genuine": the CMS signature is delegated
      (domain/rfc3161.py), and the printed line says so.
    - ``broken``    a token that attests OTHER bytes. Checked and false.
    - ``unverifiable`` a token this build cannot read, or a receipt prefix
      from a newer waxseal. Unknown formats are opaque, not errors
      (RFC 6962 section 4.6).
    - ``noted``     an OpenTimestamps proof, opaque by design and labelled
      as such. Deliberately does NOT raise the exit code: an operator who
      anchors to a calendar would otherwise see exit 2 on every healthy verify
      and learn to ignore it, which costs more than it buys.
    """
    from waxseal.domain import ots, rfc3161
    from waxseal.domain.checkpoint import checkpoint_frame

    receipt = record.receipt
    seq = record.checkpoint.seq
    if receipt is None:
        return _ReceiptVerdict(_RECEIPT_ABSENT)

    if receipt.startswith(rfc3161.RECEIPT_PREFIX):
        der = rfc3161.decode_receipt(receipt)
        if der is None:
            return _ReceiptVerdict(
                _RECEIPT_UNVERIFIABLE,
                note=(
                    f"seq={seq}: RFC 3161 receipt is not readable by this build "
                    f"({rfc3161.MALFORMED_TOKEN}) — unverifiable by name, NOT evidence "
                    "of tampering"
                ),
                reason=rfc3161.MALFORMED_TOKEN,
            )
        frame = checkpoint_frame(record.checkpoint)
        # expected_nonce comes from the record when the sink stored one;
        # None (every record written before the field existed) skips the
        # comparison rather than failing it, since absence is not a mismatch.
        token, why = rfc3161.read_timestamp_resp(der, frame, expected_nonce=record.nonce)
        if token is not None:
            return _ReceiptVerdict(
                _RECEIPT_CHECKED,
                note=(
                    f"seq={seq}: attested time (RFC 3161, structural only — signature "
                    f"NOT verified): {token.gen_time_iso}"
                ),
            )
        if why in _RECEIPT_CHECKED_FALSE:
            return _ReceiptVerdict(
                _RECEIPT_BROKEN,
                note=(
                    f"seq={seq}: the RFC 3161 receipt attests different bytes than the "
                    f"record beside it ({why}) — note the signature itself is still "
                    "unverified here"
                ),
                reason=why,
            )
        return _ReceiptVerdict(
            _RECEIPT_UNVERIFIABLE,
            note=(
                f"seq={seq}: RFC 3161 receipt is not readable by this build ({why}) — "
                "unverifiable by name, NOT evidence of tampering"
            ),
            reason=why,
        )

    if receipt.startswith(ots.RECEIPT_PREFIX):
        return _ReceiptVerdict(_RECEIPT_NOTED, note=f"seq={seq}: {ots.PENDING_NOTE}")

    prefix = receipt.split(":", 1)[0]
    return _ReceiptVerdict(
        _RECEIPT_UNVERIFIABLE,
        note=(
            f"seq={seq}: receipt type {prefix!r} is unknown to this build — "
            "unverifiable by name, NOT evidence of tampering"
        ),
        reason="unknown_receipt_type",
    )


def _witness_verdicts(log: AuditLog, urls: list[str]) -> list[WitnessVerdict]:
    """Ask every configured witness what it saw and compare.

    An unreachable or unusable witness becomes an ``unreachable`` verdict
    rather than an exception: one notary being down must not deny the audit
    the other two would have provided. It is never silent: the caller prints
    every verdict, including this one.
    """
    from waxseal.adapters.witness import HTTPWitness
    from waxseal.domain.witnessing import check_witnessed, unreachable_witness

    hashes = log.entry_hashes()
    verdicts: list[WitnessVerdict] = []
    for url in urls:
        witness = HTTPWitness(url, api_key=_witness_api_key())
        try:
            observation = witness.fetch()
        except (OSError, RemoteError) as e:
            verdicts.append(unreachable_witness(witness.name, reason=str(e)))
            continue
        verdicts.append(check_witnessed(hashes, observation, name=witness.name))
    return verdicts


def _witness_line(verdict: WitnessVerdict) -> str:
    from waxseal.domain.witnessing import WITNESS_INCONSISTENT, WITNESS_UNREACHABLE

    if verdict.status == WITNESS_UNREACHABLE:
        # Rule 5 one layer up: a check that did not run is not a check that
        # passed, and not a break either. It contributes exit 2
        # (unverifiable), the same verdict an unknown fingerprint gets, for
        # the same reason (SPEC.md section 14).
        return (
            f"witness {verdict.name}: unreachable ({verdict.reason}) — NOT checked; "
            "an unreachable witness is never a pass"
        )
    if verdict.status == WITNESS_INCONSISTENT:
        return (
            f"witness {verdict.name}: INCONSISTENT at seq={verdict.broken_seq}: "
            f"{verdict.reason} — the local trail does not extend what this witness "
            "saw, which is evidence of split-view or a rewritten history"
        )
    line = f"witness {verdict.name}: consistent (checked={verdict.checked})"
    if verdict.reason is not None:
        line += f" — {verdict.reason}: this witness holds nothing, so it covers nothing"
    if verdict.unreadable:
        line += (
            f"\n  note: {verdict.unreadable} record(s) this build could not read — "
            "coverage this run did not measure"
        )
    return line


def _witness_exit_code(verdicts: list[WitnessVerdict]) -> int:
    from waxseal.domain.witnessing import WITNESS_INCONSISTENT, WITNESS_UNREACHABLE

    # Inconsistency is evidence of a split view, a break (1). A witness that
    # could not be asked is coverage this run does not have: unverifiable (2),
    # never a pass and never conflated with tampering (SPEC.md section 14).
    # _combine keeps "1 beats 2" when another dimension found a real break.
    if any(v.status == WITNESS_INCONSISTENT for v in verdicts):
        return 1
    if any(v.status == WITNESS_UNREACHABLE for v in verdicts):
        return 2
    return 0


def _observed_witness_consistent(verdicts: list[WitnessVerdict]) -> bool:
    """Whether this run reached at least one witness that returned a
    ``consistent`` verdict: the "observed" half of a declared-vs-observed
    separation comparison (waxseal-7tk.3.2). An ``unreachable`` or
    ``inconsistent`` witness does not count: neither is a witness this run
    actually confirmed agreement with.
    """
    from waxseal.domain.witnessing import WITNESS_CONSISTENT

    return any(v.status == WITNESS_CONSISTENT for v in verdicts)


def _observed_ledger_ok(check: _Check) -> bool:
    """Whether this run's ledger check (waxseal-fg4.45, F4's
    ``--rpc``/``--liveness``/``--registry``) corroborated the declared
    ledger authority: the "observed" half of a declared-vs-observed
    separation comparison, the ledger dimension's own
    ``_observed_witness_consistent``. Only ``Verdict.OK`` counts — a
    delinquent liveness finding, a registry disagreement, AND an
    unreachable RPC endpoint (``_ledger_check`` can never itself distinguish
    the last from the first two; all three land on ``Verdict.UNVERIFIABLE``,
    see that function's docstring) all fold to ``False`` here, the same
    precedent set for an unreachable-vs-inconsistent witness: neither is a
    ledger this run actually confirmed agreement with. The caller decides
    whether this dimension was measured AT ALL this run (``None`` when
    neither flag was given) — this function is only ever called once that
    is already known to be true.
    """
    return check.verdict is Verdict.OK


def _witness_api_key() -> str | None:
    # Same rule as the chain backend: credentials come from the environment,
    # never from argv (where they would land in shell history and `ps`).
    # Deliberately NOT WAXSEAL_API_KEY: that is the chain server's WRITE
    # credential, and REMOTE.md section 8 puts a witness under a different
    # administrative authority: a witness handed the chain key could append
    # forged entries to the very chain it exists to cross-check.

    return os.environ.get("WAXSEAL_WITNESS_API_KEY")
