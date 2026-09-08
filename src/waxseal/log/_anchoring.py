"""Aggregate and anchor-sink helpers. Receives dependencies as arguments."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from waxseal.domain.sealing import AttestResult, aggregate_commit, verify_anchored_aggregate


def maybe_record_anchor_sink(anchor_sink: Any, trail_path: Path | None) -> Any:
    """Wrap an external sink so library callers file the sidecar too.

    The README-advertised pattern (open + external sink +
    anchor_every) contacted the TSA and DISCARDED every returned
    receipt. Only the CLI wrapped sinks in RecordingAnchorSink, so
    library callers paid for evidence that landed nowhere. Wrap here,
    at the one seam open() and with_anchor_sink() both pass through.
    Sinks that already write the sidecar (RecordingAnchorSink,
    FileAnchorSink, and MultiAnchorSink (waxseal-4yk, which fans a
    checkpoint out to several RecordingAnchorSinks of its own) must
    not be wrapped again: a double-filed checkpoint would overstate
    anchor coverage. Path-less backends (memory, remote) have no
    sidecar location and keep the sink as given. Deferred import,
    same as verify_anchored_aggregates.
    """
    if anchor_sink is None or trail_path is None:
        return anchor_sink
    from waxseal.adapters.anchors import (
        FileAnchorSink,
        MultiAnchorSink,
        RecordingAnchorSink,
    )

    if not isinstance(anchor_sink, (FileAnchorSink, RecordingAnchorSink, MultiAnchorSink)):
        return RecordingAnchorSink(trail_path, anchor_sink)
    return anchor_sink


def aggregate_binding(aggregate_source: Any) -> tuple[str | None, int | None]:
    """The forward-secure aggregate commitment to include in a checkpoint.

    ``(None, None)`` whenever there is no accumulator to commit to: no
    aggregate source at all (the default, since an attestor only becomes
    one by keeping an accumulator), a source that exposes no
    ``read_aggregate``, or one whose ``read_aggregate`` returns None
    because nothing has aggregated yet. A checkpoint must not claim a
    binding that nothing can be checked against, and most trails have none.

    Only the commitment leaves this method. The accumulator itself is
    never published: an attacker who can copy an intermediate value can
    restore it over a truncated trail, which is the hole the aggregate
    scheme exists to close.
    """
    read_aggregate = getattr(aggregate_source, "read_aggregate", None)
    if read_aggregate is None:
        return (None, None)
    try:
        state = read_aggregate()
    except (ValueError, KeyError, TypeError) as e:
        # `.sealagg` is attacker-writable by the same threat model as the
        # keyfile (attest.py's module docstring). verify_attestations
        # already turns this into "malformed_aggregate"; anchor() is a
        # write path so it can only refuse, but CLAUDE.md rule 6 still
        # requires the refusal be labelled, and a bare JSONDecodeError three
        # frames down is indistinguishable from an unrelated bug, unlike
        # attest.py's own epoch-desync RuntimeError.
        raise RuntimeError(
            "'.sealagg' sidecar is malformed; cannot bind an aggregate "
            "commitment for this anchor — operator decision required"
        ) from e
    if state is None:
        return (None, None)
    _, epoch, agg = state
    return (aggregate_commit(epoch, agg), epoch)


def verify_anchored_aggregates(
    attestor: Any,
    aggregate_source: Any,
    *,
    initial_key: bytes,
) -> AttestResult:
    """Check every anchored aggregate commitment against the attestations.

    The check the local sidecars cannot make. ``verify_attestations``
    compares `.sealagg` against `.attest`, both under whoever owns the
    trail, so an attacker who truncates the trail and restores an older
    accumulator satisfies it. The commitments here come from anchor
    records a third party witnessed, so passing this requires not having
    rewritten what that third party holds.

    Anchor records with no binding (every record written before it
    existed, and every trail that never aggregated) are counted
    ``unverifiable``: no aggregate claim was made, so there is none to
    check, and calling that a pass would report coverage nobody has.
    """
    read_aggregate = getattr(aggregate_source, "read_aggregate", None)
    agg_start = 0
    if read_aggregate is not None:
        state = read_aggregate()
        if state is not None:
            agg_start = state[0]

    from waxseal.adapters.anchors import read_anchor_records

    try:
        sidecar = read_anchor_records(attestor.trail_path)
    except (ValueError, KeyError, TypeError):
        # Attacker-writable sidecar: malformed bytes are a verdict, never
        # a crash that denies the audit (same contract as verify_seals).
        return AttestResult(
            ok=False,
            checked=0,
            broken_seq=None,
            reason="malformed_anchor",
            unverifiable=(),
        )

    if not sidecar.records and not sidecar.unreadable_versions:
        return AttestResult(
            ok=True, checked=0, broken_seq=None, reason="no_anchors_recorded", unverifiable=()
        )

    attestations = list(attestor.attestations())
    checked = 0
    unverifiable: list[int] = []
    for record in sidecar.records:
        cp = record.checkpoint
        if cp.agg_commit is None or cp.agg_epoch is None:
            unverifiable.append(cp.seq)
            continue
        reason = verify_anchored_aggregate(
            attestations,
            initial_key,
            agg_start=agg_start,
            anchored_epoch=cp.agg_epoch,
            anchored_commit=cp.agg_commit,
        )
        if reason is not None:
            return AttestResult(
                ok=False,
                checked=checked,
                broken_seq=cp.seq,
                reason=reason,
                unverifiable=tuple(unverifiable),
            )
        checked += 1
    # A record in a format this build cannot read is coverage it does not
    # have, and saying so is the whole of rule 6. `verify --anchors` names
    # it with this same string; two paths reading one sidecar must not
    # come back with two different accounts of it.
    return AttestResult(
        ok=True,
        checked=checked,
        broken_seq=None,
        reason="unreadable_record_version" if sidecar.unreadable_versions else None,
        unverifiable=tuple(unverifiable),
    )
