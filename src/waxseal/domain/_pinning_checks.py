"""Pin policy checks. PinState parse/render stay on pinning.py."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Final

from waxseal.domain.checkpoint import Checkpoint, verify_checkpoint

# verify_checkpoint's vocabulary is about an anchor sidecar. The same failure
# means something else when the claimant is the verifier's own past self, and
# an operator reading "anchor_root_mismatch" from a --pin check would go
# looking for a sidecar that is not involved.
_REASONS: Final = {
    "malformed_checkpoint": "malformed_pin",
    "anchor_beyond_head": "pin_beyond_head",
    "anchor_entry_hash_mismatch": "pin_mismatch",
    "anchor_root_mismatch": "pin_mismatch",
}


def check_pin(entry_hashes: list[str] | tuple[str, ...], pin: Checkpoint) -> str | None:
    """Check the trail against a previously pinned checkpoint.

    Returns ``None`` when the pinned prefix is still exactly what it was, else
    ``malformed_pin``, ``pin_beyond_head`` (the trail is shorter than what was
    already confirmed, a rollback or truncation), or ``pin_mismatch`` (the
    confirmed history has been rewritten). Never raises: a pin check runs on
    input an attacker may control.
    """
    reason = verify_checkpoint(entry_hashes, pin)
    if reason is None:
        return None
    # Every verify_checkpoint reason is mapped explicitly; a new one added
    # there must be given a pin-side meaning rather than leaking through.
    return _REASONS.get(reason, "malformed_pin")


# A pin-side vocabulary must not collide with the sidecar-comparison
# vocabulary an operator would go looking for instead (see _REASONS above).
ANCHOR_STALE: Final = "anchor_stale"
ANCHOR_TIMESTAMP_UNPARSEABLE: Final = "anchor_timestamp_unparseable"


def anchor_staleness(
    max_age_s: int,
    records: Sequence[tuple[int, str]],
    *,
    now: datetime,
) -> str | None:
    """Decide whether the most recent (highest checkpoint seq) external
    anchor record is within ``max_age_s`` of ``now``.

    ``records`` is ``(checkpoint.seq, ts)`` pairs rather than
    ``AnchorRecord`` objects: ``AnchorRecord`` lives in
    ``adapters/anchors.py``, and ``domain/`` must not import ``adapters/``
    (CLAUDE.md's layer DAG, enforced by
    ``tests/architecture/test_invariants.py::TestDomainPurity``). Plain
    ``(seq, ts)`` pairs keep this function pure and importable from
    anywhere without smuggling an adapter type across that boundary.

    Returns ``None`` (not stale) when the newest record's timestamp parses
    and is within the deadline. Returns a reason string otherwise:

    - ``anchor_stale`` when there ARE records but the newest is older than
      ``max_age_s``, OR when there are NO records at all, since absence of
      anchoring evidence is itself staleness ("vắng anchor = vắng bằng
      chứng"; W4/C3).
    - ``anchor_timestamp_unparseable`` when the newest record exists but its
      ``ts`` cannot be parsed as an ISO-8601 datetime (or does not compare
      against ``now``, e.g. a naive value next to an aware ``now``). This
      is unverifiable-by-name (a storage/format problem), never conflated
      with ``anchor_stale`` (a temporal fact) or read as "not stale" (rule
      5: a value this build cannot interpret must never render as evidence
      of freshness).

    "Most recent" is decided by the greatest ``checkpoint.seq``, an
    anchoring event's position in the trail's own history, never by
    wall-clock string comparison, which can mislead across differently
    formatted timestamps.

    Never raises: called on attacker-writable sidecar data, the same
    fail-closed discipline ``verify_checkpoint``/``verify_membership``
    already hold to.
    """
    if not records:
        return ANCHOR_STALE
    _, newest_ts = max(records, key=lambda r: r[0])
    try:
        moment = datetime.fromisoformat(newest_ts)
        age_s = (now - moment).total_seconds()
    except (ValueError, TypeError):
        # ValueError: not ISO-8601 at all. TypeError: parsed but naive/aware
        # mismatch against `now` makes the subtraction itself refuse, still
        # a format problem this build cannot interpret, not a temporal fact.
        return ANCHOR_TIMESTAMP_UNPARSEABLE
    if age_s > max_age_s:
        return ANCHOR_STALE
    return None


# Same collision rule ANCHOR_STALE/ANCHOR_TIMESTAMP_UNPARSEABLE follow: never
# reuse a genuine tamper-finding name (see _REASONS above).
ANCHOR_POLICY_DOWNGRADE: Final = "anchor_policy_downgrade"
ANCHOR_BINDING_UNREADABLE: Final = "anchor_binding_unreadable"


def anchor_policy_downgrade(
    pinned_seq: int,
    records: Sequence[tuple[int, str | None]],
    *,
    any_unreadable: bool,
) -> str | None:
    """Decide whether an aggregate binding (SPEC §15) that was expected is
    actually present in the anchor sidecar, at or after the pinned seq.

    ``records`` is ``(checkpoint.seq, checkpoint.agg_commit)`` pairs -- plain
    values, not ``AnchorRecord`` objects, for the same layer-boundary reason
    ``anchor_staleness`` takes plain tuples (``domain/`` must not import
    ``adapters/``). ``agg_commit`` is ``None`` for a v1-shaped record (no
    binding at all) and a non-``None`` string for a v2 record carrying the
    aggregate commitment.

    Returns ``None`` (no downgrade) when at least one record at or after
    ``pinned_seq`` has a non-``None`` ``agg_commit``. Returns a reason string
    otherwise:

    - ``anchor_binding_unreadable`` when ``any_unreadable`` is ``True``: some
      sidecar records were in a format this build cannot read at all, so "no
      binding found among the readable ones" is NOT evidence there is truly
      no binding -- an unreadable record might have carried one. Rule 5:
      unreadable must never collapse into "confirmed absent", the exact
      distinction this bead's own notes call out ("unreadable_versions khong
      rong -> unverifiable, khong duoc doc thanh khong-co-binding").
    - ``anchor_policy_downgrade`` when every readable record was inspected
      (``any_unreadable`` is ``False``) and none at or after ``pinned_seq``
      carries a binding -- the actual F2 finding: an attacker controlling
      the sidecar can silently present only v1-shaped records and strip
      SPEC §15's replay-plus-truncate protection.

    Never raises: called on attacker-writable sidecar data, same
    fail-closed discipline as ``anchor_staleness``/``verify_checkpoint``.
    """
    if any(seq >= pinned_seq and agg is not None for seq, agg in records):
        return None
    if any_unreadable:
        return ANCHOR_BINDING_UNREADABLE
    return ANCHOR_POLICY_DOWNGRADE
