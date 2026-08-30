"""Pinned-head verification: the verifier's own memory of what it already saw.

A hash chain is self-consistent by construction. Recomputing it proves the
links hold; it cannot prove that the history being served today is the history
that was served yesterday, because a writer who can rewrite the whole trail can
re-hash it into a different, equally self-consistent past. That is the blind
spot an attacker-writable disk and a Byzantine chain server share.

A pin closes it the way SSH's ``known_hosts`` does: the first look is trusted
(and labelled as such, since trust-on-first-use is an assumption, not a check), and
every look after that is compared against what was recorded. The recorded thing
is an ordinary ``Checkpoint``, so the comparison is ``verify_checkpoint`` and
this module adds no new cryptography, only a vocabulary, because "the anchor
sidecar disagrees" and "the history I personally confirmed has changed" are
different findings for an operator even when the arithmetic is identical.

The pin's value comes entirely from WHERE it is kept. Under the same authority
as the trail it describes, it is one more file the same attacker rewrites; the
security argument is separation, and this module cannot enforce it.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Final

from waxseal.domain.checkpoint import Checkpoint, verify_checkpoint
from waxseal.domain.separation import SeparationTopology

PIN_STATE_VERSION: Final = 1

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


class PinStateError(Exception):
    """A stored pin state that could not be used as one."""


class PinMalformed(PinStateError):
    """Not a pin state this build can read at all.

    Treated as a break rather than a downgrade to first-use: re-pinning over
    an unreadable state is exactly the move an attacker wants after rewriting
    a trail, and "the file was corrupt so I trusted whatever I was served" is
    not a check.
    """


class PinVersionUnknown(PinStateError):
    """A pin state from a newer waxseal.

    Unverifiable BY NAME: this build cannot know what a future version's
    fields mean, and guessing would be the migration-060 mistake. Deliberately
    NOT a subclass of PinMalformed: the two get different exit codes, and one
    catch clause covering both would hand a forward-compatible state the
    tampering verdict.
    """


@dataclass(frozen=True, slots=True)
class PinState:
    """What a verifier remembers about one trail.

    ``target`` and ``chain_id`` identify what was pinned, so a state file
    pointed at a different trail is refused instead of silently compared.
    ``pinned_ts`` is informative only. It is not part of any hashed frame,
    and nothing here trusts it.

    ``declared_topology`` is a trailing optional field, the same pattern
    ``VerifyResult.drops_source`` uses: adding it does not break any existing
    construction site. ``None`` means "this pin never declared a separation
    topology", the ordinary case for every pin state written before this
    field existed, and still the default for one written after. It is
    NOT the same as a topology whose values happen to be the smallest
    possible ones (rule 5, applied to this module's own state).

    ``max_anchor_age_s`` is a second trailing-optional field, same pattern
    again: ``None`` means "this pin never declared a silence deadline",
    every pin state before this bead, and still the default afterward.
    W4/C3 (beads-v1.2.2 class, applied to anchor coverage going quiet
    rather than to a schema version): a declared deadline with no fresh
    `.anchors` record to show for it is itself the finding, not a value to
    infer from wall-clock arithmetic no one asked for.

    ``expect_anchor_binding`` is a THIRD trailing field, but simpler than
    the two above: it is a POLICY SWITCH (did the operator ask for the F2
    check to run), not a factual claim about the world, so there is no
    meaningful difference between "never declared" and "declared off",
    both mean "don't run this check". A plain ``bool`` defaulting to
    ``False`` is correct and sufficient; it does NOT need the
    ``None``-means-"undeclared" convention the two fields above use. See
    ``anchor_policy_downgrade`` for the check itself (W5/F2).
    """

    target: str
    chain_id: str | None
    checkpoint: Checkpoint
    pinned_ts: str
    declared_topology: SeparationTopology | None = None
    max_anchor_age_s: int | None = None
    expect_anchor_binding: bool = False


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


def check_pin_target(state: PinState, *, target: str, chain_id: str | None) -> str | None:
    """Confirm the pin describes the trail about to be checked.

    A mismatch is neither a pass nor a tampering finding. It means the
    operator pointed a pin at something else. Returns ``pin_target_mismatch``
    so the caller can say so and stop, rather than comparing two unrelated
    histories or overwriting a pin that was never about this trail.
    """
    if state.target != target or state.chain_id != chain_id:
        return "pin_target_mismatch"
    return None


def render_pin_state(state: PinState) -> str:
    """Canonical JSON for a pin state file.

    ``chain_id`` is written as an explicit ``null`` rather than omitted, for
    the reason the decision record uses the same rule: a reader must be able
    to tell "not applicable" from "a key someone dropped". ``declared_topology``
    follows the opposite convention deliberately: its absence IS the "not
    declared" signal (rule 5 again: undeclared must never render as a
    present-but-empty value), so the key itself is omitted rather than
    written as ``null``, and only appears when a topology was actually given.
    ``expect_anchor_binding`` follows neither convention: it is a plain
    boolean with a real, meaningful default (``False``), so it is always
    written explicitly, never omitted and never a special-cased ``null``.
    """
    obj: dict[str, Any] = {
        "v": PIN_STATE_VERSION,
        "target": state.target,
        "chain_id": state.chain_id,
        "seq": state.checkpoint.seq,
        "entry_hash": state.checkpoint.entry_hash,
        "root": state.checkpoint.root,
        "pinned_ts": state.pinned_ts,
        "expect_anchor_binding": state.expect_anchor_binding,
    }
    if state.declared_topology is not None:
        obj["declared_topology"] = {
            "seal_escrow": state.declared_topology.seal_escrow,
            "anchor_sinks": state.declared_topology.anchor_sinks,
            "witness": state.declared_topology.witness,
            "pin_separate": state.declared_topology.pin_separate,
        }
    if state.max_anchor_age_s is not None:
        # A plain scalar, unlike declared_topology's nested object, so there is
        # only one number to declare, not a group of fields that must arrive
        # together. Same omit-when-absent convention: undeclared must never
        # render as a present zero (rule 5).
        obj["max_anchor_age_s"] = state.max_anchor_age_s
    return json.dumps(obj, indent=2, sort_keys=True)


def parse_pin_state(text: str) -> PinState:
    """Read a pin state file.

    Raises ``PinVersionUnknown`` for a version this build does not implement
    and ``PinMalformed`` for anything else it cannot read. Unknown extra keys
    within a known version are ignored, for forward compatibility inside a
    version, which is a different question from an unknown version.
    """
    try:
        obj = json.loads(text)
    except (ValueError, TypeError) as e:
        raise PinMalformed(f"pin state is not JSON: {e}") from e
    if not isinstance(obj, dict):
        raise PinMalformed(f"pin state must be a JSON object, got {type(obj).__name__}")

    version = obj.get("v")
    if not isinstance(version, int) or isinstance(version, bool):
        raise PinMalformed(f"pin state version must be an integer, got {version!r}")
    if version != PIN_STATE_VERSION:
        raise PinVersionUnknown(
            f"pin state version {version} is not {PIN_STATE_VERSION}: this build "
            "cannot check it, which is not evidence of tampering"
        )

    return PinState(
        target=_require_str(obj, "target"),
        chain_id=_optional_str(obj, "chain_id"),
        checkpoint=Checkpoint(
            seq=_require_int(obj, "seq"),
            entry_hash=_require_str(obj, "entry_hash"),
            root=_require_str(obj, "root"),
        ),
        pinned_ts=_require_str(obj, "pinned_ts"),
        declared_topology=_optional_topology(obj, "declared_topology"),
        max_anchor_age_s=_optional_int(obj, "max_anchor_age_s"),
        expect_anchor_binding=_optional_bool(obj, "expect_anchor_binding", False),
    )


def _require_str(obj: dict[str, Any], key: str) -> str:
    value = obj.get(key)
    if not isinstance(value, str):
        raise PinMalformed(f"pin state field {key!r} must be a string, got {value!r}")
    return value


def _optional_str(obj: dict[str, Any], key: str) -> str | None:
    value = obj.get(key)
    if value is None or isinstance(value, str):
        return value
    raise PinMalformed(f"pin state field {key!r} must be a string or null, got {value!r}")


def _require_int(obj: dict[str, Any], key: str) -> int:
    value = obj.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise PinMalformed(f"pin state field {key!r} must be an integer, got {value!r}")
    return value


def _optional_int(obj: dict[str, Any], key: str) -> int | None:
    value = obj.get(key)
    if value is None:
        return None
    # Same isinstance(value, bool) exclusion _require_int uses: a JSON
    # true/false must never be silently accepted as an int.
    if not isinstance(value, int) or isinstance(value, bool):
        raise PinMalformed(f"pin state field {key!r} must be an integer or null, got {value!r}")
    return value


def _require_bool(obj: dict[str, Any], key: str) -> bool:
    value = obj.get(key)
    if not isinstance(value, bool):
        raise PinMalformed(f"pin state field {key!r} must be a boolean, got {value!r}")
    return value


def _optional_bool(obj: dict[str, Any], key: str, default: bool) -> bool:
    value = obj.get(key)
    if value is None:
        # Key absent (every pin file written before this field existed) or
        # explicit null: both fall back to `default`, the same treatment
        # `_optional_str`/`_optional_int` give absence in this file already.
        return default
    if not isinstance(value, bool):
        raise PinMalformed(f"pin state field {key!r} must be a boolean, got {value!r}")
    return value


def _optional_topology(obj: dict[str, Any], key: str) -> SeparationTopology | None:
    """The whole ``declared_topology`` object is optional, but never partial.

    Key absent: ``None``, meaning "not declared", the ordinary case for every pin
    state written before this field existed, unchanged by this bead. Key
    present: all four subfields are required together, each validated with
    the same discipline as every other pin field, since a partially-present
    object (e.g. missing ``pin_separate``) is malformed, never silently
    defaulted, because a defaulted field here would be indistinguishable
    from an operator who actually declared it that way.
    """
    value = obj.get(key)
    if value is None:
        return None
    if not isinstance(value, dict):
        raise PinMalformed(f"pin state field {key!r} must be an object, got {value!r}")
    return SeparationTopology(
        seal_escrow=_require_bool(value, "seal_escrow"),
        anchor_sinks=_require_int(value, "anchor_sinks"),
        witness=_require_bool(value, "witness"),
        pin_separate=_require_bool(value, "pin_separate"),
    )


# reason strings anchor_staleness returns, never "anchor_root_mismatch" or
# any other name a genuine tamper finding already uses, per this module's own
# rule (see _REASONS above) that a pin-side vocabulary must not collide with
# the sidecar-comparison vocabulary an operator would go looking for instead.
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
