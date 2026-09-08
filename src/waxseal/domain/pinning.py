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
from dataclasses import dataclass
from typing import Any, Final

from waxseal.domain._pinning_checks import (
    ANCHOR_BINDING_UNREADABLE,
    ANCHOR_POLICY_DOWNGRADE,
    ANCHOR_STALE,
    ANCHOR_TIMESTAMP_UNPARSEABLE,
    anchor_policy_downgrade,
    anchor_staleness,
    check_pin,
)
from waxseal.domain.checkpoint import Checkpoint
from waxseal.domain.separation import SeparationTopology

__all__ = (
    "ANCHOR_BINDING_UNREADABLE",
    "ANCHOR_POLICY_DOWNGRADE",
    "ANCHOR_STALE",
    "ANCHOR_TIMESTAMP_UNPARSEABLE",
    "PIN_STATE_VERSION",
    "PinMalformed",
    "PinState",
    "PinStateError",
    "PinVersionUnknown",
    "anchor_policy_downgrade",
    "anchor_staleness",
    "check_pin",
    "check_pin_target",
    "parse_pin_state",
    "render_pin_state",
)

PIN_STATE_VERSION: Final = 1


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

    ``declared_topology.ledger`` (waxseal-fg4.45) nests the SAME
    omit-when-undeclared rule one level down, inside the object the four
    original subfields already write unconditionally: those four are
    required together and always present when ``declared_topology`` is at
    all, but ``ledger`` is ``bool | None`` on its own (see
    ``SeparationTopology``'s docstring), so it is written only when it is
    not ``None`` — an older topology that never declared it must round-trip
    through save/load without ever growing a ``"ledger": false`` this
    module invented.
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
        topology_obj: dict[str, Any] = {
            "seal_escrow": state.declared_topology.seal_escrow,
            "anchor_sinks": state.declared_topology.anchor_sinks,
            "witness": state.declared_topology.witness,
            "pin_separate": state.declared_topology.pin_separate,
        }
        if state.declared_topology.ledger is not None:
            topology_obj["ledger"] = state.declared_topology.ledger
        obj["declared_topology"] = topology_obj
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


def _optional_bool_or_none(obj: dict[str, Any], key: str) -> bool | None:
    """Like ``_optional_bool``, but absence means "never declared", not a
    caller-supplied meaningful default — ``SeparationTopology.ledger``'s own
    convention (see its docstring), distinct from ``expect_anchor_binding``'s
    plain-bool-with-a-real-default one that ``_optional_bool`` above serves.
    """
    value = obj.get(key)
    if value is None:
        return None
    if not isinstance(value, bool):
        raise PinMalformed(f"pin state field {key!r} must be a boolean, got {value!r}")
    return value


def _optional_topology(obj: dict[str, Any], key: str) -> SeparationTopology | None:
    """The whole ``declared_topology`` object is optional, but never partial.

    Key absent: ``None``, meaning "not declared", the ordinary case for every pin
    state written before this field existed, unchanged by this bead. Key
    present: all four ORIGINAL subfields are required together, each
    validated with the same discipline as every other pin field, since a
    partially-present object (e.g. missing ``pin_separate``) is malformed,
    never silently defaulted, because a defaulted field here would be
    indistinguishable from an operator who actually declared it that way.

    ``ledger`` (waxseal-fg4.45) is deliberately NOT a fifth required
    subfield here: it was added after SPEC 13.1's "all four together" shape
    had already shipped, so requiring it now would turn every
    ``declared_topology`` written by an older waxseal into ``malformed_pin``
    on its very next read — the exact append-only violation this bead's
    OWNER DECISION forbids. It is read with ``_optional_bool_or_none``
    instead: absent (every pre-fg4.45 topology, and any topology that still
    does not mention it) parses as ``None``, "never declared", never as
    ``False``.
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
        ledger=_optional_bool_or_none(value, "ledger"),
    )
