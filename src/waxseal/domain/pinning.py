"""Pinned-head verification: the verifier's own memory of what it already saw.

A hash chain is self-consistent by construction. Recomputing it proves the
links hold; it cannot prove that the history being served today is the history
that was served yesterday, because a writer who can rewrite the whole trail can
re-hash it into a different, equally self-consistent past. That is the blind
spot an attacker-writable disk and a Byzantine chain server share.

A pin closes it the way SSH's ``known_hosts`` does: the first look is trusted
(and labelled as such — trust-on-first-use is an assumption, not a check), and
every look after that is compared against what was recorded. The recorded thing
is an ordinary ``Checkpoint``, so the comparison is ``verify_checkpoint`` and
this module adds no new cryptography — only a vocabulary, because "the anchor
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

from waxseal.domain.checkpoint import Checkpoint, verify_checkpoint

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

    Unverifiable BY NAME — this build cannot know what a future version's
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
    ``pinned_ts`` is informative only — it is not part of any hashed frame,
    and nothing here trusts it.
    """

    target: str
    chain_id: str | None
    checkpoint: Checkpoint
    pinned_ts: str


def check_pin(entry_hashes: list[str] | tuple[str, ...], pin: Checkpoint) -> str | None:
    """Check the trail against a previously pinned checkpoint.

    Returns ``None`` when the pinned prefix is still exactly what it was, else
    ``malformed_pin``, ``pin_beyond_head`` (the trail is shorter than what was
    already confirmed — a rollback or truncation), or ``pin_mismatch`` (the
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

    A mismatch is neither a pass nor a tampering finding — it means the
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
    to tell "not applicable" from "a key someone dropped".
    """
    return json.dumps(
        {
            "v": PIN_STATE_VERSION,
            "target": state.target,
            "chain_id": state.chain_id,
            "seq": state.checkpoint.seq,
            "entry_hash": state.checkpoint.entry_hash,
            "root": state.checkpoint.root,
            "pinned_ts": state.pinned_ts,
        },
        indent=2,
        sort_keys=True,
    )


def parse_pin_state(text: str) -> PinState:
    """Read a pin state file.

    Raises ``PinVersionUnknown`` for a version this build does not implement
    and ``PinMalformed`` for anything else it cannot read. Unknown extra keys
    within a known version are ignored — forward compatibility inside a
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
