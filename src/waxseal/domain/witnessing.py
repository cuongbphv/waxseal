"""Witness cross-check: comparing the local trail against outside observers.

A pinned head catches a server that rewrites history for one client. It cannot
catch split-view: a server that serves one self-consistent history to the
auditor and a different one to the operator, indefinitely. Neither client sees
the other's, so no local check can tell the two worlds apart; the observation
has to leave the client. That is the fork-consistency result (Mazières &
Shasha, SUNDR) and the reason certificate transparency needs gossip in
addition to logs.

A witness is a service under a DIFFERENT authority that the client publishes
its checkpoints to and later reads back. Consistency with what a witness holds
is checked with ``verify_checkpoint``: with the full local hash list in hand,
"the current tree extends the tree the witness saw" is exactly what that
already decides, so no second proof format is introduced. RFC 9162 consistency
proofs stay the primitive for the case this module does not cover, a witness
checking two published heads against each other without holding the log.

What witnesses do NOT give, stated here so no caller has to infer it: they
narrow trust, they do not remove it. Witnesses that collude with the server,
or an attacker positioned to impersonate every witness the client can reach,
defeat the whole arrangement, and nothing after the last published checkpoint
is witnessed at all.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

from waxseal.domain.checkpoint import Checkpoint, verify_checkpoint

WITNESS_CONSISTENT: Final = "consistent"
WITNESS_INCONSISTENT: Final = "inconsistent"
WITNESS_UNREACHABLE: Final = "unreachable"


@dataclass(frozen=True, slots=True)
class WitnessObservation:
    """What one witness reports having seen.

    ``unreadable`` counts records this build could not parse as checkpoints.
    They are carried rather than dropped: a witness holding fifty records of
    which this build reads two has given two records' worth of coverage, and
    reporting only the two would overstate it.
    """

    checkpoints: tuple[Checkpoint, ...]
    unreadable: int = 0


@dataclass(frozen=True, slots=True)
class WitnessVerdict:
    """One witness's outcome.

    ``status`` is deliberately three-valued. Collapsing ``unreachable`` into
    either of the others is the mistake this type exists to prevent: a witness
    that did not answer has measured nothing, which is neither agreement nor
    evidence of a fork.
    """

    name: str
    status: str
    checked: int
    reason: str | None = None
    broken_seq: int | None = None
    unreadable: int = 0


def check_witnessed(
    entry_hashes: Sequence[str], observation: WitnessObservation, *, name: str
) -> WitnessVerdict:
    """Check the local trail against every checkpoint one witness holds.

    Returns the first disagreement found, with the seq it was found at, or a
    consistent verdict naming how many checkpoints were confirmed. Never
    raises: a witness response is remote input.

    A witness holding nothing yields ``checked=0`` and the reason
    ``no_checkpoints_witnessed``: it answered, and it had no coverage to
    offer. That is not the same as agreeing with the trail.
    """
    checked = 0
    for cp in observation.checkpoints:
        reason = verify_checkpoint(entry_hashes, cp)
        if reason is not None:
            return WitnessVerdict(
                name=name,
                status=WITNESS_INCONSISTENT,
                checked=checked,
                reason=reason,
                broken_seq=cp.seq,
                unreadable=observation.unreadable,
            )
        checked += 1
    return WitnessVerdict(
        name=name,
        status=WITNESS_CONSISTENT,
        checked=checked,
        reason=None if checked else "no_checkpoints_witnessed",
        broken_seq=None,
        unreadable=observation.unreadable,
    )


def unreachable_witness(name: str, *, reason: str) -> WitnessVerdict:
    """A witness that could not be asked.

    Constructed by the caller that owns the network, so ``check_witnessed``
    stays pure. The verdict carries ``checked=0`` because that is the honest
    number: nothing was compared.
    """
    return WitnessVerdict(
        name=name, status=WITNESS_UNREACHABLE, checked=0, reason=reason, broken_seq=None
    )
