"""Whether a SEALED segment reached an archive — the J3 vocabulary (pure).

On-chain anchoring and the `.anchors` sidecar keep hashes, not content: an
attacker with write access to the disk can DELETE history. The chain detects
that (the anchored hash is still there) and cannot undo it, so proof without
availability is proof about a corpse. J3 pushes each sealed segment somewhere
else; this module is the vocabulary for saying whether it got there.

Three states, because two would lie. "The segment is off-box" and "nobody was
asked to put it off-box" are different facts, and so is "we asked and it did
not arrive". Reporting no-destination-configured as success invents a copy
that does not exist (beads v1.2.2's false confidence); reporting it as a
failure alarms an operator who never opted in (migration 060's false alarm).
Same collapse theorem as CLAUDE.md's "Named principle", one more instance.

Deliberately NOT ``domain.verdict.Verdict``, for the same reason
``adapters.s3.WormState`` is not: ``Verdict``'s three values carry CLI exit
codes and chain-integrity severity, and neither mapping is honest here. A
segment that failed to upload is not a BROKEN chain -- the chain is intact and
verifies ok, only its off-box copy is missing -- and rotation has no exit code
to spend anyway. So this reuses ``Verdict``'s SHAPE (an enum, a spelled-out
exhaustive label table, a renderer that always states the weaker claim) with
its own three values.
"""

from __future__ import annotations

import enum
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final


class ArchiveState(enum.Enum):
    """What became of one sealed segment's off-box copy.

    ``NOT_ATTEMPTED`` is not a degraded ``FAILED``. It covers both "no
    destination was configured for this trail" and "the destination could not
    even be asked" (the ``s3`` extra absent, say): in neither case did a
    segment leave the box, and in neither case did anything go wrong.
    """

    STORED = "archive_stored"
    FAILED = "archive_failed"
    NOT_ATTEMPTED = "archive_not_attempted"


@dataclass(frozen=True, slots=True)
class ArchiveReport:
    """One archive outcome: the state, where it was headed, and why.

    ``destination`` and ``detail`` are both required, with no defaults. A bare
    ``archive_failed`` tells an operator that something did not arrive
    somewhere for some reason, which is three unknowns and no action (rule 6:
    a degradation is recorded in the output, never merely signalled).
    """

    state: ArchiveState
    destination: str
    detail: str


#: What rotation calls to push one sealed segment: ``(name, bytes) -> report``.
#: A plain callable rather than a Protocol, matching
#: ``adapters.remote.Transport``: the two destinations that exist (S3 and the
#: server's import API) share exactly one operation, and a class would add a
#: type for callers to instantiate without adding anything to say. A
#: destination is expected to answer with a report rather than raise -- the
#: rotation caller wraps it anyway, because an archive is never allowed to
#: take a rotation down with it.
ArchiveDestination = Callable[[str, bytes], ArchiveReport]


# Exhaustive over ArchiveState, spelled out rather than derived (matching
# domain.verdict's tables and adapters.s3's _WORM_LABEL): a state missing from
# here raises KeyError in the renderer instead of quietly borrowing another
# state's sentence. Only the STORED line says a copy exists, and it says what
# the copy is and is not evidence of.
_ARCHIVE_LABEL: Final[dict[ArchiveState, str]] = {
    ArchiveState.STORED: (
        "a copy of the sealed segment exists at {destination} ({detail}). Scope: the "
        "archive holds the bytes as they were read at rotation, so the history survives "
        "deletion of the local file. It is not evidence that the local file is unchanged, "
        "and storage refuses an overwrite of the copy only if that storage says so on its "
        "own (S3 Object Lock, WORM) — this line alone claims availability, not "
        "immutability (DESIGN.md §11)."
    ),
    ArchiveState.FAILED: (
        "the sealed segment was sent to {destination} and did not arrive ({detail}). The "
        "rotation itself COMPLETED: the chain is intact, the new segment is open, and "
        "nothing was lost on this box. What is missing is the off-box copy, so this "
        "segment survives only as long as its local file does. This is a measured "
        "failure of the archive, never a finding about the chain."
    ),
    ArchiveState.NOT_ATTEMPTED: (
        "no archive of the sealed segment was attempted, destination {destination} "
        "({detail}). This is NOT 'stored' and NOT 'failed': nothing was sent, so there is "
        "nothing off-box and nothing went wrong. It must be rendered as unattempted "
        "rather than collapsed into either binary (CLAUDE.md rule 5) — an operator who "
        "believes a destination is configured needs to see this line to learn it is not."
    ),
}


def render_archive_state(report: ArchiveReport) -> list[str]:
    """Human-readable lines for a notice or a report, in ``domain.tickets``'s
    style.

    Prefixed with the state's own token, so the three outcomes are
    distinguishable in a log by grep and can never be told apart only by
    prose.
    """
    return [
        f"{report.state.value}: "
        + _ARCHIVE_LABEL[report.state].format(
            destination=report.destination, detail=report.detail
        )
    ]
