"""Sealed segments: per-project trail naming and multi-segment verification
(SPEC.md section 20).

A hook that appends on every tool call grows one file without bound, and one
file shared by every project a developer touches braids unrelated work into a
single chain. Both are fixed here: a trail is routed into a per-project
directory (``project_slug``) and rolled over into ordinal-numbered segments
(``segment_name``) once the active one passes a byte threshold.

Segments are linked by a BINDING, never by ``prev_hash``. Each new segment is
a NEW chain -- seq 0, ``prev_hash`` = 64 zeros -- whose seq-0 payload is the
pointer triple ``(chain_id, seq, head_hash)`` naming the closing segment's
tip. That triple is exactly ``domain.handoff.HandoffBinding``, reused verbatim
including ``binding_holds``; only the payload type and the ``chain_id``
convention below are new. Extending ``prev_hash`` across a file boundary
instead would make the whole history one chain again, so verifying the newest
segment would require every byte of every older one -- the growth problem
rotation exists to solve.

The payload type is deliberately NOT ``HANDOFF_PAYLOAD_TYPE``: mixing
delegation with rotation would make `verify-handoff` report rotation
bindings, and the two have different obligations -- a rotation binding is
MANDATORY at seq 0 of every segment that has a predecessor (its absence is a
verdict), while a handoff binding is optional wherever it appears.

Pure module: no filesystem access, no ports, no adapters. ``verify_segments``
is handed segments that have already been read (each with its own
``verify_chain`` verdict, its entry hashes, and its seq-0 payload) and only
decides what they add up to. ``sources/rotation.py`` does the reading and the
writing; `waxseal segments` does the reporting.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Final

from waxseal.domain.handoff import HandoffBinding, binding_holds, from_payload
from waxseal.domain.verdict import Verdict
from waxseal.domain.verify import VerifyResult

#: Payload type of a segment's seq-0 rotation binding. A distinct type from
#: HANDOFF_PAYLOAD_TYPE, for the reason in this module's docstring.
ROTATION_PAYLOAD_TYPE: Final = "application/vnd.waxseal.rotation-binding+json"

#: Segment ordinals are zero-padded to this width so LEXICOGRAPHIC order over
#: file names equals CHRONOLOGICAL order. Timestamp-named segments were
#: rejected for exactly this: clock skew (a VM resumed, an NTP step) reverses
#: them, and a verifier walking names would then check the bindings backwards.
SEGMENT_DIGITS: Final = 5

SEGMENT_SUFFIX: Final = ".jsonl"

#: Per-segment states. The first three are ``Verdict``'s three values; the
#: fourth is its own state because "a binding names it and it is not here" is
#: a distinguishable fact an operator has to see, never printed as "tampered".
SEGMENT_OK: Final = "ok"
SEGMENT_BROKEN: Final = "broken"
SEGMENT_UNVERIFIABLE: Final = "unverifiable"
SEGMENT_MISSING: Final = "missing"

_SLUG_READABLE_MAX: Final = 32
_SLUG_DIGEST_CHARS: Final = 12
_SLUG_FALLBACK: Final = "unnamed"

_UNSAFE: Final = re.compile(r"[^a-z0-9]+")
_PATH_SEPARATORS: Final = re.compile(r"[/\\]")
_DIGITS: Final = frozenset("0123456789")

_STATE_VERDICT: Final[dict[str, Verdict]] = {
    SEGMENT_OK: Verdict.OK,
    SEGMENT_UNVERIFIABLE: Verdict.UNVERIFIABLE,
    SEGMENT_BROKEN: Verdict.BROKEN,
    # Settled by the repository owner 31/08/2026: a surviving binding is
    # POSITIVE evidence the named segment existed, which puts its absence on
    # the same fail-closed footing as `binding_holds` itself. Reporting it as
    # UNVERIFIABLE would let deleting a segment downgrade the whole directory
    # from exit 1 to exit 2 -- an attacker choosing their own verdict.
    SEGMENT_MISSING: Verdict.BROKEN,
}


@dataclass(frozen=True, slots=True)
class SegmentRead:
    """One segment as it was already read off storage.

    ``chain=None`` means the segment's stored lines could not be parsed at
    all -- a torn write from a crash mid-rotation, or an out-of-band edit.
    That is NOT a ``VerifyResult`` saying "broken": nothing was compared, so
    nothing is known (CLAUDE.md rule 5), and ``entry_hashes`` is then empty
    because the hashes are unavailable rather than known-to-be-none.
    """

    identity: str
    chain: VerifyResult | None
    entry_hashes: tuple[str, ...] = ()
    genesis_payload_type: str | None = None
    #: The seq-0 payload, already JSON-decoded by the caller. ``None`` covers
    #: both "no seq-0 entry" and "its bytes would not decode".
    genesis_payload: Any | None = None


@dataclass(frozen=True, slots=True)
class SegmentState:
    """What one segment (or one named-but-absent segment) amounts to.

    Exactly one reason per segment, the most severe found, so a report line
    cannot say two things about the same file.
    """

    identity: str
    state: str
    reason: str | None
    broken_seq: int | None = None


@dataclass(frozen=True, slots=True)
class SegmentsResult:
    segments: tuple[SegmentState, ...] = field(default=())
    verdict: Verdict = Verdict.OK


def project_slug(cwd: str) -> str:
    """The directory name a project's trail lives under: a readable half plus
    a 48-bit digest of ``cwd``.

    The digest is over the LITERAL ``cwd`` string. Resolving it first
    (symlinks, case folding, trailing separators) is host-dependent -- the
    same project resolves differently on a mac, in a container, and under
    WSL -- which would split one project's history across two slugs on
    whichever host disagreed, and a split trail looks exactly like a
    truncated one.

    A 48-bit collision merely MERGES two projects into one trail: weaker
    privacy separation between them, never a broken chain, because each
    segment is still one contiguous chain whatever wrote it.

    ``session_id`` was rejected as the key: it changes every session, so it
    would spawn thousands of trails nobody ever verifies.
    """
    digest = hashlib.sha256(cwd.encode("utf-8", "surrogatepass")).hexdigest()
    return f"{_readable(cwd)}-{digest[:_SLUG_DIGEST_CHARS]}"


def _readable(cwd: str) -> str:
    """The human half of the slug: the project directory's own name, folded
    to ``[a-z0-9-]`` and clipped. Purely cosmetic -- separation comes from the
    digest -- so an empty result is a fallback word, never an error."""
    basename = _PATH_SEPARATORS.split(cwd.rstrip("/\\"))[-1]
    folded = _UNSAFE.sub("-", basename.lower()).strip("-")
    clipped = folded[:_SLUG_READABLE_MAX].strip("-")
    return clipped or _SLUG_FALLBACK


def segment_name(stem: str, ordinal: int) -> str:
    """The file name of segment ``ordinal`` for a trail named ``stem``."""
    if ordinal < 0:
        raise ValueError(f"segment ordinal must not be negative: {ordinal!r}")
    if ordinal > 10**SEGMENT_DIGITS - 1:
        # Past this the padding widens and lexicographic order stops matching
        # chronological order, which `segment_ordinal` would then refuse to
        # parse -- the segment would become invisible to discovery. Loud here
        # beats invisible there.
        raise ValueError(
            f"segment ordinal exceeds the {SEGMENT_DIGITS}-digit name space: {ordinal!r}"
        )
    return f"{stem}.{ordinal:0{SEGMENT_DIGITS}d}{SEGMENT_SUFFIX}"


def segment_ordinal(name: str, stem: str) -> int | None:
    """``name``'s ordinal, or ``None`` when it is not a numbered segment of
    ``stem``.

    Strict on purpose: exactly ``SEGMENT_DIGITS`` ASCII digits. A loose parse
    would accept ``trail.1.jsonl`` and ``trail.000001.jsonl`` as ordinals
    whose name order no longer matches their numeric order.
    """
    prefix = f"{stem}."
    if not name.startswith(prefix) or not name.endswith(SEGMENT_SUFFIX):
        return None
    middle = name[len(prefix) : -len(SEGMENT_SUFFIX)]
    if len(middle) != SEGMENT_DIGITS or not _DIGITS.issuperset(middle):
        return None
    return int(middle)


def segment_identity(name: str) -> str:
    """A segment's identity inside its directory: the file name without the
    ``.jsonl`` suffix. This is what a ``chain_id`` names and what resolves a
    binding to its predecessor."""
    return name.removesuffix(SEGMENT_SUFFIX)


def segment_chain_id(slug: str, identity: str) -> str:
    """The ``chain_id`` a rotation binding records: ``<slug>/<identity>``.

    The slug half records which project directory the segment lived under at
    rotation time and is metadata only -- resolution is by ``identity`` (see
    ``verify_segments``), so moving or renaming the directory is not a break.
    """
    return f"{slug}/{identity}"


def verify_segments(segments: Sequence[SegmentRead]) -> SegmentsResult:
    """What a directory of segments adds up to, in the order given (ordinal
    order, which is also chronological order -- see ``SEGMENT_DIGITS``).

    Never raises: every input here comes off an attacker-writable directory,
    so malformed bindings, absent predecessors and unparseable segments are
    verdicts, not exceptions.

    A segment carrying a rotation binding at seq 0 is checked wherever it
    sits, INCLUDING the lowest ordinal present. Exempting the lowest one
    unconditionally would make prefix deletion free: remove segments 0 and 1
    and segment 2 becomes "the first", so nothing would ask about the binding
    it still carries. Only a segment whose seq 0 is NOT a binding is exempt,
    and then only at position 0 -- the genuinely first segment of a trail.
    """
    present = {seg.identity: seg for seg in segments}
    states: list[SegmentState] = []
    emitted_missing: set[str] = set()

    for index, seg in enumerate(segments):
        if seg.chain is None:
            states.append(
                SegmentState(seg.identity, SEGMENT_UNVERIFIABLE, "segment_unreadable")
            )
            continue
        if not seg.chain.ok:
            # A segment whose own links do not hold says nothing useful about
            # its binding, so the break is the whole finding for it.
            states.append(
                SegmentState(
                    seg.identity, SEGMENT_BROKEN, seg.chain.reason, seg.chain.broken_seq
                )
            )
            continue

        binding_state, missing = _binding_finding(seg, index=index, present=present)
        if missing is not None and missing not in emitted_missing:
            emitted_missing.add(missing)
            states.append(SegmentState(missing, SEGMENT_MISSING, "segment_missing"))

        # A binding finding is UNVERIFIABLE or BROKEN, never OK, and an
        # unknown fingerprint is only ever UNVERIFIABLE -- the weakest
        # non-OK state. So preferring the binding finding whenever there is
        # one is always at least as severe; no comparison is needed.
        finding = binding_state
        if finding is None and seg.chain.unverifiable:
            finding = SegmentState(
                seg.identity,
                SEGMENT_UNVERIFIABLE,
                "unknown_fingerprint",
                seg.chain.unverifiable[0],
            )
        states.append(finding or SegmentState(seg.identity, SEGMENT_OK, None))

    verdict = Verdict.OK
    for state in states:
        verdict = verdict.join(_STATE_VERDICT[state.state])
    return SegmentsResult(segments=tuple(states), verdict=verdict)


def _binding_finding(
    seg: SegmentRead, *, index: int, present: dict[str, SegmentRead]
) -> tuple[SegmentState | None, str | None]:
    """``(this segment's binding finding, the name of an absent predecessor)``.

    Both ``None`` means the binding holds, or none was required.
    """
    if seg.genesis_payload_type != ROTATION_PAYLOAD_TYPE:
        if index == 0:
            return None, None
        return (
            SegmentState(seg.identity, SEGMENT_BROKEN, "rotation_binding_missing", 0),
            None,
        )
    try:
        binding: HandoffBinding = from_payload(seg.genesis_payload)
    except ValueError:
        # Unverifiable by name, never tampered (CLAUDE.md rule 5): a payload
        # this build cannot read is not a payload known to be wrong.
        return (
            SegmentState(seg.identity, SEGMENT_UNVERIFIABLE, "rotation_binding_unreadable", 0),
            None,
        )
    named = binding.chain_id.rpartition("/")[2]
    predecessor = present.get(named)
    if predecessor is None:
        return None, named
    if predecessor.chain is None:
        # The predecessor is here but unreadable, so there is nothing to
        # compare against -- unmeasured, never "does not hold".
        return (
            SegmentState(seg.identity, SEGMENT_UNVERIFIABLE, "rotation_binding_unchecked", 0),
            None,
        )
    if not binding_holds(binding, predecessor.entry_hashes):
        # Deterministic comparison against the predecessor's OWN current
        # hashes -- the same footing as `verify-handoff`'s exit 1, so this is
        # a genuinely detected mismatch, not an ambiguity.
        return (
            SegmentState(seg.identity, SEGMENT_BROKEN, "rotation_binding_mismatch", 0),
            None,
        )
    return None, None
