"""Segment rotation: seal the active segment, create the next one, bind them
(SPEC.md section 20; `domain/segments.py` for the naming and the verdicts).

A hook that appends on every tool dispatch grows one file without bound. The
trigger here is ONE `os.stat` at open -- O(1), on the path already being
opened. By-count was rejected because stored entry sizes differ by ~100x (a
prompt line versus a clipped terminal dump), so a count says almost nothing
about bytes; manual-only was rejected because hooks run unattended, and
unbounded growth is the bug being fixed, not a state an operator will notice.

NO RENAME. `adapters/atomic.py` stays the single owner of the atomic-replace
syscall (tests/architecture/test_invariants.py scans for the call by name, so
this file must not even spell it): the active segment is simply the highest
ordinal present, and rotation only ever creates a file. Renaming the closing
segment would also invalidate every `chain_id` already recorded against it.

CLAUDE.md rule 7, widened one level: read-tail + append is one critical
section, and rotation makes that section span TWO files -- the closing
segment's tail is read and the new segment's genesis binding is written under
a single `<dir>/segments.lock`. Two writers that both rotated would each
write a genesis binding into the same new segment; the second one is not a
fork (the backend's own file lock serializes it) but it is a duplicate
rotation record, and the re-check under the lock is what prevents it.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any, Final

# The writer's own O(1) tail read (waxseal-7tk.1). Imported rather than
# re-implemented so the reader that seals a segment and the writer that
# extends it can never disagree about which line is the tail.
from waxseal.adapters._envelope import tail_fields
from waxseal.adapters.filelock import file_lock
from waxseal.adapters.jsonl import _read_last_line
from waxseal.domain.handoff import HandoffBinding, to_payload
from waxseal.domain.segments import (
    ROTATION_PAYLOAD_TYPE,
    SEGMENT_SUFFIX,
    segment_chain_id,
    segment_identity,
    segment_name,
    segment_ordinal,
)
from waxseal.log import AuditLog

#: 16 MiB. A CONSTANT IN CODE with no environment variable to tune it (owner
#: decision, 31/08/2026): a threshold an operator can raise is a threshold
#: that gets raised the first time rotation is inconvenient, and the file it
#: bounds is the one an incident review has to read. At the measured 1.9 KB
#: per stored hook entry this is roughly 8.8k entries per segment.
DEFAULT_MAX_SEGMENT_BYTES: Final = 16 * 1024 * 1024

_LOCK_BASE: Final = "segments"

_BUILT_IN_LABEL: Final = "built-in default"
_CALLER_LABEL: Final = "caller-supplied"


def _stderr_notice(message: str) -> None:
    """Where a labelled degradation goes by default.

    stderr, never stdout: a hook's stdout is read by its host (Claude Code
    injects it into model context, Cursor parses it as a permission
    decision), so a diagnostic printed there would be interpreted.
    """
    print(f"[waxseal-audit] {message}", file=sys.stderr)


def open_segmented(
    base: Path | str,
    *,
    max_segment_bytes: int = DEFAULT_MAX_SEGMENT_BYTES,
    notice: Callable[[str], None] = _stderr_notice,
    **open_kwargs: Any,
) -> AuditLog:
    """An ``AuditLog`` on the active segment of the trail ``base`` names,
    rotating first if the active segment has passed ``max_segment_bytes``.

    ``base`` may be either the unnumbered logical name (``trail.jsonl`` --
    what `WAXSEAL_TRAIL` holds, adopted as the base segment on its first
    rotation) or an already-numbered segment (``trail.00000.jsonl`` -- the
    per-project routed default). Both resolve to the same stem.

    ``max_segment_bytes`` is a FUNCTION PARAMETER, not configuration: a
    programmatic caller embedding waxseal owns its own storage budget, while
    the hooks pass ``DEFAULT_MAX_SEGMENT_BYTES`` and the rotation notice says
    which of the two the number came from (rule 6 -- a threshold carries its
    provenance for the same reason a fail-open does).

    Remaining ``open_kwargs`` go straight to ``AuditLog.open``, so
    ``redactor``/``record_drops``/``anchor_sink`` behave exactly as they do
    without rotation -- and every sidecar derives its own path from the
    segment file it belongs to, so `.drops`/`.anchors`/`.attest` follow the
    active segment with no code here.
    """
    path = Path(base).expanduser()
    directory, stem = _dir_and_stem(path)
    active = _active(directory, stem, path)
    if _size(active) < max_segment_bytes:
        return AuditLog.open(active, **open_kwargs)

    with file_lock(directory / _LOCK_BASE):
        # Re-resolve and re-stat INSIDE the lock: another process may have
        # rotated while this one waited, in which case the active segment is
        # a different file and is under threshold again.
        active = _active(directory, stem, path)
        if _size(active) < max_segment_bytes:
            return AuditLog.open(active, **open_kwargs)

        tail = _read_last_line(active)
        if tail is None:
            # Over threshold with no complete entry (a file of blank lines, a
            # torn single line): there is no tail for a binding to point at,
            # so there is nothing to seal yet.
            return AuditLog.open(active, **open_kwargs)
        try:
            last_seq, last_hash = tail_fields(json.loads(tail))
        except (ValueError, KeyError, TypeError) as e:
            # A torn write from a crash mid-flush, or an out-of-band edit.
            # Reported, never repaired (rule 4), and labelled rather than
            # swallowed (rule 6) -- a writer that crashed here must not take
            # the next append down with it.
            notice(
                f"cannot read the closing segment's tail ({e!r}) — NOT rotating, "
                f"still appending to {active.name}; run `waxseal segments` on "
                f"{directory}"
            )
            return AuditLog.open(active, **open_kwargs)

        _final_checkpoint(active, notice=notice, **open_kwargs)

        new_path = directory / segment_name(stem, _next_ordinal(directory, stem))
        log = AuditLog.open(new_path, **open_kwargs)
        # A NEW chain: seq 0, prev_hash = 64 zeros. Segments are linked ONLY
        # by this binding, never by prev_hash across a file boundary.
        log.append(
            payload=to_payload(
                HandoffBinding(
                    chain_id=segment_chain_id(directory.name, segment_identity(active.name)),
                    seq=last_seq,
                    head_hash=last_hash,
                )
            ),
            payload_type=ROTATION_PAYLOAD_TYPE,
        )
        notice(
            f"rotated at {max_segment_bytes} bytes "
            f"({_threshold_label(max_segment_bytes)}): {active.name} sealed, "
            f"now appending to {new_path.name}"
        )
        return log


def active_segment(base: Path | str) -> Path:
    """The segment a writer would append to right now: the highest ordinal
    present, else the unnumbered base, else the path itself (nothing written
    yet). Read-only -- creates nothing."""
    path = Path(base).expanduser()
    directory, stem = _dir_and_stem(path)
    return _active(directory, stem, path)


def discover_segments(directory: Path | str) -> list[Path]:
    """Every segment file in ``directory``, grouped by stem and in ordinal
    order within each group (an unnumbered base first, as the oldest).

    A stem with no NUMBERED segment is not a segment group: an unrotated
    single trail is what `waxseal verify` is for, and `waxseal segments`
    reports finding nothing rather than inventing a one-segment directory.
    """
    directory = Path(directory).expanduser()
    if not directory.is_dir():
        return []
    numbered: dict[str, list[tuple[int, Path]]] = {}
    for entry in directory.iterdir():
        stem = _stem_of(entry.name)
        if stem is None:
            continue
        ordinal = segment_ordinal(entry.name, stem)
        # _stem_of only returns a stem for a correctly numbered name, so the
        # ordinal is present by construction.
        assert ordinal is not None  # type-narrowing
        numbered.setdefault(stem, []).append((ordinal, entry))
    found: list[Path] = []
    for stem in sorted(numbered):
        unnumbered = directory / f"{stem}{SEGMENT_SUFFIX}"
        if unnumbered.exists():
            found.append(unnumbered)
        found.extend(path for _, path in sorted(numbered[stem]))
    return found


def _stem_of(name: str) -> str | None:
    """``name``'s stem if it is a correctly numbered segment file, else None."""
    head = segment_identity(name).rpartition(".")[0]
    if not head:
        return None
    return head if segment_ordinal(name, head) is not None else None


def _dir_and_stem(path: Path) -> tuple[Path, str]:
    stem = _stem_of(path.name)
    if stem is not None:
        return path.parent, stem
    return path.parent, segment_identity(path.name)


def _active(directory: Path, stem: str, fallback: Path) -> Path:
    ordinals = _ordinals(directory, stem)
    if ordinals:
        return directory / segment_name(stem, max(ordinals))
    unnumbered = directory / f"{stem}{SEGMENT_SUFFIX}"
    if unnumbered.exists():
        return unnumbered
    return fallback


def _next_ordinal(directory: Path, stem: str) -> int:
    ordinals = _ordinals(directory, stem)
    # No numbered segment yet means the unnumbered base is the one being
    # sealed, so it becomes segment "before 0" and the new file is 0.
    return max(ordinals) + 1 if ordinals else 0


def _ordinals(directory: Path, stem: str) -> list[int]:
    if not directory.is_dir():
        return []
    found = []
    for entry in directory.iterdir():
        ordinal = segment_ordinal(entry.name, stem)
        if ordinal is not None:
            found.append(ordinal)
    return found


def _size(path: Path) -> int:
    """The active segment's size in bytes, or 0 when it does not exist yet.

    One stat call, not exists()+stat(): the trigger has to stay O(1) on the
    append path.
    """
    try:
        return path.stat().st_size
    except OSError:
        return 0


def _threshold_label(max_segment_bytes: int) -> str:
    """Where the threshold came from. A caller who passes exactly the built-in
    number is indistinguishable from one who passed nothing, which is correct:
    the label describes the NUMBER's provenance, not the call site's."""
    if max_segment_bytes == DEFAULT_MAX_SEGMENT_BYTES:
        return _BUILT_IN_LABEL
    return _CALLER_LABEL


def _final_checkpoint(active: Path, *, notice: Callable[[str], None], **open_kwargs: Any) -> None:
    """Publish one last checkpoint for the segment being sealed, best-effort.

    This is the anchor sidecar carve-out SPEC section 9 already spells out
    (`waxseal anchor` writes `.anchors`), never a chain append, so it does not
    touch the CLI's never-appends rule or this segment's own history. A
    failure is labelled and never blocks (rule 6): a sealed segment with no
    closing checkpoint is a weaker record, but refusing to rotate would trade
    that for unbounded growth plus a lost event.
    """
    if open_kwargs.get("anchor_sink") is None:
        return
    try:
        AuditLog.open(active, **open_kwargs).anchor()
    except Exception as e:  # noqa: BLE001 - labelled, never swallowed (rule 6)
        notice(
            f"final checkpoint for {active.name} failed ({e}) — sealing it anyway; "
            "that segment's .anchors sidecar has no closing checkpoint"
        )
