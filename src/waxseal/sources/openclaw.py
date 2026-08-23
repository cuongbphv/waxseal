"""OpenClaw audit-ledger source: chain a ledger that prunes itself.

OpenClaw already records what its agents did — `audit_events` in
`state/openclaw.sqlite`, written off the hot path, queryable with
`openclaw audit --json`. What it does not do is keep that record, or prove it
was not edited. Its own docs say so (docs/gateway/audit.md):

  "It is not a lossless compliance archive; if you need one, use an external
   system fed by OpenTelemetry or channel-level tooling."
  "Queries never return records older than 30 days, and the ledger is capped
   at 100,000 rows; expired rows are pruned during startup, hourly
   maintenance, and later writes."

There is no hash on a ledger row and no link between rows, so a deleted or
edited row leaves nothing behind. This module is the external archive: it
pages the documented export into a waxseal chain, where the record becomes
append-only, offline-verifiable, and fingerprint-versioned — the last of those
matters because the ledger's shape has already migrated once ("the earlier
run/tool-only ledger"), which is the migration-060 failure class.

An exporter, not a hook, for two reasons OpenClaw's own tracker supplies:
issue #105453 objects to audit work on the execution path, and issue #115342
argues the capability belongs at the audit layer because provider hooks cover
one runtime each. Reading the ledger covers every runtime through one path and
costs the agent nothing.

Verified against openclaw/openclaw @ main, 2026-08-22:
- record shape: src/audit/audit-event-types.ts (AUDIT_EVENT_SCHEMA_VERSION 1),
  src/audit/audit-event-store.ts parseAuditRecordBase;
- paging: audit-event-store.ts listAuditEvents — ORDER BY sequence DESC, and
  `--cursor` is exclusive (`where("sequence", "<", cursor)`), so the export
  walks BACKWARDS and this module has to reverse it;
- limits and retention: docs/cli/audit.md ("--limit <count>: activity page
  size from 1 to 500"), docs/gateway/audit.md (30 days, 100,000 rows).

What this proves, and what it does not: the chain proves nothing was altered
after ingest. It cannot prove the ledger was complete when read — OpenClaw
documents that "absence of a row proves nothing" — and it carries no tool
arguments or results, because the ledger deliberately stores none.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import threading
from collections.abc import Callable
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, TypeGuard

from waxseal.adapters.filelock import file_lock
from waxseal.log import AuditLog

OPENCLAW_AUDIT_PAYLOAD_TYPE: Final = "application/vnd.openclaw.audit-event+json"
OPENCLAW_GAP_PAYLOAD_TYPE: Final = "application/vnd.waxseal.openclaw-ingest-gap+json"

# docs/cli/audit.md: activity page size is 1..500. Asking for more is an
# error from the CLI, so clamp rather than let a caller's number fail the run.
MAX_LIMIT: Final = 500
DEFAULT_LIMIT: Final = MAX_LIMIT

# 500 x 250 = 125,000 rows, above OpenClaw's own 100,000-row ledger cap: a
# first run against a full ledger must not need a second pass, because rows
# the cap left behind are older than the resume point and never come back.
DEFAULT_MAX_PAGES: Final = 250

# docs/cli/audit.md --kind. Validated here so a typo fails before the CLI
# runs, instead of being reported as an unusable export.
KINDS: Final = ("agent_run", "tool_action", "message")

_EXPORT_TIMEOUT_SECONDS: Final = 60.0


@dataclass(frozen=True)
class Gap:
    """A hole in OpenClaw's `sequence` between two ingested records.

    `cause` distinguishes what the hole means, because the two causes call for
    different operator responses and neither is tampering:

    - "prune_or_drop": the rows were gone before waxseal saw them — expiry,
      the row cap, or a dropped write. OpenClaw's queue is documented
      best-effort, so prune and drop are indistinguishable from outside; the
      gap names the range, never a cause it cannot establish.
    - "page_cap": `max_pages` stopped this run early, so the rows were left
      behind by waxseal's own bound, not by OpenClaw.
    """

    missing_after: int
    missing_before: int
    cause: str


@dataclass(frozen=True)
class IngestResult:
    ingested: int
    last_sequence: int | None
    dropped: int = 0
    unusable: int = 0
    # None = gap detection did not run (a filtered export, or an export that
    # never arrived). () = it ran and found none. CLAUDE.md rule 5.
    gaps: tuple[Gap, ...] | None = ()
    truncated: bool = False
    notice: str | None = None


def run_openclaw_audit(args: list[str]) -> str:
    """Default export runner: `openclaw <args>` → stdout.

    Raises rather than returning a sentinel — `ingest` owns the fail-open
    decision, and a runner that silently returned "" would be indistinguishable
    from an empty ledger.
    """
    binary = os.environ.get("WAXSEAL_OPENCLAW_BIN", "openclaw")
    # shutil.which, not a bare name: it honours PATHEXT, which is the only way
    # a Windows install (openclaw.cmd) resolves.
    resolved = shutil.which(binary)
    if resolved is None:
        raise FileNotFoundError(f"{binary} is not on PATH")
    proc = subprocess.run(
        [resolved, *args],
        capture_output=True,
        # Explicit utf-8: the text layer would otherwise decode with the
        # locale codec (cp1252 on Windows), which has already broken this
        # repo once, and agent/session ids are not ASCII-only.
        encoding="utf-8",
        errors="replace",
        timeout=_EXPORT_TIMEOUT_SECONDS,
        check=False,
    )
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()[:500]
        raise RuntimeError(f"{binary} audit exit {proc.returncode}: {detail}")
    return proc.stdout


def last_ingested_sequence(log: AuditLog) -> int | None:
    """Highest OpenClaw `sequence` already on the chain, or None if this trail
    has never ingested one.

    Derived from the chain itself rather than a cursor file: a cursor file can
    disagree with the chain, and the chain is the record that has to be right.
    None is not 0 — a ledger's sequences start at 1, so 0 would be a claim
    about ingested history that never happened (CLAUDE.md rule 5).
    """
    highest: int | None = None
    for entry in log.entries():
        if entry.header.payload_type != OPENCLAW_AUDIT_PAYLOAD_TYPE or entry.payload is None:
            continue
        try:
            sequence = json.loads(entry.payload).get("sequence")
        except (ValueError, AttributeError):
            continue
        if _is_sequence(sequence) and (highest is None or sequence > highest):
            highest = sequence
    return highest


def _is_sequence(value: Any) -> TypeGuard[int]:
    # bool is an int subclass; True would otherwise read as sequence 1.
    return isinstance(value, int) and not isinstance(value, bool)


def _sequence_of(record: Any) -> int | None:
    if not isinstance(record, dict):
        return None
    sequence = record.get("sequence")
    if not _is_sequence(sequence):
        return None
    return sequence if sequence >= 1 else None


def _page_args(*, limit: int, kind: str | None, cursor: int | None) -> list[str]:
    args = ["audit", "--json", "--limit", str(limit)]
    if kind is not None:
        args += ["--kind", kind]
    if cursor is not None:
        args += ["--cursor", str(cursor)]
    return args


# Overlap on a trail with no local path (memory, remote) can only come from
# threads of this process; the file lock below covers the on-disk case.
_PROCESS_INGEST_LOCK = threading.Lock()


def _ingest_lock_target(trail: Path) -> Path:
    # Deliberately NOT the trail itself: file_lock(trail) is the JSONL
    # backend's own append lock, which every append inside the run below
    # takes — holding it for the whole run would deadlock the run against
    # its own appends. A dedicated <trail>.ingest.lock sits next to it.
    return trail.with_name(trail.name + ".ingest")


def ingest(
    log: AuditLog,
    *,
    kind: str | None = None,
    limit: int = DEFAULT_LIMIT,
    max_pages: int = DEFAULT_MAX_PAGES,
    run_fn: Callable[[list[str]], str] | None = None,
) -> IngestResult:
    """Append every ledger record newer than the last ingested one.

    Idempotent: the resume point comes from the chain, and the WHOLE run —
    resume-read through append — holds one ingest lock, because two
    overlapping timer runs that both read the same resume point both ingest
    the same rows (read-tail + append is one critical section, CLAUDE.md
    rule 7, here with "tail" spelled "resume point"). Never raises — this
    runs on a timer, and an audit exporter that crashes the timer stops being
    an audit exporter; a run that cannot take the lock (Windows'
    msvcrt.locking gives up after ~10s) backs off with a labelled notice.
    Degradations are reported in the result and, when they cost entries,
    counted as dropped writes on the log (CLAUDE.md rule 6).

    Pass `kind` to narrow the export; doing so turns gap detection OFF, because
    absent sequences are then the filter working as asked, and calling that
    loss would be a false alarm.
    """
    if kind is not None and kind not in KINDS:
        raise ValueError(f"kind must be one of {KINDS}, not {kind!r}")
    limit = max(1, min(limit, MAX_LIMIT))
    fetch = run_fn if run_fn is not None else run_openclaw_audit

    trail = getattr(log, "trail_path", None)
    if trail is None:
        with _PROCESS_INGEST_LOCK:
            return _ingest_run(log, kind=kind, limit=limit, max_pages=max_pages, fetch=fetch)
    stack = ExitStack()
    try:
        stack.enter_context(file_lock(_ingest_lock_target(trail)))
    except OSError as e:
        # Another run holds the lock and this platform's lock gave up waiting.
        # Backing off IS the correct timer behaviour: the run that holds the
        # lock is ingesting these very rows, and the next tick resumes past
        # them. Reported, never raised (rule 6).
        return IngestResult(
            ingested=0,
            last_sequence=None,
            gaps=None,
            notice=f"another run holds the ingest lock: {type(e).__name__}: {e}",
        )
    with stack:
        return _ingest_run(log, kind=kind, limit=limit, max_pages=max_pages, fetch=fetch)


def _ingest_run(
    log: AuditLog,
    *,
    kind: str | None,
    limit: int,
    max_pages: int,
    fetch: Callable[[list[str]], str],
) -> IngestResult:
    """The run body. Callers hold the ingest lock (or the process fallback)."""
    try:
        resume_from = last_ingested_sequence(log)
    except Exception as e:
        # Without a resume point an ingest would re-append history it already
        # holds, so an unreadable trail stops the run instead of duplicating
        # it. Reported, never raised: this runs on a timer.
        return IngestResult(
            ingested=0,
            last_sequence=None,
            gaps=None,
            notice=f"cannot read the existing trail: {type(e).__name__}: {e}",
        )
    fresh: dict[int, dict[str, Any]] = {}
    unusable = 0
    cursor: int | None = None
    truncated = False
    pages = 0

    while True:
        if pages >= max_pages:
            truncated = True
            break
        try:
            page = json.loads(fetch(_page_args(limit=limit, kind=kind, cursor=cursor)))
        except Exception as e:
            # The export never arrived. Nothing was read, so nothing was
            # dropped — reporting this as a dropped write would make
            # dropped_writes mean two different things.
            return IngestResult(
                ingested=0,
                last_sequence=resume_from,
                gaps=None,
                notice=f"openclaw audit export failed: {type(e).__name__}: {e}",
            )
        pages += 1
        if not isinstance(page, dict) or not isinstance(page.get("events"), list):
            return IngestResult(
                ingested=0,
                last_sequence=resume_from,
                unusable=unusable,
                gaps=None,
                notice="openclaw audit output is not a {events: [...]} page",
            )
        events: list[Any] = page["events"]
        if not events:
            break

        reached_known = False
        for record in events:
            sequence = _sequence_of(record)
            if sequence is None:
                # One damaged record must not cost the whole page; the loss is
                # counted, never silent.
                unusable += 1
                continue
            if resume_from is not None and sequence <= resume_from:
                reached_known = True
                continue
            fresh[sequence] = record
        if reached_known:
            break

        next_cursor = page.get("nextCursor")
        if not isinstance(next_cursor, int) or isinstance(next_cursor, bool):
            break
        cursor = next_cursor

    if not fresh:
        gaps: tuple[Gap, ...] | None = None if kind is not None else ()
        notice = f"{unusable} unusable record(s) in the export" if unusable else None
        return IngestResult(
            ingested=0,
            last_sequence=resume_from,
            unusable=unusable,
            gaps=gaps,
            truncated=truncated,
            notice=notice,
        )

    ordered = [fresh[s] for s in sorted(fresh)]
    found_gaps: list[Gap] = []
    if kind is None:
        # The oldest fetched record is not adjacent to the resume point: rows
        # went missing between runs, or our own page cap stopped short.
        first = _sequence_of(ordered[0])
        assert first is not None  # only parsed sequences reach `fresh`
        if resume_from is not None and first > resume_from + 1:
            found_gaps.append(
                Gap(
                    missing_after=resume_from,
                    missing_before=first,
                    cause="page_cap" if truncated else "prune_or_drop",
                )
            )
        previous = first
        for record in ordered[1:]:
            sequence = _sequence_of(record)
            assert sequence is not None
            if sequence > previous + 1:
                found_gaps.append(
                    Gap(missing_after=previous, missing_before=sequence, cause="prune_or_drop")
                )
            previous = sequence

    gap_before: dict[int, Gap] = {g.missing_before: g for g in found_gaps}
    ingested = 0
    dropped = 0
    last_sequence = resume_from
    for record in ordered:
        sequence = _sequence_of(record)
        assert sequence is not None
        gap = gap_before.get(sequence)
        if gap is not None and not log.try_append(
            payload={
                "kind": "ingest_gap",
                "missing_after": gap.missing_after,
                "missing_before": gap.missing_before,
                "cause": gap.cause,
            },
            payload_type=OPENCLAW_GAP_PAYLOAD_TYPE,
        ):
            dropped += 1
        if log.try_append(payload=record, payload_type=OPENCLAW_AUDIT_PAYLOAD_TYPE):
            ingested += 1
            last_sequence = sequence
        else:
            dropped += 1

    notices = []
    if truncated:
        notices.append(f"stopped at max_pages={max_pages}; older records were not ingested")
    if unusable:
        notices.append(f"{unusable} unusable record(s) in the export")
    if dropped:
        notices.append(f"{dropped} entr(ies) could not be appended")
    if found_gaps:
        ranges = ", ".join(f"{g.missing_after}->{g.missing_before} ({g.cause})" for g in found_gaps)
        notices.append(f"sequence gap(s): {ranges}")

    return IngestResult(
        ingested=ingested,
        last_sequence=last_sequence,
        dropped=dropped,
        unusable=unusable,
        gaps=None if kind is not None else tuple(found_gaps),
        truncated=truncated,
        notice="; ".join(notices) if notices else None,
    )
