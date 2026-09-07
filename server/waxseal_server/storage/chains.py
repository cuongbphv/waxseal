"""Multi-chain storage behind the REMOTE.md endpoints.

The write path uses waxseal as a LIBRARY, through `JSONLBackend.append`, whose
builder callback is invoked with `(next_seq, prev_hash)` while the backend's own
file lock is held. That is what makes the compare-and-set of REMOTE.md section 4
atomic with the append rather than a check racing beside it: rejecting inside the
builder happens under the same lock that decided the tail. CLAUDE.md rule 7 is
the library-side statement of the same requirement, and a server that lets two
POSTs win the same `seq` has forked the chain.

A hosted chain ROTATES (waxseal-fg4.17, owner decision 01/09/2026). Workstream B
built rotation for the hook path; the deployment path — the one trail that grows
for months unattended — was still one file without bound, which also left the
Segments screen correct and permanently useless. So `append` reaches
`sources.rotation`, and every read here resolves the segment it is actually
about instead of a fixed file name.

TWO NESTED CRITICAL SECTIONS, and the order is the safety argument:

    segments.lock   (per chain directory, `rotation.segments_lock`)
      -> trail.<n>.jsonl.lock   (per segment file, the backend's own)

`open_segmented` takes them in that order and so does `append` below, so there
is no cycle to deadlock on. `append` holds the OUTER one across resolving the
active segment AND appending to it, because the window rotation opens is not the
CAS — that still runs under the same per-file lock that decided the tail — but
the segment the CAS lands in: a rotation slipping between "which file is active"
and "append to it" seals a segment an entry is still about to extend, leaving a
sealed segment whose tail is not the tail its successor's binding names. Rotation
itself runs BEFORE that block, never inside it, so J3's archive step keeps the
placement `rotation._archive_sealed` argues for — outside every lock, because it
is a network call and a stalled endpoint holding a writer lock is the unbounded
growth J3 exists to prevent, arriving by J3's own hand.

The receipt log's lock is still taken after the chain's is released, never
nested inside it: the ordering note on `append` is unchanged by any of this.

The O(1) JSONL tail read lives in the library (`read_last_line`) so this
server does not grow a second implementation that can drift. It is a public
helper as of 0.1.6; the import is no longer a reach past a private name.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any, Final

from waxseal import Entry, Verdict
from waxseal.adapters.filelock import file_lock
from waxseal.adapters.jsonl import JSONLBackend, read_last_line
from waxseal.domain.archive import ArchiveDestination
from waxseal.domain.segments import SEGMENT_SUFFIX, segment_identity
from waxseal.sources.rotation import (
    DEFAULT_MAX_SEGMENT_BYTES,
    active_segment,
    discover_segments,
    open_segmented,
    segments_lock,
)
from waxseal_server.domain.envelope import parse_envelope
from waxseal_server.domain.errors import DamagedReceiptLog, PreconditionFailed
from waxseal_server.domain.identifiers import require_chain_id
from waxseal_server.domain.receipts import ReceiptChain
from waxseal_server.domain.results import (
    AppendResult,
    ChainSummary,
    ReceiptCrossCheck,
    ReceiptLogReport,
)

TRAIL_NAME: Final = "trail.jsonl"
RECEIPT_LOG_NAME: Final = "receipts.jsonl"

#: The segment stem every chain's trail rotates under. Segment zero of a chain
#: is the unnumbered `trail.jsonl` itself: rotation never renames, so the file
#: an existing deployment already has stays exactly where it is and becomes the
#: segment "before 0" (`sources/rotation.py`).
_TRAIL_STEM: Final = TRAIL_NAME.removesuffix(SEGMENT_SUFFIX)

#: Opaque to clients (REMOTE.md section 4). The prefix exists so a cursor from
#: some other server, or a hand-typed integer, is rejected rather than silently
#: interpreted as an offset into this one.
_CURSOR_PREFIX: Final = "e"

#: A cursor names the SEGMENT it was issued against as well as the offset into
#: it. Without that, a reader whose chain rotated mid-page would resume at its
#: offset in a file it never saw the start of and get a short page with nothing
#: to say so — silent incompleteness, which is the failure this project treats
#: as worse than a loud one.
_CURSOR_SEGMENT_SEPARATOR: Final = "~"

#: The receipt record shape this build writes and can read back (SPEC.md §19).
_RECEIPT_VERSION: Final = 1


def _log_notice(message: str) -> None:
    """Where rotation's labelled degradations land on the server.

    `rotation.py` defaults to stderr because a hook's stdout is read by its
    host; here the destination is the log an operator actually reads. A
    rotation, a failed archive and an unreadable closing segment are all facts
    about the deployment, and rule 6 forbids the only alternative — dropping
    them on the floor.
    """
    logging.getLogger(__name__).warning("%s", message)


class ChainStore:
    """One directory per `chain_id` under `root`, each a fully separate chain."""

    def __init__(
        self,
        root: Path | str,
        *,
        max_segment_bytes: int = DEFAULT_MAX_SEGMENT_BYTES,
        notice: Callable[[str], None] = _log_notice,
        archive: ArchiveDestination | None = None,
    ) -> None:
        self._root = Path(root).expanduser()
        # A CONSTRUCTOR ARGUMENT and deliberately not an environment variable.
        # The owner's 31/08/2026 decision on DEFAULT_MAX_SEGMENT_BYTES was that
        # a threshold an operator can raise is one that gets raised the first
        # time rotation is inconvenient, and the file it bounds is the one an
        # incident review has to read. A programmatic embedder owns its own
        # storage budget; a deployment does not get to opt out.
        self._max_segment_bytes = max_segment_bytes
        self._notice = notice
        # J3, off by default: an absent destination is reported as "not
        # attempted" on every rotation rather than passing silently.
        self._archive = archive

    # ---------------------------------------------------------------- paths

    def chain_dir(self, chain_id: str) -> Path:
        return self._root / require_chain_id(chain_id)

    def trail_path(self, chain_id: str) -> Path:
        """The chain's BASE segment — the unnumbered file every chain starts
        as, and the one a first rotation seals. NOT necessarily the file being
        written now: see `active_trail_path`."""
        return self.chain_dir(chain_id) / TRAIL_NAME

    def active_trail_path(self, chain_id: str) -> Path:
        """The segment a writer would extend right now. Creates nothing."""
        return active_segment(self.trail_path(chain_id))

    def segment_paths(self, chain_id: str) -> list[Path]:
        """Every segment of this chain, oldest first."""
        return self._segments_in(self.chain_dir(chain_id))

    def receipt_log_path(self, chain_id: str) -> Path:
        return self.chain_dir(chain_id) / RECEIPT_LOG_NAME

    def chain_ids(self) -> list[str]:
        if not self._root.is_dir():
            return []
        return sorted(
            child.name
            for child in self._root.iterdir()
            if child.is_dir() and self._segments_in(child)
        )

    @staticmethod
    def _segments_in(directory: Path) -> list[Path]:
        """This trail's segments in `directory`, oldest first.

        `discover_segments` reports nothing for a stem with no NUMBERED
        segment, which is every chain that has not rotated yet — so the
        unrotated single file is the fallback, never a special case elsewhere.
        The filter keeps the receipt log and any other stem out.
        """
        found = [
            path
            for path in discover_segments(directory)
            if segment_identity(path.name).partition(".")[0] == _TRAIL_STEM
        ]
        if found:
            return found
        base = directory / TRAIL_NAME
        return [base] if base.exists() else []

    # ----------------------------------------------------------------- read

    def head(self, chain_id: str) -> tuple[int, str] | None:
        """`(seq, entry_hash)` of the tail, or None when the chain is empty.

        None is REMOTE.md section 4's 404: "no entries yet", which a fresh
        writer reads as `(seq=-1, GENESIS)`. It is never an error.
        """
        last = read_last_line(self.active_trail_path(chain_id))
        if last is None:
            return None
        obj = json.loads(last)
        return int(obj["header"]["seq"]), str(obj["entry_hash"])

    def page(
        self, chain_id: str, *, cursor: str | None, limit: int
    ) -> tuple[list[dict[str, Any]], str | None]:
        """One page of stored envelopes from ONE segment, in append order —
        never re-sorted.

        Sorting by `seq` would hide a storage-order reorder from the client's
        own verifier, which is exactly the failure `ReaderBackend.entries()`
        forbids for every other backend.

        Paging never crosses a segment boundary, and that is not a shortcut.
        Each segment is its OWN chain — seq 0, genesis `prev_hash`, linked to
        its predecessor by a binding and never by `prev_hash` across a file
        (SPEC.md section 20) — so concatenating two would hand `verify_chain`
        on the client a seq that restarts at 0. That is fork-shaped: a false
        tamper alarm the server manufactured out of its own housekeeping. A
        cursorless read is about the ACTIVE segment; a cursor names the segment
        it was issued against and finishes reading that one.
        """
        start, identity = decode_cursor(cursor)
        if identity is None:
            trail = self.active_trail_path(chain_id)
        else:
            wanted = f"{identity}{SEGMENT_SUFFIX}"
            # Resolved by matching a segment that is actually here, never by
            # joining the cursor's text onto a path: the cursor is client
            # input, and `../` in it must reach nothing.
            named = [path for path in self.segment_paths(chain_id) if path.name == wanted]
            if not named:
                raise ValueError(f"cursor names a segment this chain does not have: {cursor!r}")
            trail = named[0]
        if not trail.exists():
            return [], None
        page: list[dict[str, Any]] = []
        index = 0
        more = False
        with open(trail, encoding="utf-8", newline="") as handle:
            for line in handle:
                if not line.strip():
                    continue
                if index >= start:
                    if len(page) == limit:
                        more = True
                        break
                    page.append(json.loads(line))
                index += 1
        if not more:
            return page, None
        return page, encode_cursor(start + len(page), segment_identity(trail.name))

    def summary(self, chain_id: str) -> ChainSummary:
        """Counts and identities for one chain, without a verdict.

        A damaged receipt log yields `receipt=None` rather than raising: the
        chain is still readable, and a broken sidecar is a finding about the
        sidecar, not a reason to blank the row that would have shown it.
        """
        # Across EVERY segment, not just the live one: the question a chain row
        # answers is how much history this chain holds and what it costs, and
        # rotation must not make either number appear to fall.
        entries = 0
        size = 0
        for trail in self.segment_paths(chain_id):
            size += trail.stat().st_size
            with open(trail, encoding="utf-8", newline="") as handle:
                entries += sum(1 for line in handle if line.strip())
        try:
            receipt = self.receipt_head(chain_id)
        except (json.JSONDecodeError, KeyError, ValueError):
            receipt = None
        return ChainSummary(
            chain_id=chain_id,
            entries=entries,
            size_bytes=size,
            head=self.head(chain_id),
            receipt=receipt,
        )

    # ---------------------------------------------------------------- write

    def append(self, chain_id: str, envelope: Any) -> AppendResult:
        """Accept one entry under the CAS precondition, then acknowledge it.

        The two locks are taken in sequence, never nested: the chain's lock is
        released before the receipt log's is taken, so there is no lock-ordering
        hazard between them. The cost is that under concurrency two receipts may
        be issued in a different order than their entries landed. REMOTE.md
        section 10 defines the receipt chain as running over acknowledgments *in
        acknowledgment order*, so that is the specified behaviour rather than a
        gap — and `cross_check_receipts` keys on `seq`, so it does not care.

        A crash between the two leaves an entry with no receipt. That is the
        honest outcome: the client never saw a `201`, so nothing was ever
        acknowledged to anyone, and inventing a receipt afterwards would be the
        server claiming to remember something it did not say.
        """
        base = self.trail_path(chain_id)
        entry = parse_envelope(envelope)

        def build(next_seq: int, prev_hash: str) -> Entry:
            # Under the backend's write lock. Rejecting here — rather than after
            # a separate head read — is what makes the precondition atomic with
            # the append (REMOTE.md section 4).
            if next_seq != entry.header.seq or prev_hash != entry.header.prev_hash:
                raise PreconditionFailed(
                    f"expected (seq={next_seq}, prev_hash={prev_hash}), "
                    f"got (seq={entry.header.seq}, prev_hash={entry.header.prev_hash})"
                )
            return entry

        # Rotation first and OUTSIDE the block below, because `open_segmented`
        # takes `segments.lock` itself and J3's archive step runs after it
        # releases. Nesting the two would deadlock; wrapping them would drag a
        # network call under a writer lock, which is exactly the placement
        # `rotation._archive_sealed` argues against.
        open_segmented(
            base,
            max_segment_bytes=self._max_segment_bytes,
            notice=self._notice,
            archive=self._archive,
        )
        # Resolve the active segment and append to it under ONE hold of the
        # rotation lock. The CAS is already atomic with the append — the
        # builder runs under the backend's own per-file lock — but without this
        # hold a rotation can seal the segment between the resolve and the
        # write, and the entry lands in a file whose successor has already
        # bound it as finished.
        with segments_lock(base):
            stored = JSONLBackend(self.active_trail_path(chain_id)).append(build)
        receipt_seq, receipt_head = self._acknowledge(chain_id, stored)
        return AppendResult(
            seq=stored.header.seq,
            entry_hash=stored.entry_hash,
            receipt_seq=receipt_seq,
            receipt_head=receipt_head,
        )

    # ------------------------------------------------------------- receipts

    def receipt_head(self, chain_id: str) -> tuple[int, str] | None:
        last = read_last_line(self.receipt_log_path(chain_id))
        if last is None:
            return None
        record = json.loads(last)
        return int(record["receipt_seq"]), str(record["receipt_head"])

    def receipt_records(self, chain_id: str) -> list[dict[str, Any]] | None:
        """Every acknowledgment record, or None when the log is absent.

        None is "no log", never an empty list, and a log that cannot be parsed
        raises instead of borrowing either answer (CLAUDE.md rule 5).
        """
        path = self.receipt_log_path(chain_id)
        if not path.exists():
            return None
        try:
            return [
                json.loads(line)
                for line in path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
        except json.JSONDecodeError as exc:
            raise DamagedReceiptLog(f"{path}: {exc}") from exc

    def verify_receipt_log(self, chain_id: str) -> ReceiptLogReport:
        """Recompute the server's own acknowledgment history from its records.

        This is the check that makes the receipt chain evidence rather than a
        promise: it needs no credential and no server cooperation beyond handing
        the records over, so a third party reaches the same verdict the server
        does. Its three outcomes are SPEC.md section 19's own table.
        """
        path = self.receipt_log_path(chain_id)
        if not path.exists():
            # Absent is not "checked, found nothing" (CLAUDE.md rule 5).
            return ReceiptLogReport(Verdict.OK, checked=None, reason="not_recorded")

        chain = ReceiptChain()
        checked = 0
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                record = json.loads(line)
                version = record["v"]
            except (json.JSONDecodeError, TypeError, KeyError):
                return ReceiptLogReport(
                    Verdict.BROKEN, checked=checked, reason="malformed_receipt_record"
                )
            if version != _RECEIPT_VERSION:
                # A `v` from a newer build: unverifiable by name, never tampered.
                return ReceiptLogReport(
                    Verdict.UNVERIFIABLE, checked=checked, reason="unreadable_record_version"
                )
            try:
                stored_seq = int(record["receipt_seq"])
                stored_head = str(record["receipt_head"])
                computed_seq, computed_head = chain.acknowledge(str(record["entry_hash"]))
            except (KeyError, TypeError, ValueError):
                # Broken bytes inside this project's OWN format are a break, not
                # an unknown (SPEC.md section 17's asymmetry).
                return ReceiptLogReport(
                    Verdict.BROKEN, checked=checked, reason="malformed_receipt_record"
                )
            if stored_seq != computed_seq:
                return ReceiptLogReport(
                    Verdict.BROKEN,
                    checked=checked,
                    reason="receipt_seq_gap",
                    broken_receipt_seq=stored_seq,
                )
            if stored_head != computed_head:
                return ReceiptLogReport(
                    Verdict.BROKEN,
                    checked=checked,
                    reason="receipt_head_mismatch",
                    broken_receipt_seq=stored_seq,
                )
            checked += 1
        return ReceiptLogReport(Verdict.OK, checked=checked)

    def cross_check_receipts(self, chain_id: str) -> ReceiptCrossCheck:
        """Compare what this server acknowledged with what it is now storing.

        `verify_receipt_log` asks whether the acknowledgment log is internally
        consistent, and stays `ok` after an edit to the trail because the log
        itself was not touched. This asks the question that edit actually
        raises: does entry `seq` still carry the hash that was acknowledged for
        it? The comparison is deterministic — the same footing as a pin (SPEC.md
        section 13) — so a disagreement is a break, never unverifiable.

        Honest limit, and it is the same one SPEC.md section 19 states: a server
        that rewrote BOTH the trail and its own receipt log consistently passes
        this. What it defeats is the cheaper edit that does not also curate the
        receipts.
        """
        try:
            records = self.receipt_records(chain_id)
        except DamagedReceiptLog:
            return ReceiptCrossCheck(
                Verdict.BROKEN, checked=0, reason="malformed_receipt_record"
            )
        if records is None:
            return ReceiptCrossCheck(Verdict.OK, checked=None, reason="not_recorded")

        # seq -> the hashes stored at that seq, across every segment. A LIST
        # rather than one hash because seq restarts at 0 in each segment
        # (SPEC.md section 20), so a rotated chain holds several entries at seq
        # 3 and a receipt for any of them is satisfied by any of them. Nothing
        # is given up: an edited or deleted entry changes or removes its hash,
        # so it is absent from the list either way. On an unrotated chain every
        # list has exactly one element and this is the check it always was.
        by_seq: dict[int, list[str]] = {}
        for obj in self._stored_envelopes(chain_id):
            by_seq.setdefault(int(obj["header"]["seq"]), []).append(str(obj["entry_hash"]))
        checked = 0
        for record in records:
            if not isinstance(record, dict) or "v" not in record:
                return ReceiptCrossCheck(
                    Verdict.BROKEN, checked=checked, reason="malformed_receipt_record"
                )
            if record["v"] != _RECEIPT_VERSION:
                return ReceiptCrossCheck(
                    Verdict.UNVERIFIABLE, checked=checked, reason="unreadable_record_version"
                )
            try:
                seq = int(record["seq"])
                acknowledged = str(record["entry_hash"])
            except (KeyError, TypeError, ValueError):
                return ReceiptCrossCheck(
                    Verdict.BROKEN, checked=checked, reason="malformed_receipt_record"
                )
            if seq not in by_seq:
                # The trail is shorter than an acknowledged append: a rollback or
                # a truncation, not a missing measurement.
                return ReceiptCrossCheck(
                    Verdict.BROKEN,
                    checked=checked,
                    reason="receipt_beyond_head",
                    broken_seq=seq,
                )
            if acknowledged not in by_seq[seq]:
                return ReceiptCrossCheck(
                    Verdict.BROKEN, checked=checked, reason="receipt_mismatch", broken_seq=seq
                )
            checked += 1
        return ReceiptCrossCheck(Verdict.OK, checked=checked)

    # -------------------------------------------------------------- private

    def _stored_envelopes(self, chain_id: str) -> list[dict[str, Any]]:
        return [
            json.loads(line)
            for trail in self.segment_paths(chain_id)
            for line in trail.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    def _acknowledge(self, chain_id: str, entry: Entry) -> tuple[int, str]:
        log_path = self.receipt_log_path(chain_id)
        # The lock spans read-tail + append for the same reason the chain's own
        # does: two acknowledgements must never be issued the same receipt_seq,
        # which is the one thing REMOTE.md section 10 forbids answering twice.
        with file_lock(log_path):
            last = read_last_line(log_path)
            if last is None:
                chain = ReceiptChain()
            else:
                prior = json.loads(last)
                chain = ReceiptChain.resume(
                    int(prior["receipt_seq"]), str(prior["receipt_head"])
                )
            receipt_seq, receipt_head = chain.acknowledge(entry.entry_hash)
            record = {
                "entry_hash": entry.entry_hash,
                "receipt_head": receipt_head,
                "receipt_seq": receipt_seq,
                "seq": entry.header.seq,
                "ts": entry.header.ts,
                "v": _RECEIPT_VERSION,
            }
            with open(log_path, "a", encoding="utf-8", newline="") as handle:
                handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
                handle.flush()
        return receipt_seq, receipt_head


def encode_cursor(index: int, identity: str) -> str:
    return f"{_CURSOR_PREFIX}{index}{_CURSOR_SEGMENT_SEPARATOR}{identity}"


def decode_cursor(cursor: str | None) -> tuple[int, str | None]:
    """`(offset, segment identity)`.

    The identity is `None` only for "no cursor at all" — the first page, which
    is about whatever segment is active when it is asked for. It is never a
    guessed segment: a cursor that carries no identity is refused rather than
    aimed at the active file, because the one thing a resumed read must not do
    is silently continue in a different file.
    """
    if cursor is None:
        return 0, None
    if not cursor.startswith(_CURSOR_PREFIX):
        raise ValueError(f"unrecognized cursor {cursor!r}")
    offset, _, identity = cursor[len(_CURSOR_PREFIX) :].partition(_CURSOR_SEGMENT_SEPARATOR)
    if not offset.isdigit() or not identity:
        raise ValueError(f"unrecognized cursor {cursor!r}")
    return int(offset), identity
