"""Multi-chain storage behind the REMOTE.md endpoints.

The write path uses waxseal as a LIBRARY, through `JSONLBackend.append`, whose
builder callback is invoked with `(next_seq, prev_hash)` while the backend's own
file lock is held. That is what makes the compare-and-set of REMOTE.md section 4
atomic with the append rather than a check racing beside it: rejecting inside the
builder happens under the same lock that decided the tail. CLAUDE.md rule 7 is
the library-side statement of the same requirement, and a server that lets two
POSTs win the same `seq` has forked the chain.

One import reaches past the library's public API on purpose. `_read_last_line`
is format-critical: a second implementation of an O(1) JSONL tail read in this
repository is a second thing that can drift, and it lives in the same repository,
versioned and CI-run together, so a change to it breaks these tests in the same
commit.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Final

from waxseal import Entry, Verdict
from waxseal.adapters.filelock import file_lock
from waxseal.adapters.jsonl import JSONLBackend, _read_last_line
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

#: Opaque to clients (REMOTE.md section 4). The prefix exists so a cursor from
#: some other server, or a hand-typed integer, is rejected rather than silently
#: interpreted as an offset into this one.
_CURSOR_PREFIX: Final = "e"

#: The receipt record shape this build writes and can read back (SPEC.md §19).
_RECEIPT_VERSION: Final = 1


class ChainStore:
    """One directory per `chain_id` under `root`, each a fully separate chain."""

    def __init__(self, root: Path | str) -> None:
        self._root = Path(root).expanduser()

    # ---------------------------------------------------------------- paths

    def chain_dir(self, chain_id: str) -> Path:
        return self._root / require_chain_id(chain_id)

    def trail_path(self, chain_id: str) -> Path:
        return self.chain_dir(chain_id) / TRAIL_NAME

    def receipt_log_path(self, chain_id: str) -> Path:
        return self.chain_dir(chain_id) / RECEIPT_LOG_NAME

    def chain_ids(self) -> list[str]:
        if not self._root.is_dir():
            return []
        return sorted(
            child.name
            for child in self._root.iterdir()
            if child.is_dir() and (child / TRAIL_NAME).exists()
        )

    # ----------------------------------------------------------------- read

    def head(self, chain_id: str) -> tuple[int, str] | None:
        """`(seq, entry_hash)` of the tail, or None when the chain is empty.

        None is REMOTE.md section 4's 404: "no entries yet", which a fresh
        writer reads as `(seq=-1, GENESIS)`. It is never an error.
        """
        last = _read_last_line(self.trail_path(chain_id))
        if last is None:
            return None
        obj = json.loads(last)
        return int(obj["header"]["seq"]), str(obj["entry_hash"])

    def page(
        self, chain_id: str, *, cursor: str | None, limit: int
    ) -> tuple[list[dict[str, Any]], str | None]:
        """One page of stored envelopes, in append order — never re-sorted.

        Sorting by `seq` would hide a storage-order reorder from the client's
        own verifier, which is exactly the failure `ReaderBackend.entries()`
        forbids for every other backend.
        """
        start = decode_cursor(cursor)
        trail = self.trail_path(chain_id)
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
        return page, encode_cursor(start + len(page)) if more else None

    def summary(self, chain_id: str) -> ChainSummary:
        """Counts and identities for one chain, without a verdict.

        A damaged receipt log yields `receipt=None` rather than raising: the
        chain is still readable, and a broken sidecar is a finding about the
        sidecar, not a reason to blank the row that would have shown it.
        """
        trail = self.trail_path(chain_id)
        entries = 0
        size = 0
        if trail.exists():
            size = trail.stat().st_size
            with open(trail, encoding="utf-8", newline="") as handle:
                entries = sum(1 for line in handle if line.strip())
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
        trail = self.trail_path(chain_id)
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

        stored = JSONLBackend(trail).append(build)
        receipt_seq, receipt_head = self._acknowledge(chain_id, stored)
        return AppendResult(
            seq=stored.header.seq,
            entry_hash=stored.entry_hash,
            receipt_seq=receipt_seq,
            receipt_head=receipt_head,
        )

    # ------------------------------------------------------------- receipts

    def receipt_head(self, chain_id: str) -> tuple[int, str] | None:
        last = _read_last_line(self.receipt_log_path(chain_id))
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

        by_seq = {
            int(obj["header"]["seq"]): str(obj["entry_hash"])
            for obj in self._stored_envelopes(chain_id)
        }
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
            if by_seq[seq] != acknowledged:
                return ReceiptCrossCheck(
                    Verdict.BROKEN, checked=checked, reason="receipt_mismatch", broken_seq=seq
                )
            checked += 1
        return ReceiptCrossCheck(Verdict.OK, checked=checked)

    # -------------------------------------------------------------- private

    def _stored_envelopes(self, chain_id: str) -> list[dict[str, Any]]:
        trail = self.trail_path(chain_id)
        if not trail.exists():
            return []
        return [
            json.loads(line)
            for line in trail.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    def _acknowledge(self, chain_id: str, entry: Entry) -> tuple[int, str]:
        log_path = self.receipt_log_path(chain_id)
        # The lock spans read-tail + append for the same reason the chain's own
        # does: two acknowledgements must never be issued the same receipt_seq,
        # which is the one thing REMOTE.md section 10 forbids answering twice.
        with file_lock(log_path):
            last = _read_last_line(log_path)
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


def encode_cursor(index: int) -> str:
    return f"{_CURSOR_PREFIX}{index}"


def decode_cursor(cursor: str | None) -> int:
    if cursor is None:
        return 0
    if not cursor.startswith(_CURSOR_PREFIX) or not cursor[len(_CURSOR_PREFIX) :].isdigit():
        raise ValueError(f"unrecognized cursor {cursor!r}")
    return int(cursor[len(_CURSOR_PREFIX) :])
