"""Receipt-log read, verify, and cross-check helpers.

`ChainStore` remains the facade: these functions take paths and records, never
HTTP, and never `log._backend`. The receipt chain is SPEC.md section 19.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Final

from waxseal import Entry, Verdict
from waxseal.adapters.filelock import file_lock
from waxseal.adapters.jsonl import read_last_line
from waxseal_server.domain.errors import DamagedReceiptLog
from waxseal_server.domain.receipts import ReceiptChain
from waxseal_server.domain.results import ReceiptCrossCheck, ReceiptLogReport

#: The receipt record shape this build writes and can read back (SPEC.md §19).
RECEIPT_VERSION: Final = 1


def read_receipt_head(path: Path) -> tuple[int, str] | None:
    last = read_last_line(path)
    if last is None:
        return None
    record = json.loads(last)
    return int(record["receipt_seq"]), str(record["receipt_head"])


def load_receipt_records(path: Path) -> list[dict[str, Any]] | None:
    """Every acknowledgment record, or None when the log is absent.

    None is "no log", never an empty list, and a log that cannot be parsed
    raises instead of borrowing either answer (CLAUDE.md rule 5).
    """
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


def verify_receipt_log(path: Path) -> ReceiptLogReport:
    """Recompute the server's own acknowledgment history from its records.

    This is the check that makes the receipt chain evidence rather than a
    promise: it needs no credential and no server cooperation beyond handing
    the records over, so a third party reaches the same verdict the server
    does. Its three outcomes are SPEC.md section 19's own table.
    """
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
        if version != RECEIPT_VERSION:
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


def cross_check_receipts(
    records: list[dict[str, Any]] | None,
    stored: list[dict[str, Any]],
) -> ReceiptCrossCheck:
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
    for obj in stored:
        by_seq.setdefault(int(obj["header"]["seq"]), []).append(str(obj["entry_hash"]))
    checked = 0
    for record in records:
        if not isinstance(record, dict) or "v" not in record:
            return ReceiptCrossCheck(
                Verdict.BROKEN, checked=checked, reason="malformed_receipt_record"
            )
        if record["v"] != RECEIPT_VERSION:
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


def acknowledge(log_path: Path, entry: Entry) -> tuple[int, str]:
    # The lock spans read-tail + append for the same reason the chain's own
    # does: two acknowledgements must never be issued the same receipt_seq,
    # which is the one thing REMOTE.md section 10 forbids answering twice.
    with file_lock(log_path):
        last = read_last_line(log_path)
        if last is None:
            chain = ReceiptChain()
        else:
            prior = json.loads(last)
            chain = ReceiptChain.resume(int(prior["receipt_seq"]), str(prior["receipt_head"]))
        receipt_seq, receipt_head = chain.acknowledge(entry.entry_hash)
        record = {
            "entry_hash": entry.entry_hash,
            "receipt_head": receipt_head,
            "receipt_seq": receipt_seq,
            "seq": entry.header.seq,
            "ts": entry.header.ts,
            "v": RECEIPT_VERSION,
        }
        with open(log_path, "a", encoding="utf-8", newline="") as handle:
            handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
            handle.flush()
    return receipt_seq, receipt_head
