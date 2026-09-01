"""Per-append receipts (SPEC.md section 19), the pure half.

A receipt is a second authority's acknowledgment, made at write time, that
entry `seq` carried `entry_hash` the moment it was accepted (the server-side
chain that issues them is REMOTE.md section 10). Anchoring bounds a rewrite to
the window since the last checkpoint; a receipt bounds it to a single entry,
because an edit to any acknowledged entry contradicts a stored record from the
very next append onward.

Not to be confused with `domain/rfc3161.py`'s receipt, which is a timestamp
authority's opaque token for a checkpoint. This one is per-append and is this
project's own format, which is exactly why its failures are classified the way
they are below.

Reconciliation is a DETERMINISTIC comparison between two of this project's own
artifacts — the same footing as a pin (section 13) — so a disagreement is a
break, never "unverifiable". The one exception is section 17's asymmetry:
corrupt bytes in a format this project defines are a break, while a record
stamped with a version only a NEWER build understands is unverifiable by name.
Collapsing those two is the beads-v1.2.2 failure class rebuilt inside the
sidecar's own parser.

Honest limit (SPEC.md section 19, stated so no caller can imply otherwise):
the sidecar is as attacker-writable as the trail beside it. A rewrite that
curates BOTH consistently passes this check; only the server's own receipt
chain catches that. What this defeats is the cheaper attack — a trail edit
that does not also curate the sidecar.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Final

from waxseal.domain.verdict import Verdict

# The record version this build writes and reads. Append-only like every other
# version identity here: a new field set is a new version, never a redefinition
# of this one.
RECEIPT_RECORD_VERSION: Final = 1
KNOWN_RECORD_VERSIONS: Final = frozenset({RECEIPT_RECORD_VERSION})

RECEIPT_MISMATCH: Final = "receipt_mismatch"
RECEIPT_BEYOND_HEAD: Final = "receipt_beyond_head"
MALFORMED_RECEIPT_RECORD: Final = "malformed_receipt_record"
UNREADABLE_RECORD_VERSION: Final = "unreadable_record_version"

RECEIPT_HEX64: Final = frozenset("0123456789abcdef")


@dataclass(frozen=True, slots=True)
class ReceiptRecord:
    """One readable line of the `.receipts` sidecar."""

    line_no: int
    seq: int
    entry_hash: str
    receipt_seq: int
    receipt_head: str
    source: str
    ts: str


@dataclass(frozen=True, slots=True)
class MalformedRecord:
    """A line in a version this build DOES know, whose bytes it still cannot
    read. This project's own format, so this is a break (section 17)."""

    line_no: int
    detail: str


@dataclass(frozen=True, slots=True)
class UnreadableRecord:
    """A line stamped with a version this build does not know. Unverifiable by
    name: recomputing a verdict over a shape whose meaning this build was never
    told is the one lie a tamper-evidence mechanism must not tell."""

    line_no: int
    version: str


ReceiptLine = ReceiptRecord | MalformedRecord | UnreadableRecord


@dataclass(frozen=True, slots=True)
class ReceiptSidecar:
    """What a verifier was given, in file order.

    ``present`` is not derivable from ``lines``: no sidecar at all ("not
    recorded") and a sidecar holding no records ("checked, found nothing") are
    different evidential states, and rule 5 forbids rendering the first as the
    second.
    """

    present: bool
    lines: tuple[ReceiptLine, ...] = ()


@dataclass(frozen=True, slots=True)
class ReceiptReconciliation:
    verdict: Verdict
    reason: str | None
    checked: int
    # None for a malformed record: naming a seq would mean inventing the very
    # field that failed to parse.
    broken_seq: int | None
    broken_line: int | None
    present: bool
    latest_seq: int | None = None
    unreadable_versions: tuple[str, ...] = field(default=())


def build_receipt_record(
    *,
    seq: int,
    entry_hash: str,
    receipt_seq: int,
    receipt_head: str,
    source: str,
    ts: str,
) -> dict[str, Any]:
    """The sidecar record SPEC.md section 19 defines, and nothing else.

    No payload field exists to accidentally populate: section 12's rule, for
    section 12's reason — the payload has not been through redact-before-hash
    at the point a sidecar sees it.
    """
    return {
        "entry_hash": entry_hash,
        "receipt_head": receipt_head,
        "receipt_seq": receipt_seq,
        "seq": seq,
        "source": source,
        "ts": ts,
        "v": RECEIPT_RECORD_VERSION,
    }


def parse_receipt_line(line: str, *, line_no: int) -> ReceiptLine:
    """Classify one sidecar line. Never raises: a verdict, never a crash.

    The version stamp is read before anything else, so a record from a newer
    build is reported unverifiable even when its other fields look wrong to
    this one — those fields mean whatever the newer format says they mean.
    """
    try:
        obj = json.loads(line)
    except ValueError as e:
        return MalformedRecord(line_no=line_no, detail=f"not JSON: {e}")
    if not isinstance(obj, dict):
        return MalformedRecord(
            line_no=line_no, detail=f"record must be a JSON object, got {type(obj).__name__}"
        )
    version = obj.get("v", RECEIPT_RECORD_VERSION)
    if not isinstance(version, int) or isinstance(version, bool):
        # A version stamp is an integer by definition, so a list/string/object
        # here is not a shape from some newer build — it is corrupt bytes in
        # this project's own format. Reading it as "unverifiable" would hand an
        # attacker a one-field lever to downgrade any break to exit 2. (Found
        # by the never-raise fuzz sweep, which crashed on an unhashable `v`.)
        return MalformedRecord(
            line_no=line_no, detail=f"v must be an integer version stamp, got {version!r}"
        )
    if version not in KNOWN_RECORD_VERSIONS:
        return UnreadableRecord(line_no=line_no, version=str(version))
    try:
        return ReceiptRecord(
            line_no=line_no,
            seq=_index(obj, "seq"),
            entry_hash=_hex64(obj, "entry_hash"),
            receipt_seq=_index(obj, "receipt_seq"),
            receipt_head=_hex64(obj, "receipt_head"),
            # Metadata, not evidence: absent because the writer predates the
            # field is not a reason to call the acknowledgment unreadable.
            source=str(obj.get("source", "unknown")),
            ts=str(obj.get("ts", "")),
        )
    except (KeyError, TypeError, ValueError) as e:
        return MalformedRecord(line_no=line_no, detail=str(e))


def reconcile_receipts(
    entry_hashes: Sequence[str], sidecar: ReceiptSidecar
) -> ReceiptReconciliation:
    """Compare every readable record against the trail's own hashes.

    Reports the FIRST break in file order and stops judging further records,
    the same discipline `verify_chain` follows: which record is the tamper is a
    decision only an operator can make.
    """
    verdict = Verdict.OK
    reason: str | None = None
    broken_seq: int | None = None
    broken_line: int | None = None
    checked = 0
    latest_seq: int | None = None
    unreadable: list[str] = []

    for entry in sidecar.lines:
        if isinstance(entry, UnreadableRecord):
            unreadable.append(entry.version)
            continue
        if isinstance(entry, MalformedRecord):
            if verdict is not Verdict.BROKEN:
                verdict, reason = Verdict.BROKEN, MALFORMED_RECEIPT_RECORD
                broken_line = entry.line_no
            continue
        checked += 1
        latest_seq = entry.seq if latest_seq is None else max(latest_seq, entry.seq)
        if verdict is Verdict.BROKEN:
            continue
        if entry.seq >= len(entry_hashes):
            verdict, reason = Verdict.BROKEN, RECEIPT_BEYOND_HEAD
            broken_seq, broken_line = entry.seq, entry.line_no
        elif entry_hashes[entry.seq] != entry.entry_hash:
            verdict, reason = Verdict.BROKEN, RECEIPT_MISMATCH
            broken_seq, broken_line = entry.seq, entry.line_no

    if unreadable and verdict is Verdict.OK:
        verdict, reason = Verdict.UNVERIFIABLE, UNREADABLE_RECORD_VERSION
    return ReceiptReconciliation(
        verdict=verdict,
        reason=reason,
        checked=checked,
        broken_seq=broken_seq,
        broken_line=broken_line,
        present=sidecar.present,
        latest_seq=latest_seq,
        unreadable_versions=tuple(unreadable),
    )


def _index(obj: dict[str, Any], key: str) -> int:
    value = obj[key]
    # bool is an int in Python: `true` must never become seq 1.
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"{key} must be an integer, got {type(value).__name__}")
    if value < 0:
        raise ValueError(f"{key} must be non-negative, got {value}")
    return value


def _hex64(obj: dict[str, Any], key: str) -> str:
    value = obj[key]
    if not isinstance(value, str) or len(value) != 64 or not set(value) <= RECEIPT_HEX64:
        raise ValueError(f"{key} must be 64 lowercase hex characters, got {value!r}")
    return value
