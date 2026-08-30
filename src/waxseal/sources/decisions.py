"""AI decision source: record and read back model decisions on a chain.

The schema lives in ``domain.decision``; this module is the thin layer that
touches an ``AuditLog``, mirroring ``sources.files``. Nothing here reimplements
canonicalization or hashing: the payload goes through ``AuditLog.append``, so
a decision is hashed by exactly the same path as every other entry and the
log's redactor runs before anything is committed.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from typing import Any

from waxseal.domain.canonical import canonical_json
from waxseal.domain.decision import (
    DECISION_PAYLOAD_TYPE,
    DecisionRecord,
    from_payload,
    to_payload,
)
from waxseal.domain.header import Entry
from waxseal.log import AuditLog
from waxseal.ports.redact import Redactor


def commit_input(
    payload: dict[str, Any] | bytes, *, redactor: Redactor | None = None
) -> str:
    """SHA-256 over the canonical bytes of a model input, which is what a decision
    record commits to instead of the input itself, so the trail carries no
    customer data.

    Pass the same ``redactor`` the log uses. Redaction runs first, exactly as
    it does on the append path: the commitment then binds the redacted form,
    and cannot be used as an oracle to confirm a guess at the cleartext
    secret. Committing to unredacted bytes would put that oracle in the trail.

    A ``bytes`` input with a redactor is refused rather than passed through:
    the ``Redactor`` port only sees dicts, so "redacted" would be a claim
    nothing checked, and a fail-open guard must be labelled, never silent
    (CLAUDE.md rule 6), and here it can simply be prevented.

    Standard limit of any hash commitment: over a low-entropy input it is
    *confirmable*: someone who can guess the input can verify the guess.
    Commit to a redacted or salted form where that matters.
    """
    if isinstance(payload, bytes):
        if redactor is not None:
            raise ValueError(
                "a redactor cannot inspect bytes; redact the input as a dict, "
                "or commit the bytes without claiming they were redacted"
            )
        return hashlib.sha256(payload).hexdigest()
    if not isinstance(payload, dict):
        raise TypeError(f"payload must be dict or bytes, got {type(payload).__name__}")
    if redactor is not None:
        payload = redactor.redact(payload)
    return hashlib.sha256(canonical_json(payload)).hexdigest()


def record_decision(log: AuditLog, record: DecisionRecord) -> Entry:
    """Append one decision to the chain."""
    return log.append(payload=to_payload(record), payload_type=DECISION_PAYLOAD_TYPE)


def iter_decisions(
    log: AuditLog, *, decision_type: str | None = None
) -> Iterator[tuple[Entry, DecisionRecord | None]]:
    """Walk the trail's decision entries in chain order.

    Yields ``(entry, record)``; ``record`` is ``None`` when those bytes do not
    parse as a decision record. The row is still surfaced with its seq rather
    than dropped, because a reader silently skipping rows it dislikes is how
    an audit misses the interesting one (rule 6). Unparseable is not a
    tampering verdict either: ``verify`` owns that question and answers it
    separately.

    A ``decision_type`` filter matches only rows that parsed; an unparseable
    row has no type to match on and is left out rather than counted in on the
    strength of a field nobody could read.
    """
    for entry in log.entries():
        if entry.header.payload_type != DECISION_PAYLOAD_TYPE:
            continue
        record: DecisionRecord | None = None
        if entry.payload is not None:
            try:
                record = from_payload(json.loads(entry.payload))
            except (ValueError, TypeError, UnicodeDecodeError):
                record = None
        if decision_type is not None and (
            record is None or record.decision_type != decision_type
        ):
            continue
        yield entry, record
