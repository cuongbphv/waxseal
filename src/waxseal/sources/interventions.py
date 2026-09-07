"""Human-intervention source: record and read back intervention rows on a chain.

The schema lives in ``domain.intervention``; this module is the thin layer
that touches an ``AuditLog``, mirroring ``sources.decisions``. Nothing here
reimplements canonicalization or hashing: the payload goes through
``AuditLog.append``, so an intervention is hashed by exactly the same path as
every other entry and the log's redactor runs before anything is committed —
which matters because ``rationale`` is free text a human wrote while stopping
something.

Library calls only. The CLI never appends chain entries (CLAUDE.md's CLI
contract): the act of intervening happens in the deployer's own code, and so
does recording it.
"""

from __future__ import annotations

import json
from collections.abc import Iterator

from waxseal.domain.header import Entry
from waxseal.domain.intervention import (
    INTERVENTION_PAYLOAD_TYPE,
    InterventionRecord,
    from_payload,
    to_payload,
)
from waxseal.log import AuditLog


def record_intervention(log: AuditLog, record: InterventionRecord) -> Entry:
    """Append one intervention to the chain.

    The entry header's ``ts`` is the time of the act; there is no
    ``occurred_at`` in the payload for a second, disagreeable copy of it.
    """
    return log.append(payload=to_payload(record), payload_type=INTERVENTION_PAYLOAD_TYPE)


def iter_interventions(
    log: AuditLog, *, decision_ref: str | None = None
) -> Iterator[tuple[Entry, InterventionRecord | None]]:
    """Walk the trail's intervention entries in chain order.

    Yields ``(entry, record)``; ``record`` is ``None`` when those bytes do not
    parse as an intervention record. The row is still surfaced with its seq
    rather than dropped, because a reader silently skipping rows it dislikes
    is how an audit misses the interesting one (rule 6). Unreadable is not a
    tampering verdict either: ``verify`` owns that question separately.

    A ``decision_ref`` filter matches only rows that parsed. An unreadable row
    has no reference to match on and is left out rather than counted in on the
    strength of a field nobody could read — so a filtered walk is not a
    complete listing, and a caller that needs the unreadable seqs named should
    use ``scan_interventions``, whose ``unreadable`` tuple reports them.
    """
    for entry in log.entries():
        if entry.header.payload_type != INTERVENTION_PAYLOAD_TYPE:
            continue
        record: InterventionRecord | None = None
        if entry.payload is not None:
            try:
                record = from_payload(json.loads(entry.payload))
            except (ValueError, TypeError, UnicodeDecodeError):
                record = None
        if decision_ref is not None and (
            record is None or record.decision_ref != decision_ref
        ):
            continue
        yield entry, record
