"""AI incident source: record and read back serious-incident rows on a chain.

The schema and the folding live in ``domain.incident``; this module is the
thin layer that touches an ``AuditLog``, mirroring ``sources.decisions``.
Nothing here reimplements canonicalization or hashing: the payload goes
through ``AuditLog.append``, so an incident is hashed by exactly the same path
as every other entry and the log's redactor runs before anything is committed
— which matters more here than almost anywhere, because ``summary`` is free
text a human wrote in a hurry while something was on fire.

Library calls only. The CLI never appends chain entries (CLAUDE.md's CLI
contract), so recording an incident is something a deployer's own code does.
"""

from __future__ import annotations

import json
from collections.abc import Iterator

from waxseal.domain.header import Entry
from waxseal.domain.incident import (
    INCIDENT_PAYLOAD_TYPE,
    IncidentRecord,
    from_payload,
    to_payload,
)
from waxseal.log import AuditLog


def record_incident(log: AuditLog, record: IncidentRecord) -> Entry:
    """Append one incident row to the chain.

    A submission recorded later is a NEW call with the same ``incident_id``
    carrying ``report_ref``/``reported_at``, never an edit: the log is
    append-only and ``domain.incident.scan_incidents`` folds the rows.
    """
    return log.append(payload=to_payload(record), payload_type=INCIDENT_PAYLOAD_TYPE)


def iter_incidents(
    log: AuditLog, *, incident_id: str | None = None
) -> Iterator[tuple[Entry, IncidentRecord | None]]:
    """Walk the trail's incident entries in chain order, AT ROW LEVEL.

    Yields ``(entry, record)`` per row, with no folding: which rows restate
    which incident is ``domain.incident.scan_incidents``'s question, and an
    iterator that answered it would hide the restatement history behind its
    own result.

    ``record`` is ``None`` when those bytes do not parse as an incident
    record. The row is still surfaced with its seq rather than dropped,
    because a reader silently skipping rows it dislikes is how an audit misses
    the interesting one (rule 6). Unreadable is not a tampering verdict
    either: ``verify`` owns that question and answers it separately.

    An ``incident_id`` filter matches only rows that parsed. An unreadable row
    has no id to match on and is left out rather than counted in on the
    strength of a field nobody could read — so a filtered walk is not a
    complete listing, and a caller that needs the unreadable seqs named should
    use ``scan_incidents``, whose ``unreadable`` tuple reports them.
    """
    for entry in log.entries():
        if entry.header.payload_type != INCIDENT_PAYLOAD_TYPE:
            continue
        record: IncidentRecord | None = None
        if entry.payload is not None:
            try:
                record = from_payload(json.loads(entry.payload))
            except (ValueError, TypeError, UnicodeDecodeError):
                record = None
        if incident_id is not None and (record is None or record.incident_id != incident_id):
            continue
        yield entry, record
