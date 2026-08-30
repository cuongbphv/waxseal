"""DropRecorder: records that a write was lost, without ever becoming a
second way for a write to be lost.

CLAUDE.md rule 5: ``dropped_writes: int | None`` reports completeness
separate from chain integrity, and ``None`` (never measured) must never
collapse into ``0`` (measured, zero seen). A DropRecorder is how that
measurement gets made durable across process restarts (log.py's own
in-memory counter resets to 0 every time a new AuditLog is opened).

Implementations MUST NOT raise from ``record()``. It is invoked from the
caller's own failure path (``try_append``'s except-block), so a recorder that
raises there would turn "one write was dropped" into "the drop was never
recorded AND the calling code path breaks too," which is a strictly worse
failure than the one it exists to measure.
"""

from __future__ import annotations

from typing import Protocol


class DropRecorder(Protocol):
    def record(
        self, *, reason: str, payload_type: str | None = None, source: str = "library"
    ) -> None:
        """Record that a write was dropped. Never raises.

        ``reason`` is the exception type name or a short cause string.
        ``payload_type`` is metadata only: the payload itself must never
        appear here; it has not gone through redact-before-hash by the time
        a drop can occur, so recording it would be exactly the cleartext
        leak CLAUDE.md's redaction rule exists to prevent.
        """
        ...
