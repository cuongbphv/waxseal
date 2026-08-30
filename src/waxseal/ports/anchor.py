"""AnchorSink: publishes a checkpoint somewhere the log's own writer cannot
silently rewrite it (DESIGN.md's anchoring upgrade path).

A hash chain resists edits BEHIND its tip; it cannot by itself resist an
attacker who rewrites the whole file, because every prev_hash downstream of
the edit is recomputable. Anchoring a Checkpoint's root somewhere out of that
writer's reach (a signed release, another host, a public timestamping
service) closes that gap. Two real external anchors ship as AnchorSinks:
Rfc3161AnchorSink (adapters/rfc3161.py) and OtsAnchorSink (adapters/ots.py).
Others (a pushed git commit, a signed release) need tooling outside this
package; implement one as an AnchorSink and hand it to AuditLog.
FileAnchorSink (adapters/anchors.py) is the local baseline: a sidecar record
next to the trail, not an independent witness on its own, and its own docstring
says so.
"""

from __future__ import annotations

from typing import Protocol

from waxseal.domain.checkpoint import Checkpoint, SinkReceipt


class AnchorSink(Protocol):
    name: str

    def anchor(self, checkpoint: Checkpoint) -> str | SinkReceipt | None:
        """Publish ``checkpoint``. Return an opaque receipt string, a
        ``SinkReceipt`` when request material (an RFC 3161 nonce) must be
        stored for later re-verification, or None if this sink has no
        receipt to give. Raise on failure, since a caller treats any exception
        as a failed anchor attempt, never silently as a "no receipt"
        success."""
        ...
