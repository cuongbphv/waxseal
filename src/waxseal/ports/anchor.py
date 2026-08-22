"""AnchorSink: publishes a checkpoint somewhere the log's own writer cannot
silently rewrite it (DESIGN.md's anchoring upgrade path).

A hash chain resists edits BEHIND its tip; it cannot by itself resist an
attacker who rewrites the whole file, because every prev_hash downstream of
the edit is recomputable. Anchoring a Checkpoint's root somewhere out of that
writer's reach (a signed release, another host, a public timestamping
service) closes that gap. Real external anchors — OpenTimestamps, an RFC 3161
TSA, a pushed git commit — need tooling this zero-dependency library does not
ship; implement one of those as an AnchorSink and hand it to AuditLog.
FileAnchorSink (adapters/anchors.py) is the local baseline: a sidecar record
next to the trail, not an independent witness on its own — its own docstring
says so.
"""

from __future__ import annotations

from typing import Protocol

from waxseal.domain.checkpoint import Checkpoint


class AnchorSink(Protocol):
    name: str

    def anchor(self, checkpoint: Checkpoint) -> str | None:
        """Publish ``checkpoint``. Return an opaque receipt string, or None
        if this sink has no receipt to give. Raise on failure — a caller
        treats any exception as a failed anchor attempt, never silently as
        a "no receipt" success."""
        ...
