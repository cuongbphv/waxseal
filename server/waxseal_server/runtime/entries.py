"""Entries rendered for a viewer.

Reading entries to display them is not a verdict, which is why this is the one
read that uses the `AuditLog` facade instead of the CLI: `waxseal tail` prints a
one-line human summary, and a viewer needs the envelope. It stays on
`log.entries()` and never reaches for `log._backend` — the same boundary
`sources/` is held to.

The payload handed back is base64 of the bytes on disk, and those bytes were
redacted BEFORE they were hashed. There is no un-redaction step here, and adding
one would not merely leak a secret: it would produce bytes that do not hash to
the `payload_hash` the chain committed to.
"""

from __future__ import annotations

import base64
import itertools
from pathlib import Path
from typing import Any

from waxseal import AuditLog


def read_entries_for_display(trail: Path | str, *, limit: int) -> list[dict[str, Any]]:
    """Up to `limit` entries in storage order, as SPEC.md section 7 envelopes.

    Storage order, never re-sorted by `seq`: a viewer that tidied the order
    would hide exactly the reordering a verifier exists to catch.

    Raises whatever `AuditLog.open` raises for a path it has no backend for —
    "could not read" must not arrive at a screen looking like "nothing to read".
    """
    log = AuditLog.open(trail)
    return [
        {
            "header": {
                "seq": entry.header.seq,
                "ts": entry.header.ts,
                "hash_version": entry.header.hash_version,
                "payload_type": entry.header.payload_type,
                "payload_hash": entry.header.payload_hash,
                "prev_hash": entry.header.prev_hash,
            },
            "entry_hash": entry.entry_hash,
            "payload_b64": base64.b64encode(entry.payload or b"").decode("ascii"),
        }
        for entry in itertools.islice(log.entries(), limit)
    ]
