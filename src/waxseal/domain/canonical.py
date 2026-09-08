"""Canonical JSON payload bytes: the single owner of this serialization.

The chain commits to `payload_hash`, so what "the same payload" means is
decided entirely by these four options. Two producers that disagree about key
order or separator whitespace produce different hashes for identical data and
the disagreement surfaces later as a false tampering report, the same class
of failure as an unversioned schema widening, one layer down.

It lives here, alone, so a second copy cannot drift from the first: `AuditLog`
hashes payloads with it and `sources.decisions.commit_input` commits to model
inputs with it, and both are then hashing the same bytes by construction.

`ensure_ascii=True` is deliberate: it costs bytes for non-Latin text but makes
the frame independent of any downstream tool's Unicode normalization or
encoding assumptions, which is the property a byte-exact audit needs. This is
part of the on-disk format, so changing any option here is a SPEC break, not a
refactor, and the golden vectors will say so.
"""

from __future__ import annotations

import json
from typing import Any


def canonical_json(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )
