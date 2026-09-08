"""The shared sanitizer every redacting integration re-exports.

Field maps stay on the host modules. This module is the last gate a host
value passes before it is hashed: redact-before-hash, then a visible clip.
A clip that ran first could split a secret across the boundary (a PEM
losing its END marker stops matching) and land cleartext on disk.

`hermes_gateway` is NOT a caller: its `_sanitize` does not redact or clip
strings, because AuditLog's own redactor covers that path there.
"""

from __future__ import annotations

from typing import Any

from waxseal.adapters.redactors import RegexRedactor

# Tool outputs can be megabytes. Clip stored fields, visibly, because silent
# truncation would read as "the full output".
MAX_FIELD_CHARS = 4096

_REDACTOR = RegexRedactor()


def clip(text: str) -> str:
    if len(text) <= MAX_FIELD_CHARS:
        return text
    return text[:MAX_FIELD_CHARS] + f"…[truncated {len(text) - MAX_FIELD_CHARS} chars]"


def sanitize(value: Any) -> Any:
    """Keep the payload JSON-serializable and bounded whatever the host holds."""
    if value is None or isinstance(value, (int, float, bool)):
        return value
    if isinstance(value, str):
        return clip(_REDACTOR.redact_text(value))
    if isinstance(value, dict):
        return {str(k): sanitize(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [sanitize(v) for v in value]
    return clip(_REDACTOR.redact_text(repr(value)))
