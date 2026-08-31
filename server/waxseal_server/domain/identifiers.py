"""Identifier shapes, checked before anything is joined to a path.

Every id in this server eventually becomes a directory or file name. Validating
the VALUE rather than the resolved path means there is no normalization to get
subtly wrong and no `..` to reason about: a name either matches the pattern or
it never reaches the filesystem.

Three shapes, deliberately separate rather than one permissive pattern —
`chain_id` and `witness_id` are operator-chosen, `import_id` is server-issued
and therefore much narrower.
"""

from __future__ import annotations

import re
from typing import Final

from waxseal_server.domain.errors import InvalidIdentifier, MalformedEnvelope

#: Operator-chosen names: a leading alphanumeric, then the usual safe set.
SAFE_NAME_RE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
#: Server-issued: `uuid4().hex`, and nothing else is ever a valid import id.
IMPORT_ID_RE: Final = re.compile(r"^[0-9a-f]{32}$")
HEX64_RE: Final = re.compile(r"^[0-9a-f]{64}$")


def require_chain_id(chain_id: str) -> str:
    if not isinstance(chain_id, str) or not SAFE_NAME_RE.match(chain_id):
        raise InvalidIdentifier(
            "chain_id must be 1-64 characters of [A-Za-z0-9._-] starting alphanumeric, "
            f"got {chain_id!r}"
        )
    return chain_id


def require_witness_id(witness_id: str) -> str:
    if not isinstance(witness_id, str) or not SAFE_NAME_RE.match(witness_id):
        raise InvalidIdentifier(
            f"witness id must be a safe path segment, got {witness_id!r}"
        )
    return witness_id


def is_import_id(value: str) -> bool:
    return bool(IMPORT_ID_RE.match(value))


def require_import_id(import_id: str) -> str:
    if not is_import_id(import_id):
        raise InvalidIdentifier(f"import id must be 32 hex characters, got {import_id!r}")
    return import_id


def is_hex64(value: object) -> bool:
    return isinstance(value, str) and bool(HEX64_RE.match(value))


def require_hex64(value: object, field: str) -> str:
    """Field-level check for the wire formats, raising the 400-shaped error."""
    if not is_hex64(value):
        raise MalformedEnvelope(f"{field} must be 64 lowercase hex characters, got {value!r}")
    return str(value)
