"""Operators, roles and API keys.

The role table below is the product's own sentence about itself, and the shape
of it matters more than the contents: **no role can edit an entry**, because no
such scope exists to grant. "Verify reports, never repairs" (CLAUDE.md rule 4)
is unrepresentable here rather than merely unimplemented, and the test suite
asserts that by walking every scope of every role.

A key's plaintext exists exactly once, at mint. Only its SHA-256 is stored, so
the store cannot show a key again — and cannot leak every key at once either.
There is no password anywhere in this module: the key IS the credential, which
is why this server has no login form to fake.
"""

from __future__ import annotations

import enum
import hashlib
import re
import secrets
import uuid
from dataclasses import dataclass
from typing import Final

from waxseal_server.domain.errors import InvalidIdentifier

ScopeSet = frozenset[str]

#: 24 random bytes → 32 base64url characters → 192 bits. Comfortably past the
#: 128 the test floors it at, and short enough to paste.
_SECRET_BYTES: Final = 24

KEY_PREFIX: Final = "wxs_live_"

#: Lowercase on purpose: usernames appear in URLs and log lines, and a store
#: that treats `Admin` and `admin` as two identities is a store with two admins.
_USERNAME_RE: Final = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")

#: How much of a key is safe to show: enough to tell two apart in a list,
#: nowhere near enough to reconstruct one.
_SHOWN_CHARS: Final = 4


class Role(enum.Enum):
    """Who an operator is. Parsed strictly — see `Role("superuser")`.

    Defaulting an unrecognised role would be a silent downgrade or a silent
    escalation depending on which way it defaulted, and both are worse than a
    refusal.
    """

    ADMIN = "admin"
    AUDITOR = "auditor"
    WRITER = "writer"
    VIEWER = "viewer"


# Scope vocabulary. Every one is a read, a verify, an append, or key
# administration. There is deliberately no `entries:edit`, no `entries:delete`
# and no `trails:repair`.
SCOPE_TRAILS_READ: Final = "trails:read"
SCOPE_HEAD_READ: Final = "head:read"
SCOPE_ENTRIES_APPEND: Final = "entries:append"
SCOPE_VERIFY_RUN: Final = "verify:run"
SCOPE_PROOF_EXPORT: Final = "proof:export"
SCOPE_IMPORT_WRITE: Final = "import:write"
SCOPE_KEYS_MANAGE: Final = "keys:manage"
SCOPE_PUBLIC_READ: Final = "public:read"

_SCOPES: Final[dict[Role, ScopeSet]] = {
    # Manages the server, its operators and its keys — and still cannot edit an
    # entry, because nobody can.
    Role.ADMIN: frozenset(
        {
            SCOPE_TRAILS_READ,
            SCOPE_HEAD_READ,
            SCOPE_ENTRIES_APPEND,
            SCOPE_VERIFY_RUN,
            SCOPE_PROOF_EXPORT,
            SCOPE_IMPORT_WRITE,
            SCOPE_KEYS_MANAGE,
            SCOPE_PUBLIC_READ,
        }
    ),
    Role.AUDITOR: frozenset(
        {
            SCOPE_TRAILS_READ,
            SCOPE_HEAD_READ,
            SCOPE_VERIFY_RUN,
            SCOPE_PROOF_EXPORT,
            SCOPE_IMPORT_WRITE,
            SCOPE_PUBLIC_READ,
        }
    ),
    # The machine account. It extends the chain and discovers the tail it is
    # extending; it cannot read what is on the chain, which is what keeps a
    # leaked writer key from becoming a leaked audit trail.
    Role.WRITER: frozenset({SCOPE_ENTRIES_APPEND, SCOPE_HEAD_READ}),
    Role.VIEWER: frozenset({SCOPE_TRAILS_READ, SCOPE_PUBLIC_READ}),
}


def scopes_for_role(role: Role) -> ScopeSet:
    """The scopes a role grants. Immutable: one request's check must not be
    able to widen the next request's permissions."""
    return _SCOPES[role]


def hash_key(plaintext: str) -> str:
    """SHA-256 of the whole key, lowercase hex — the only form ever stored."""
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


def mint_key() -> tuple[str, str]:
    """A fresh key and its fingerprint. The plaintext is returned once, here."""
    plaintext = KEY_PREFIX + secrets.token_urlsafe(_SECRET_BYTES)
    return plaintext, hash_key(plaintext)


def new_key_id() -> str:
    """A public, non-secret handle for a key, safe to put in a URL."""
    return uuid.uuid4().hex


def key_fingerprint(plaintext: str) -> str:
    """The display form: `wxs_live_9f2k…`.

    Shown in listings so an operator can recognise which key a row is about.
    Four characters of a 192-bit secret narrows a handful of keys to one and
    brute-forces nothing.
    """
    if not plaintext.startswith(KEY_PREFIX):
        raise ValueError(f"not a waxseal API key: {plaintext[:12]!r}…")
    body = plaintext[len(KEY_PREFIX) :]
    return KEY_PREFIX + body[:_SHOWN_CHARS] + "…"


@dataclass(frozen=True, slots=True)
class Operator:
    """Who is acting. `username` is the identity and never changes."""

    username: str
    display_name: str
    email: str | None
    role: Role
    created_at: str
    active: bool = True

    @property
    def scopes(self) -> ScopeSet:
        # An inactive operator keeps its role and grants nothing, so a
        # deactivation cannot be undone by forgetting which role it had.
        return scopes_for_role(self.role) if self.active else frozenset()


@dataclass(frozen=True, slots=True)
class ApiKey:
    """A credential, described. The secret itself is not in here and cannot be.

    `fingerprint` is the display form (`wxs_live_9f2k…`); the SHA-256 lives in
    the store and never reaches this record, so handing an `ApiKey` to a
    template cannot leak one.
    """

    key_id: str
    username: str
    label: str
    fingerprint: str
    created_at: str
    last_used_at: str | None = None
    revoked_at: str | None = None

    @property
    def active(self) -> bool:
        return self.revoked_at is None


@dataclass(frozen=True, slots=True)
class Principal:
    """An authenticated caller: who, by which key, with which scopes.

    `key_id is None` marks the bootstrap credential (`WAXSEAL_API_KEY`), which
    exists so a fresh deployment can mint its first real key. It is not an
    operator and is not in the store, and `preflight`-style output should say so
    rather than showing it as a user.
    """

    operator: Operator
    key_id: str | None
    scopes: ScopeSet

    def allows(self, scope: str) -> bool:
        return scope in self.scopes


def require_username(username: str) -> str:
    if not isinstance(username, str) or not _USERNAME_RE.match(username):
        raise InvalidIdentifier(
            "username must be 1-64 characters of [a-z0-9._-] starting alphanumeric, "
            f"got {username!r}"
        )
    return username
