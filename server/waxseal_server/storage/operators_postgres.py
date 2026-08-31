"""`OperatorStore` on PostgreSQL — the server's own data, and only that.

This database holds operators and their API keys. It does NOT hold trails. A
trail stays a file the stock `waxseal verify` can read on any machine, because
the moment a trail lives only in this database, this server becomes the only
thing that can verify it — which is exactly the trust concentration the public
read point exists to remove. The waxseal library and its CLI know nothing about
Postgres and must not learn.

The connection factory is INJECTED, the same discipline the library's own
`PostgresBackend` follows: this module names no driver, opens no pool of its
own, and can be pointed at a test database by handing it a different callable.

Uniqueness is enforced by the database (`PRIMARY KEY` on username,
`UNIQUE` on the key hash) rather than by a read-then-write in Python. Two
processes seeding at once is then a constraint violation, not a race that
quietly leaves one admin overwriting another.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Final

from waxseal_server.domain.clock import utc_now
from waxseal_server.domain.errors import NoSuchOperator, OperatorExists
from waxseal_server.domain.operators import (
    ApiKey,
    Operator,
    Principal,
    Role,
    hash_key,
    key_fingerprint,
    mint_key,
    new_key_id,
    require_username,
)

Connect = Callable[[], Any]

#: `ordinal` gives a stable insertion order independent of the clock, so two
#: rows created in the same millisecond still list deterministically.
SCHEMA: Final = """
CREATE TABLE IF NOT EXISTS waxseal_operators (
    username      TEXT PRIMARY KEY,
    display_name  TEXT NOT NULL,
    email         TEXT,
    role          TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    active        BOOLEAN NOT NULL DEFAULT TRUE,
    ordinal       BIGSERIAL
);

CREATE TABLE IF NOT EXISTS waxseal_api_keys (
    key_id        TEXT PRIMARY KEY,
    username      TEXT NOT NULL REFERENCES waxseal_operators(username) ON DELETE CASCADE,
    label         TEXT NOT NULL,
    fingerprint   TEXT NOT NULL,
    key_sha256    TEXT NOT NULL UNIQUE,
    created_at    TEXT NOT NULL,
    last_used_at  TEXT,
    revoked_at    TEXT,
    ordinal       BIGSERIAL
);

CREATE INDEX IF NOT EXISTS waxseal_api_keys_username_idx
    ON waxseal_api_keys (username);
"""

_OPERATOR_COLUMNS: Final = "username, display_name, email, role, created_at, active"
_KEY_COLUMNS: Final = (
    "key_id, username, label, fingerprint, created_at, last_used_at, revoked_at"
)


def _operator(row: tuple[Any, ...]) -> Operator:
    username, display_name, email, role, created_at, active = row
    return Operator(
        username=username,
        display_name=display_name,
        email=email,
        role=Role(role),
        created_at=created_at,
        active=bool(active),
    )


def _api_key(row: tuple[Any, ...]) -> ApiKey:
    key_id, username, label, fingerprint, created_at, last_used_at, revoked_at = row
    return ApiKey(
        key_id=key_id,
        username=username,
        label=label,
        fingerprint=fingerprint,
        created_at=created_at,
        last_used_at=last_used_at,
        revoked_at=revoked_at,
    )


class PostgresOperatorStore:
    def __init__(self, connect: Connect) -> None:
        self._connect = connect
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        with self._connect() as conn:
            conn.cursor().execute(SCHEMA)
            conn.commit()

    # --------------------------------------------------------------- operators

    def create_operator(
        self, *, username: str, display_name: str, email: str | None, role: Role
    ) -> Operator:
        require_username(username)
        operator = Operator(
            username=username,
            display_name=display_name,
            email=email,
            role=role,
            created_at=utc_now(),
        )
        with self._connect() as conn:
            cur = conn.cursor()
            # ON CONFLICT DO NOTHING, then check: the database decides who won,
            # so two processes seeding at once cannot both believe they did.
            cur.execute(
                "INSERT INTO waxseal_operators "
                "(username, display_name, email, role, created_at, active) "
                "VALUES (%s, %s, %s, %s, %s, TRUE) ON CONFLICT (username) DO NOTHING",
                (username, display_name, email, role.value, operator.created_at),
            )
            created = bool(cur.rowcount == 1)
            conn.commit()
        if not created:
            raise OperatorExists(f"operator {username!r} already exists")
        return operator

    def update_operator(
        self,
        username: str,
        *,
        display_name: str | None = None,
        email: str | None = None,
        clear_email: bool = False,
        role: Role | None = None,
        active: bool | None = None,
    ) -> Operator:
        # Read-modify-write inside one transaction, so a concurrent update
        # cannot interleave between the read and the write. `COALESCE` would
        # not do: it cannot express "set this column to NULL on purpose".
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                f"SELECT {_OPERATOR_COLUMNS} FROM waxseal_operators "
                "WHERE username = %s FOR UPDATE",
                (username,),
            )
            row = cur.fetchone()
            if row is None:
                raise NoSuchOperator(f"no operator {username!r}")
            current = _operator(row)
            updated = Operator(
                username=current.username,
                display_name=(
                    current.display_name if display_name is None else display_name
                ),
                email=None if clear_email else (current.email if email is None else email),
                role=current.role if role is None else role,
                created_at=current.created_at,
                active=current.active if active is None else active,
            )
            cur.execute(
                "UPDATE waxseal_operators SET display_name = %s, email = %s, "
                "role = %s, active = %s WHERE username = %s",
                (
                    updated.display_name,
                    updated.email,
                    updated.role.value,
                    updated.active,
                    username,
                ),
            )
            conn.commit()
        return updated

    def get_operator(self, username: str) -> Operator | None:
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                f"SELECT {_OPERATOR_COLUMNS} FROM waxseal_operators WHERE username = %s",
                (username,),
            )
            row = cur.fetchone()
        return None if row is None else _operator(row)

    def operators(self) -> list[Operator]:
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(f"SELECT {_OPERATOR_COLUMNS} FROM waxseal_operators ORDER BY ordinal")
            rows = cur.fetchall()
        return [_operator(row) for row in rows]

    # -------------------------------------------------------------------- keys

    def mint_key(self, *, username: str, label: str) -> tuple[str, ApiKey]:
        plaintext, secret_hash = mint_key()
        record = ApiKey(
            key_id=new_key_id(),
            username=username,
            label=label,
            fingerprint=key_fingerprint(plaintext),
            created_at=utc_now(),
        )
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute("SELECT 1 FROM waxseal_operators WHERE username = %s", (username,))
            if cur.fetchone() is None:
                raise NoSuchOperator(f"no operator {username!r}")
            cur.execute(
                "INSERT INTO waxseal_api_keys "
                "(key_id, username, label, fingerprint, key_sha256, created_at) "
                "VALUES (%s, %s, %s, %s, %s, %s)",
                (
                    record.key_id,
                    username,
                    label,
                    record.fingerprint,
                    secret_hash,
                    record.created_at,
                ),
            )
            conn.commit()
        return plaintext, record

    def keys(self, username: str | None = None) -> list[ApiKey]:
        with self._connect() as conn:
            cur = conn.cursor()
            if username is None:
                cur.execute(
                    f"SELECT {_KEY_COLUMNS} FROM waxseal_api_keys ORDER BY ordinal DESC"
                )
            else:
                cur.execute(
                    f"SELECT {_KEY_COLUMNS} FROM waxseal_api_keys "
                    "WHERE username = %s ORDER BY ordinal DESC",
                    (username,),
                )
            rows = cur.fetchall()
        return [_api_key(row) for row in rows]

    def revoke_key(self, key_id: str) -> bool:
        with self._connect() as conn:
            cur = conn.cursor()
            # The WHERE clause carries the idempotence: a second revoke matches
            # no row and reports that it did nothing, rather than moving the
            # timestamp and pretending it acted.
            cur.execute(
                "UPDATE waxseal_api_keys SET revoked_at = %s "
                "WHERE key_id = %s AND revoked_at IS NULL",
                (utc_now(), key_id),
            )
            revoked = bool(cur.rowcount == 1)
            conn.commit()
        return revoked

    def has_active_key(self) -> bool:
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT 1 FROM waxseal_api_keys WHERE revoked_at IS NULL LIMIT 1"
            )
            return bool(cur.fetchone() is not None)

    def authenticate(self, plaintext: str) -> Principal | None:
        if not plaintext:
            return None
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT k.key_id, k.revoked_at, "
                f"{', '.join('o.' + c for c in _OPERATOR_COLUMNS.split(', '))} "
                "FROM waxseal_api_keys k "
                "JOIN waxseal_operators o ON o.username = k.username "
                "WHERE k.key_sha256 = %s",
                (hash_key(plaintext),),
            )
            row = cur.fetchone()
            if row is None:
                return None
            key_id, revoked_at = row[0], row[1]
            operator = _operator(row[2:])
            # One None for every failure — unknown, revoked, deactivated — so a
            # caller cannot learn which of them a guessed key hit.
            if revoked_at is not None or not operator.active:
                return None
            cur.execute(
                "UPDATE waxseal_api_keys SET last_used_at = %s WHERE key_id = %s",
                (utc_now(), key_id),
            )
            conn.commit()
        return Principal(operator=operator, key_id=key_id, scopes=operator.scopes)
