"""`SettingsStore` on PostgreSQL — operational config, and only that.

This table holds no credential. `domain/settings.py` refuses `api_key`,
`witness_api_key`, `database_url` and `data_dir` by name, and both adapters go
through that refusal before touching storage, so neither can be the one that
accepts a secret. The operator store next door keeps only a key's SHA-256 for
the same reason: a database that can hold a live credential eventually leaks
one.

The connection factory is INJECTED, the same discipline as
`operators_postgres.py`: this module names no driver and opens no pool of its
own.

`updated_at` is stored but never used to order anything. It is there for the
question an incident review actually asks — "when did this endpoint change?" —
which the row itself cannot otherwise answer.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Final

from waxseal_server.domain.clock import utc_now
from waxseal_server.domain.settings import require_value, spec_for

Connect = Callable[[], Any]

SCHEMA: Final = """
CREATE TABLE IF NOT EXISTS waxseal_settings (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
"""


class PostgresSettingsStore:
    def __init__(self, connect: Connect) -> None:
        self._connect = connect
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        with self._connect() as conn:
            conn.cursor().execute(SCHEMA)
            conn.commit()

    def get(self, key: str) -> str | None:
        # `spec_for` first: an unknown or environment-only key must raise rather
        # than answer None, which would imply the setting could live here.
        spec_for(key)
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute("SELECT value FROM waxseal_settings WHERE key = %s", (key,))
            row = cur.fetchone()
        return None if row is None else str(row[0])

    def all(self) -> dict[str, str]:
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute("SELECT key, value FROM waxseal_settings")
            rows = cur.fetchall()
        return {str(k): str(v) for k, v in rows}

    def set(self, key: str, value: str) -> str:
        # Validated BEFORE the statement runs, so a refused write never reaches
        # the table and cannot replace a good value with a bad one.
        checked = require_value(key, value)
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO waxseal_settings (key, value, updated_at) "
                "VALUES (%s, %s, %s) ON CONFLICT (key) DO UPDATE "
                "SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at",
                (key, checked, utc_now()),
            )
            conn.commit()
        return checked

    def unset(self, key: str) -> bool:
        spec_for(key)
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM waxseal_settings WHERE key = %s", (key,))
            # `rowcount`, not a prior SELECT: the database says whether THIS
            # call removed anything, so a retry reports false rather than
            # claiming it acted.
            removed = bool(cur.rowcount == 1)
            conn.commit()
        return removed
