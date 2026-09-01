"""The Postgres settings adapter, against the SAME contract as the memory one.

Skips with a labelled message when no PostgreSQL is reachable, so "nobody ran
these" never reads as "these passed". Each test gets a fresh schema, so the
contract's "a fresh store has nothing stored" means what it says.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator

import pytest
from settings_store_contract import SettingsStoreContract
from waxseal_server.runtime.postgres import connection_factory, is_available
from waxseal_server.storage.settings_postgres import PostgresSettingsStore

DSN = os.environ.get(
    "WAXSEAL_TEST_DATABASE_URL",
    "postgresql://waxseal:waxseal-dev@127.0.0.1:55432/waxseal",
)

pytestmark = pytest.mark.skipif(
    not is_available(DSN),
    reason=f"no PostgreSQL reachable at {DSN} — start one with server/docker-compose.yml",
)


class TestPostgresSettingsStore(SettingsStoreContract):
    @pytest.fixture()
    def store(self) -> Iterator[PostgresSettingsStore]:
        schema = f"waxseal_test_{uuid.uuid4().hex[:12]}"
        base = connection_factory(DSN)
        with base() as conn:
            conn.cursor().execute(f'CREATE SCHEMA "{schema}"')
            conn.commit()

        def connect() -> object:
            conn = base()
            conn.cursor().execute(f'SET search_path TO "{schema}"')
            return conn

        try:
            yield PostgresSettingsStore(connect)  # type: ignore[arg-type]
        finally:
            with base() as conn:
                conn.cursor().execute(f'DROP SCHEMA "{schema}" CASCADE')
                conn.commit()
