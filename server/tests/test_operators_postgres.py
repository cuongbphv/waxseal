"""The Postgres adapter, against the SAME contract as the in-memory one.

Runs against a real PostgreSQL. When there is none reachable the whole module
skips with a message naming the DSN it looked for — a labelled absence, so
"nobody ran these" never reads as "these passed".

Each test gets a fresh schema, so the contract's "a fresh store holds nobody"
means what it says even on a database that has been used before.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator

import pytest
from operator_store_contract import OperatorStoreContract
from waxseal_server.runtime.postgres import connection_factory, is_available
from waxseal_server.storage.operators_postgres import PostgresOperatorStore

DSN = os.environ.get(
    "WAXSEAL_TEST_DATABASE_URL",
    "postgresql://waxseal:waxseal-dev@127.0.0.1:55432/waxseal",
)

pytestmark = pytest.mark.skipif(
    not is_available(DSN),
    reason=f"no PostgreSQL reachable at {DSN} — start one with server/docker-compose.yml",
)


class TestPostgresOperatorStore(OperatorStoreContract):
    @pytest.fixture()
    def store(self) -> Iterator[PostgresOperatorStore]:
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
            yield PostgresOperatorStore(connect)  # type: ignore[arg-type]
        finally:
            with base() as conn:
                conn.cursor().execute(f'DROP SCHEMA "{schema}" CASCADE')
                conn.commit()
