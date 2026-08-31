"""Which operator store a deployment actually gets.

Two ways to get this wrong, both silent: a production deployment falling back
to the in-memory store and losing every operator on restart, and a test
accidentally reaching the real database. The wiring is one function, so both are
one assertion.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from waxseal_server.app import build_operator_store
from waxseal_server.config import Settings
from waxseal_server.runtime.postgres import is_available
from waxseal_server.storage.operators_memory import InMemoryOperatorStore
from waxseal_server.storage.operators_postgres import PostgresOperatorStore

DSN = os.environ.get(
    "WAXSEAL_TEST_DATABASE_URL",
    "postgresql://waxseal:waxseal-dev@127.0.0.1:55432/waxseal",
)


class TestWiring:
    def test_no_database_url_means_the_in_memory_store(self, tmp_path: Path) -> None:
        store = build_operator_store(Settings(data_dir=tmp_path))
        assert isinstance(store, InMemoryOperatorStore)

    @pytest.mark.skipif(
        not is_available(DSN),
        reason=f"no PostgreSQL reachable at {DSN} — start one with server/docker-compose.yml",
    )
    def test_a_database_url_means_postgres(self, tmp_path: Path) -> None:
        store = build_operator_store(Settings(data_dir=tmp_path, database_url=DSN))
        assert isinstance(store, PostgresOperatorStore)


class TestAvailabilityProbe:
    def test_an_unreachable_database_is_reported_unavailable_not_raised(self) -> None:
        # The probe decides whether the Postgres suite runs. If it raised, a
        # machine without a database would error instead of skipping, and the
        # skip is what makes "nobody ran these" visible.
        assert is_available("postgresql://nobody@127.0.0.1:1/nothing") is False

    def test_a_malformed_dsn_is_also_just_unavailable(self) -> None:
        assert is_available("not-a-dsn") is False
