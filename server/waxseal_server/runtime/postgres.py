"""Opening a PostgreSQL connection — the only module that names a driver.

Kept here, in `runtime/`, because a database connection is an adapter to
something outside the process. `storage/` receives a factory and never imports
psycopg, which is what lets the storage contract run against an in-memory
adapter and against the real database without either knowing about the other.

The import is deferred into the function so a deployment that never configures
a database (the in-memory dev path) does not require the driver to be present.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

Connect = Callable[[], Any]


def connection_factory(dsn: str) -> Connect:
    """A callable returning a fresh connection, usable as a context manager.

    A factory rather than a shared connection: every store method opens, works
    and commits inside one `with`, so a failure cannot leave a half-open
    transaction for the next request to inherit.
    """

    def connect() -> Any:
        import psycopg  # deferred: only a Postgres deployment needs the driver

        return psycopg.connect(dsn)

    return connect


def is_available(dsn: str) -> bool:
    """Whether a database is reachable at `dsn`, without raising.

    Used to decide whether the real-Postgres tests can run, so their skip is a
    labelled "no database here", never a silent pass.
    """
    try:
        with connection_factory(dsn)() as conn:
            conn.cursor().execute("SELECT 1")
        return True
    except Exception:  # noqa: BLE001 - any failure means "not available"
        return False
