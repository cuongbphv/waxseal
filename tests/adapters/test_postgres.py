"""Tests for the Postgres backend.

Unit tests run against a scripted fake DBAPI connection that checks the
serialization PROTOCOL (advisory xact lock taken before the tail read, insert
in the same transaction, %s paramstyle). TestRealPostgres runs against a real
server (psycopg ships in the dev extra), started by
`docker compose -f server/docker-compose.yml up -d postgres`.

These eleven tests skipped on every local run for a year not because no
database was there, but because they looked for WAXSEAL_PG_DSN while the
server suite next door connected to its own default and passed 42 tests
against the same live server (waxseal-fg4.2, measured 31/08/2026). A skip
condition that asks "is an env var set" answers a different question from
"is a database reachable", and the difference was eleven tamper-detection
tests reading as green. The default DSN below is the server's, so one
running database serves both suites; WAXSEAL_PG_DSN still overrides it.

Reachability, not configuration, decides. When no database answers, the skip
names the DSN it tried and calls the count UNMEASURED — tests/conftest.py
prints that as its own run-summary line, because "11 skipped" among 2400
passes is exactly the collapse CLAUDE.md rule 5 forbids.

Each test gets a fresh schema and drops it afterwards, so pointing the
default at a shared development database cannot touch anything in `public`.
"""

import os
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from tests.adapters.backend_contract import BackendContractTests
from tests.adapters.test_jsonl import build_entry
from waxseal import VersionRegistry, verify_chain
from waxseal.adapters.postgres import ADVISORY_LOCK_KEY, PostgresBackend
from waxseal.domain.header import GENESIS_PREV_HASH, Entry


class FakeCursor:
    def __init__(self, conn: "FakeConn"):
        self._conn = conn
        self._result: list[tuple[object, ...]] = []

    def execute(self, sql: str, params: tuple[object, ...] = ()) -> None:
        self._conn.statements.append((sql.strip(), params))
        norm = " ".join(sql.split()).lower()
        if "pg_advisory_xact_lock" in norm:
            self._conn.locked = True
            self._result = []
        elif norm.startswith("select") and "order by seq desc" in norm:
            assert self._conn.locked, "tail read before advisory lock: fork window"
            rows = self._conn.store.rows
            self._result = [(rows[-1][0], rows[-1][6])] if rows else []
        elif norm.startswith("select"):
            self._result = list(self._conn.store.rows)
        elif norm.startswith("insert"):
            assert self._conn.locked, "insert before advisory lock: fork window"
            if any(r[0] == params[0] for r in self._conn.store.rows):
                raise RuntimeError("duplicate key value violates unique constraint")
            self._conn.pending.append(params)
        elif norm.startswith("create table"):
            pass
        else:
            raise AssertionError(f"unexpected SQL: {sql}")

    def fetchone(self) -> tuple[object, ...] | None:
        return self._result[0] if self._result else None

    def fetchall(self) -> list[tuple[object, ...]]:
        return list(self._result)

    def close(self) -> None:
        pass


class FakeStore:
    def __init__(self) -> None:
        self.rows: list[tuple[object, ...]] = []


class FakeConn:
    def __init__(self, store: FakeStore):
        self.store = store
        self.statements: list[tuple[str, tuple[object, ...]]] = []
        self.pending: list[tuple[object, ...]] = []
        self.locked = False
        self.closed = False

    def cursor(self) -> FakeCursor:
        return FakeCursor(self)

    def commit(self) -> None:
        self.store.rows.extend(self.pending)
        self.pending = []
        self.locked = False  # xact lock releases on commit

    def rollback(self) -> None:
        self.pending = []
        self.locked = False

    def close(self) -> None:
        self.closed = True


def _conns(backend: PostgresBackend) -> list[FakeConn]:
    """The `backend`/`store` fixtures below stash their scripted FakeConns
    here for the protocol assertions in TestProtocol; PostgresBackend itself
    declares no such attribute (this is test-only introspection, never a
    production surface)."""
    return backend._test_conns  # type: ignore[attr-defined,no-any-return]


@pytest.fixture()
def store() -> FakeStore:
    return FakeStore()


@pytest.fixture()
def backend(store: FakeStore) -> PostgresBackend:
    conns: list[FakeConn] = []

    def connect() -> FakeConn:
        conn = FakeConn(store)
        conns.append(conn)
        return conn

    b = PostgresBackend(connect)
    b._test_conns = conns  # type: ignore[attr-defined]
    return b


class TestPostgresBackendContract(BackendContractTests):
    # A base-class fixture wins over a same-named module fixture in pytest's
    # resolution order (class scope is closer than module scope), so the
    # module-level `backend`/`store` above must be re-exposed here rather
    # than relied on by omission — see the identical note in test_s3.py.
    @pytest.fixture()
    def backend(self, store: FakeStore) -> PostgresBackend:
        conns: list[FakeConn] = []

        def connect() -> FakeConn:
            conn = FakeConn(store)
            conns.append(conn)
            return conn

        b = PostgresBackend(connect)
        b._test_conns = conns  # type: ignore[attr-defined]
        return b


class TestProtocol:
    def test_append_takes_advisory_lock_before_tail_read(self, backend: PostgresBackend) -> None:
        # FakeCursor asserts lock-before-read/insert; this drives the flow.
        backend.append(lambda seq, prev: build_entry(seq, prev))
        stmts = [s for conn in _conns(backend) for s, _ in conn.statements]
        lock_idx = next(i for i, s in enumerate(stmts) if "pg_advisory_xact_lock" in s)
        tail_idx = next(i for i, s in enumerate(stmts) if "ORDER BY seq DESC" in s)
        assert lock_idx < tail_idx

    def test_advisory_lock_uses_the_documented_key(self, backend: PostgresBackend) -> None:
        backend.append(lambda seq, prev: build_entry(seq, prev))
        lock_params = [
            p
            for conn in _conns(backend)
            for s, p in conn.statements
            if "pg_advisory_xact_lock" in s
        ]
        assert lock_params == [(ADVISORY_LOCK_KEY,)]

    def test_first_append_gets_seq_0_and_genesis_prev(self, backend: PostgresBackend) -> None:
        seen: list[tuple[int, str]] = []

        def build(seq: int, prev: str) -> Entry:
            seen.append((seq, prev))
            return build_entry(seq, prev)

        backend.append(build)
        assert seen == [(0, GENESIS_PREV_HASH)]

    def test_round_trip_and_verify(self, backend: PostgresBackend) -> None:
        for _ in range(3):
            backend.append(lambda seq, prev: build_entry(seq, prev))
        assert verify_chain(backend.entries(), VersionRegistry()).checked == 3

    def test_connections_are_closed(self, backend: PostgresBackend) -> None:
        backend.append(lambda seq, prev: build_entry(seq, prev))
        list(backend.entries())
        assert all(c.closed for c in _conns(backend))

    def test_failed_append_rolls_back(self, backend: PostgresBackend, store: FakeStore) -> None:
        def bad_build(seq: int, prev: str) -> Entry:
            raise RuntimeError("builder exploded")

        with pytest.raises(RuntimeError, match="builder exploded"):
            backend.append(bad_build)
        assert store.rows == []


# The server's own default (server/tests/test_operators_postgres.py and
# server/docker-compose.yml). Shared on purpose: one `docker compose up`
# measures both suites, which is what the wheel's env-var-only condition
# silently opted out of.
DEFAULT_DSN = "postgresql://waxseal:waxseal-dev@127.0.0.1:55432/waxseal"
DSN = os.environ.get("WAXSEAL_PG_DSN", DEFAULT_DSN)

# tests/conftest.py keys its run-summary line on this word. A skip that only
# says "skipped" is indistinguishable from a pass in the totals line.
UNMEASURED = "UNMEASURED"


def _postgres_reachable(dsn: str) -> bool:
    """Whether a server answers at `dsn`. Never raises: any failure means
    "not available", which is a labelled absence and never a pass."""
    try:
        import psycopg
    except ImportError:
        return False
    try:
        with psycopg.connect(dsn, connect_timeout=3) as conn:
            conn.execute("SELECT 1")
    except Exception:  # noqa: BLE001 - every failure is the same answer here
        return False
    return True


PG_REACHABLE = _postgres_reachable(DSN)
PG_SKIP_REASON = (
    f"{UNMEASURED}: no PostgreSQL answered at {DSN}, so the real-backend "
    "tamper-detection tests did not run and made no claim either way — start one with "
    "`docker compose -f server/docker-compose.yml up -d postgres`, or set WAXSEAL_PG_DSN"
)

_active_schema: str | None = None


@pytest.fixture()
def pg_backend() -> Iterator[PostgresBackend]:
    """Fresh backend in a schema of its own, dropped afterwards.

    A schema per test rather than a DROP TABLE in a shared one: the default
    DSN now points at a database the server also uses, and a test suite must
    not be able to delete anything an operator put there.
    """
    global _active_schema
    psycopg = pytest.importorskip("psycopg")
    schema = f"waxseal_wheel_test_{uuid.uuid4().hex[:12]}"

    def connect() -> Any:
        conn = psycopg.connect(DSN)
        conn.execute(f'SET search_path TO "{schema}"')
        return conn

    with psycopg.connect(DSN) as admin:
        admin.execute(f'CREATE SCHEMA "{schema}"')
        admin.commit()
    _active_schema = schema
    try:
        yield PostgresBackend(connect)
    finally:
        _active_schema = None
        with psycopg.connect(DSN) as admin:
            admin.execute(f'DROP SCHEMA "{schema}" CASCADE')
            admin.commit()


def pg_execute(sql: str, params: tuple[object, ...] = ()) -> None:
    """Tamper with the table out of band, in the schema the active fixture made."""
    import psycopg

    assert _active_schema is not None, "pg_execute needs the pg_backend fixture"
    with psycopg.connect(DSN) as conn:
        conn.execute(f'SET search_path TO "{_active_schema}"')
        conn.execute(sql, params)
        conn.commit()


@pytest.mark.skipif(not PG_REACHABLE, reason=PG_SKIP_REASON)
class TestRealPostgres:
    # -- happy path -----------------------------------------------------------
    def test_append_and_verify(self, pg_backend: PostgresBackend) -> None:
        for _ in range(3):
            pg_backend.append(lambda seq, prev: build_entry(seq, prev))
        result = verify_chain(pg_backend.entries(), VersionRegistry())
        assert result.ok and result.checked == 3

    def test_binary_payload_round_trip_byte_exact(self, pg_backend: PostgresBackend) -> None:
        # BYTEA must hand back the exact bytes hashed on the way in — NULs,
        # high bytes, and the empty payload included (b"" is a payload; only
        # None is refused).
        payloads = [b"", b"\x00", b"\x00binary\xff\xfe", bytes(range(256))]
        for payload_bytes in payloads:
            # A plain lambda's default-arg params can't be annotated, and
            # mypy cannot infer them positionally against the two-arg
            # Callable[[int, str], Entry] PostgresBackend.append() expects
            # (misc: "Cannot infer type of lambda").
            def build(seq: int, prev: str, p: bytes = payload_bytes) -> Entry:
                return build_entry(seq, prev, p)

            pg_backend.append(build)
        assert [e.payload for e in pg_backend.entries()] == payloads
        assert verify_chain(pg_backend.entries(), VersionRegistry()).ok

    def test_parity_with_jsonl_and_sqlite(
        self, pg_backend: PostgresBackend, tmp_path: Path
    ) -> None:
        # Same payload must yield the same entry_hash byte-for-byte on every
        # backend — the chain must not depend on where it is stored.
        from waxseal.adapters.jsonl import JSONLBackend
        from waxseal.adapters.sqlite import SQLiteBackend

        payload = b'{"event": "parity"}'
        hashes = []
        for backend in (
            pg_backend,
            JSONLBackend(tmp_path / "trail.jsonl"),
            SQLiteBackend(tmp_path / "trail.db"),
        ):
            entry = backend.append(lambda seq, prev: build_entry(seq, prev, payload))
            hashes.append(entry.entry_hash)
        assert hashes[0] == hashes[1] == hashes[2]

    # -- tamper: every mutation class must name the right seq and reason -------
    def test_edited_payload_is_reported(self, pg_backend: PostgresBackend) -> None:
        for _ in range(3):
            pg_backend.append(lambda seq, prev: build_entry(seq, prev))
        pg_execute("UPDATE waxseal_entries SET payload = %s WHERE seq = 1", (b"forged",))
        result = verify_chain(pg_backend.entries(), VersionRegistry())
        assert not result.ok
        assert (result.broken_seq, result.reason) == (1, "payload_hash_mismatch")

    def test_edited_header_field_is_reported(self, pg_backend: PostgresBackend) -> None:
        for _ in range(3):
            pg_backend.append(lambda seq, prev: build_entry(seq, prev))
        pg_execute(
            "UPDATE waxseal_entries SET payload_type = %s WHERE seq = 1",
            ("application/x-forged",),
        )
        result = verify_chain(pg_backend.entries(), VersionRegistry())
        assert not result.ok
        assert (result.broken_seq, result.reason) == (1, "entry_hash_mismatch")

    def test_deleted_row_is_reported(self, pg_backend: PostgresBackend) -> None:
        for _ in range(3):
            pg_backend.append(lambda seq, prev: build_entry(seq, prev))
        pg_execute("DELETE FROM waxseal_entries WHERE seq = 1")
        result = verify_chain(pg_backend.entries(), VersionRegistry())
        assert not result.ok
        assert (result.broken_seq, result.reason) == (2, "seq_gap")

    def test_reordered_rows_are_reported(self, pg_backend: PostgresBackend) -> None:
        # The verifier walks rowpos (insertion order) precisely so a swap
        # cannot hide behind ORDER BY seq.
        for _ in range(3):
            pg_backend.append(lambda seq, prev: build_entry(seq, prev))
        pg_execute("UPDATE waxseal_entries SET rowpos = 100 WHERE seq = 1")
        pg_execute("UPDATE waxseal_entries SET rowpos = 2 WHERE seq = 2")
        pg_execute("UPDATE waxseal_entries SET rowpos = 3 WHERE seq = 1")
        result = verify_chain(pg_backend.entries(), VersionRegistry())
        assert not result.ok
        assert result.reason == "seq_gap"

    def test_duplicate_seq_fork_rejected_by_primary_key(self, pg_backend: PostgresBackend) -> None:
        # Storage-level backstop: even if the advisory lock were bypassed,
        # the second branch of a fork must die on PRIMARY KEY(seq).
        import psycopg

        entry = pg_backend.append(lambda seq, prev: build_entry(seq, prev))
        with pytest.raises(psycopg.errors.UniqueViolation):
            pg_execute(
                "INSERT INTO waxseal_entries"
                " (seq, ts, hash_version, payload_type, payload_hash,"
                "  prev_hash, entry_hash, payload)"
                " VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                (
                    entry.header.seq,
                    entry.header.ts,
                    entry.header.hash_version,
                    entry.header.payload_type,
                    entry.header.payload_hash,
                    entry.header.prev_hash,
                    entry.entry_hash,
                    b"fork",
                ),
            )

    # -- unknown fingerprint: unverifiable, never tampered ---------------------
    def test_unknown_fingerprint_is_unverifiable_not_tampered(
        self, pg_backend: PostgresBackend
    ) -> None:
        first = pg_backend.append(lambda seq, prev: build_entry(seq, prev))
        foreign_hash = "ab" * 32
        pg_execute(
            "INSERT INTO waxseal_entries"
            " (seq, ts, hash_version, payload_type, payload_hash,"
            "  prev_hash, entry_hash, payload)"
            " VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
            (
                1,
                "2026-08-21T06:00:00+00:00",
                "ff" * 32,  # fingerprint no registry knows
                "application/vnd.future+json",
                "cd" * 32,
                first.entry_hash,
                foreign_hash,
                b"{}",
            ),
        )
        # The chain stays linked THROUGH the opaque row: later appends chain
        # onto its stored entry_hash.
        pg_backend.append(lambda seq, prev: build_entry(seq, prev))
        result = verify_chain(pg_backend.entries(), VersionRegistry())
        assert result.ok
        assert result.unverifiable == (1,)
        assert result.checked == 2

    # -- concurrency: advisory lock must serialize real parallel writers -------
    def test_parallel_appends_never_fork_the_chain(self, pg_backend: PostgresBackend) -> None:
        # Falsifiability receipt: with pg_advisory_xact_lock removed from
        # append(), this test failed 3 out of 3 runs against Postgres 16
        # (duplicate-seq forks, measured 2026-08-21). If it never failed on
        # broken code it would prove nothing.
        from concurrent.futures import ThreadPoolExecutor

        threads, per_thread = 8, 25

        def worker(worker_id: int) -> None:
            for i in range(per_thread):
                payload = f'{{"w": {worker_id}, "i": {i}}}'.encode()

                def build(seq: int, prev: str, p: bytes = payload) -> Entry:
                    return build_entry(seq, prev, p)

                pg_backend.append(build)

        with ThreadPoolExecutor(max_workers=threads) as pool:
            list(pool.map(worker, range(threads)))

        entries = list(pg_backend.entries())
        result = verify_chain(entries, VersionRegistry())
        assert result.ok, f"chain broken at seq={result.broken_seq}: {result.reason}"
        assert result.checked == threads * per_thread
        assert [e.header.seq for e in entries] == list(range(threads * per_thread))

    # -- failure atomicity ------------------------------------------------------
    def test_failed_append_rolls_back_and_releases_lock(self, pg_backend: PostgresBackend) -> None:
        def bad_build(seq: int, prev: str) -> Entry:
            raise RuntimeError("builder exploded")

        with pytest.raises(RuntimeError, match="builder exploded"):
            pg_backend.append(bad_build)
        # No half-written row, and the advisory lock is gone: the next append
        # must proceed and still get seq 0.
        entry = pg_backend.append(lambda seq, prev: build_entry(seq, prev))
        assert entry.header.seq == 0
        assert verify_chain(pg_backend.entries(), VersionRegistry()).checked == 1
