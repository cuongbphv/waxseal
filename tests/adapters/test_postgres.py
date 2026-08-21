"""Tests for the Postgres backend.

Unit tests run against a scripted fake DBAPI connection that checks the
serialization PROTOCOL (advisory xact lock taken before the tail read, insert
in the same transaction, %s paramstyle). The TestRealPostgres suite runs only
when WAXSEAL_PG_DSN is set (psycopg ships in the dev extra), e.g. with a
throwaway server:

    docker run -d --name waxseal-pg -e POSTGRES_PASSWORD=waxseal \
      -e POSTGRES_DB=waxseal -p 5433:5432 postgres:16
    WAXSEAL_PG_DSN="postgresql://postgres:waxseal@localhost:5433/waxseal" \
      uv run pytest tests/adapters/test_postgres.py

Each real test drops and recreates the table for isolation — point the DSN
at a disposable database, never a production one.
"""

import os

import pytest

from tests.adapters.test_jsonl import build_entry
from waxseal import VersionRegistry, verify_chain
from waxseal.adapters.postgres import ADVISORY_LOCK_KEY, PostgresBackend
from waxseal.domain.header import GENESIS_PREV_HASH


class FakeCursor:
    def __init__(self, conn: "FakeConn"):
        self._conn = conn
        self._result: list[tuple] = []

    def execute(self, sql: str, params: tuple = ()) -> None:
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

    def fetchone(self):
        return self._result[0] if self._result else None

    def fetchall(self):
        return list(self._result)

    def close(self) -> None:
        pass


class FakeStore:
    def __init__(self):
        self.rows: list[tuple] = []


class FakeConn:
    def __init__(self, store: FakeStore):
        self.store = store
        self.statements: list[tuple[str, tuple]] = []
        self.pending: list[tuple] = []
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


class TestProtocol:
    def test_append_takes_advisory_lock_before_tail_read(
        self, backend: PostgresBackend
    ) -> None:
        # FakeCursor asserts lock-before-read/insert; this drives the flow.
        backend.append(lambda seq, prev: build_entry(seq, prev))
        stmts = [s for conn in backend._test_conns for s, _ in conn.statements]
        lock_idx = next(i for i, s in enumerate(stmts) if "pg_advisory_xact_lock" in s)
        tail_idx = next(i for i, s in enumerate(stmts) if "ORDER BY seq DESC" in s)
        assert lock_idx < tail_idx

    def test_advisory_lock_uses_the_documented_key(self, backend: PostgresBackend) -> None:
        backend.append(lambda seq, prev: build_entry(seq, prev))
        lock_params = [
            p for conn in backend._test_conns
            for s, p in conn.statements if "pg_advisory_xact_lock" in s
        ]
        assert lock_params == [(ADVISORY_LOCK_KEY,)]

    def test_first_append_gets_seq_0_and_genesis_prev(self, backend: PostgresBackend) -> None:
        seen: list[tuple[int, str]] = []

        def build(seq: int, prev: str):
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
        assert all(c.closed for c in backend._test_conns)

    def test_failed_append_rolls_back(self, backend: PostgresBackend, store: FakeStore) -> None:
        def bad_build(seq: int, prev: str):
            raise RuntimeError("builder exploded")

        with pytest.raises(RuntimeError, match="builder exploded"):
            backend.append(bad_build)
        assert store.rows == []


@pytest.fixture()
def pg_backend() -> "PostgresBackend":
    """Fresh backend against the real server; drops the table for isolation."""
    psycopg = pytest.importorskip("psycopg")
    dsn = os.environ["WAXSEAL_PG_DSN"]

    def connect():
        return psycopg.connect(dsn)

    with connect() as conn:
        conn.execute("DROP TABLE IF EXISTS waxseal_entries")
        conn.commit()
    return PostgresBackend(connect)


def pg_execute(sql: str, params: tuple = ()) -> None:
    import psycopg

    with psycopg.connect(os.environ["WAXSEAL_PG_DSN"]) as conn:
        conn.execute(sql, params)
        conn.commit()


@pytest.mark.skipif(
    not os.environ.get("WAXSEAL_PG_DSN"),
    reason="set WAXSEAL_PG_DSN to run against a real Postgres",
)
class TestRealPostgres:
    # -- happy path -----------------------------------------------------------
    def test_append_and_verify(self, pg_backend: PostgresBackend) -> None:
        for _ in range(3):
            pg_backend.append(lambda seq, prev: build_entry(seq, prev))
        result = verify_chain(pg_backend.entries(), VersionRegistry())
        assert result.ok and result.checked == 3

    def test_binary_payload_round_trip_byte_exact(
        self, pg_backend: PostgresBackend
    ) -> None:
        # BYTEA must hand back the exact bytes hashed on the way in — NULs,
        # high bytes, and the empty payload included (b"" is a payload; only
        # None is refused).
        payloads = [b"", b"\x00", b"\x00binary\xff\xfe", bytes(range(256))]
        for p in payloads:
            pg_backend.append(lambda seq, prev, p=p: build_entry(seq, prev, p))
        assert [e.payload for e in pg_backend.entries()] == payloads
        assert verify_chain(pg_backend.entries(), VersionRegistry()).ok

    def test_parity_with_jsonl_and_sqlite(
        self, pg_backend: PostgresBackend, tmp_path
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
        pg_execute(
            "UPDATE waxseal_entries SET payload = %s WHERE seq = 1", (b"forged",)
        )
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

    def test_duplicate_seq_fork_rejected_by_primary_key(
        self, pg_backend: PostgresBackend
    ) -> None:
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
    def test_parallel_appends_never_fork_the_chain(
        self, pg_backend: PostgresBackend
    ) -> None:
        # Falsifiability receipt: with pg_advisory_xact_lock removed from
        # append(), this test failed 3 out of 3 runs against Postgres 16
        # (duplicate-seq forks, measured 2026-08-21). If it never failed on
        # broken code it would prove nothing.
        from concurrent.futures import ThreadPoolExecutor

        threads, per_thread = 8, 25

        def worker(worker_id: int) -> None:
            for i in range(per_thread):
                payload = f'{{"w": {worker_id}, "i": {i}}}'.encode()
                pg_backend.append(
                    lambda seq, prev, p=payload: build_entry(seq, prev, p)
                )

        with ThreadPoolExecutor(max_workers=threads) as pool:
            list(pool.map(worker, range(threads)))

        entries = list(pg_backend.entries())
        result = verify_chain(entries, VersionRegistry())
        assert result.ok, f"chain broken at seq={result.broken_seq}: {result.reason}"
        assert result.checked == threads * per_thread
        assert [e.header.seq for e in entries] == list(range(threads * per_thread))

    # -- failure atomicity ------------------------------------------------------
    def test_failed_append_rolls_back_and_releases_lock(
        self, pg_backend: PostgresBackend
    ) -> None:
        def bad_build(seq: int, prev: str):
            raise RuntimeError("builder exploded")

        with pytest.raises(RuntimeError, match="builder exploded"):
            pg_backend.append(bad_build)
        # No half-written row, and the advisory lock is gone: the next append
        # must proceed and still get seq 0.
        entry = pg_backend.append(lambda seq, prev: build_entry(seq, prev))
        assert entry.header.seq == 0
        assert verify_chain(pg_backend.entries(), VersionRegistry()).checked == 1
