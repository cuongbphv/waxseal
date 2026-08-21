"""Tests for the SQLite backend (SPEC.md section 7) and JSONL↔SQLite parity."""

import sqlite3
from pathlib import Path

import pytest

from tests.adapters.test_jsonl import build_entry
from waxseal import AuditLog
from waxseal.adapters.sqlite import SQLiteBackend
from waxseal.domain.header import GENESIS_PREV_HASH

TS = "2026-08-21T06:00:00+00:00"
PT = "application/vnd.test.event+json"


class TestAppend:
    def test_first_append_gets_seq_0_and_genesis_prev(self, tmp_path: Path) -> None:
        backend = SQLiteBackend(tmp_path / "trail.db")
        seen: list[tuple[int, str]] = []

        def build(seq: int, prev: str):
            seen.append((seq, prev))
            return build_entry(seq, prev)

        backend.append(build)
        assert seen == [(0, GENESIS_PREV_HASH)]

    def test_entries_round_trip_byte_exact(self, tmp_path: Path) -> None:
        backend = SQLiteBackend(tmp_path / "trail.db")
        written = [
            backend.append(lambda seq, prev: build_entry(seq, prev, b"\x00binary\xff"))
            for _ in range(3)
        ]
        assert list(backend.entries()) == written

    def test_storage_rejects_duplicate_seq_fork(self, tmp_path: Path) -> None:
        # Defense in depth: even if locking failed, UNIQUE(seq) makes the
        # database itself refuse the second branch of a fork.
        path = tmp_path / "trail.db"
        backend = SQLiteBackend(path)
        entry = backend.append(lambda seq, prev: build_entry(seq, prev))
        conn = sqlite3.connect(path)
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO entries"
                " (seq, ts, hash_version, payload_type, payload_hash,"
                "  prev_hash, entry_hash, payload)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    entry.header.seq,
                    entry.header.ts,
                    entry.header.hash_version,
                    entry.header.payload_type,
                    entry.header.payload_hash,
                    entry.header.prev_hash,
                    "f" * 64,
                    b"fork",
                ),
            )
        conn.close()


class TestParity:
    def test_same_payload_same_entry_hash_across_backends(self, tmp_path: Path) -> None:
        # CLAUDE.md testing rule: byte-for-byte hash parity between backends.
        jsonl = AuditLog.open(tmp_path / "a.jsonl", now_fn=lambda: TS)
        sqlite_ = AuditLog.open(tmp_path / "a.db", now_fn=lambda: TS)
        for i in range(3):
            a = jsonl.append(payload={"i": i}, payload_type=PT)
            b = sqlite_.append(payload={"i": i}, payload_type=PT)
            assert a.entry_hash == b.entry_hash

    def test_auditlog_open_dispatches_sqlite_suffixes(self, tmp_path: Path) -> None:
        for suffix in (".db", ".sqlite", ".sqlite3"):
            log = AuditLog.open(tmp_path / f"t{suffix}", now_fn=lambda: TS)
            log.append(payload={"x": 1}, payload_type=PT)
            assert log.verify().ok


class TestOpenUnderContention:
    def test_open_survives_wal_transition_contention(self, tmp_path: Path) -> None:
        # The rollback→WAL journal switch needs an exclusive lock, and SQLite
        # reports SQLITE_BUSY for it WITHOUT consulting the busy handler —
        # measured: instant "database is locked" despite timeout=30 when
        # another connection holds a write lock. Surfaced as a ~1-in-5 flake
        # in the fork test when 8 threads opened one fresh trail (2026-08-21).
        import threading

        path = tmp_path / "trail.db"
        # check_same_thread=False: the release Timer commits from its own thread.
        blocker = sqlite3.connect(path, check_same_thread=False)
        blocker.execute("CREATE TABLE occupant (x)")
        blocker.execute("BEGIN IMMEDIATE")
        blocker.execute("INSERT INTO occupant VALUES (1)")
        release = threading.Timer(0.05, lambda: (blocker.commit(), blocker.close()))
        release.start()
        try:
            SQLiteBackend(path)  # must retry through the window, not raise
        finally:
            release.join()
        probe = sqlite3.connect(path)
        try:
            assert probe.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        finally:
            probe.close()

    def test_open_degrades_loudly_when_wal_stays_blocked(self, tmp_path: Path) -> None:
        # Fail-open must be labelled (CLAUDE.md rule 6): if the journal switch
        # never succeeds, open still works — rollback mode is equally
        # fork-safe, only slower — but says so instead of staying silent.
        path = tmp_path / "trail.db"
        blocker = sqlite3.connect(path)
        blocker.execute("CREATE TABLE occupant (x)")
        blocker.execute("BEGIN IMMEDIATE")
        blocker.execute("INSERT INTO occupant VALUES (1)")
        try:
            conn = sqlite3.connect(path, timeout=30.0)
            try:
                with pytest.warns(RuntimeWarning, match="journal"):
                    SQLiteBackend._enable_wal(conn, deadline_s=0.05)
            finally:
                conn.close()
        finally:
            blocker.rollback()
            blocker.close()


class TestTrailPermissions:
    def test_database_file_is_created_owner_only(self, tmp_path) -> None:
        # Same exposure as the JSONL trail: the payload-bearing database must
        # not inherit a world-readable umask.
        import os
        import sys

        import pytest

        if sys.platform == "win32":
            pytest.skip("POSIX permission bits")
        from waxseal.adapters.sqlite import SQLiteBackend

        old_umask = os.umask(0o022)
        try:
            db = tmp_path / "trail.db"
            SQLiteBackend(db)
            assert (db.stat().st_mode & 0o777) == 0o600
        finally:
            os.umask(old_umask)
