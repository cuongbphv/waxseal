"""SQLite backend (SPEC.md section 7). Stdlib sqlite3 only.

Fork prevention is layered: BEGIN IMMEDIATE serializes read-tail + insert,
and the PRIMARY KEY on seq makes the database itself reject a second entry
with the same seq even if locking were somehow bypassed. Entries are read
back ORDER BY rowid; seq is an INTEGER PRIMARY KEY, which SQLite aliases to
rowid, so this coincides with seq order, and a renumbered/reordered row is
caught by the hash checks (seq is inside the hashed header), not by read-back
order (contrast postgres.py, whose separate rowpos really is insertion order).
"""

from __future__ import annotations

import os
import sqlite3
import time
import warnings
from collections.abc import Callable, Iterator
from pathlib import Path

from waxseal.adapters._envelope import entry_from_fields
from waxseal.domain.header import GENESIS_PREV_HASH, Entry

_DDL = """
CREATE TABLE IF NOT EXISTS entries (
    seq          INTEGER PRIMARY KEY,
    ts           TEXT NOT NULL,
    hash_version TEXT NOT NULL,
    payload_type TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    prev_hash    TEXT NOT NULL,
    entry_hash   TEXT NOT NULL,
    payload      BLOB NOT NULL
)
"""


class SQLiteBackend:
    def __init__(self, path: Path | str) -> None:
        self._path = Path(path).expanduser()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        # Pre-create the database 0600 (payload-bearing, like the JSONL trail);
        # SQLite gives its -wal/-shm companions the database file's perms.
        os.close(os.open(self._path, os.O_CREAT | os.O_RDWR, 0o600))
        # sqlite3's context manager commits but never closes, so close explicitly.
        conn = self._connect()
        try:
            self._enable_wal(conn)
            conn.execute(_DDL)
            conn.commit()
        finally:
            conn.close()

    def _connect(self) -> sqlite3.Connection:
        # One connection per operation: sqlite3 connections are not
        # thread-safe to share, and appends may come from many threads.
        # Journal mode is a property of the database FILE, set once in
        # __init__, since re-issuing the pragma per connection would reopen the
        # busy race _enable_wal exists to close.
        return sqlite3.connect(self._path, timeout=30.0)

    @staticmethod
    def _enable_wal(conn: sqlite3.Connection, deadline_s: float = 5.0) -> None:
        # The rollback→WAL switch needs an exclusive lock and SQLite reports
        # SQLITE_BUSY for it WITHOUT consulting the busy handler (measured:
        # instant "database is locked" despite timeout=30). Concurrent opens
        # of a fresh trail hit exactly that window, so retry briefly. If the
        # switch still loses, keep the default rollback journal. It is equally
        # fork-safe (BEGIN IMMEDIATE + PRIMARY KEY), only slower, and we say
        # so: fail-open must be labelled (CLAUDE.md rule 6).
        deadline = time.monotonic() + deadline_s
        while True:
            try:
                conn.execute("PRAGMA journal_mode=WAL")
                return
            except sqlite3.OperationalError:
                if time.monotonic() >= deadline:
                    warnings.warn(
                        "waxseal: trail database is busy; keeping the "
                        "default journal mode instead of WAL",
                        RuntimeWarning,
                        stacklevel=2,
                    )
                    return
                time.sleep(0.005)

    def append(self, build: Callable[[int, str], Entry]) -> Entry:
        conn = self._connect()
        try:
            # IMMEDIATE takes the write lock BEFORE the tail read, so no other
            # writer can read the same tail (CLAUDE.md rule 7).
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT seq, entry_hash FROM entries ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            next_seq, prev_hash = (0, GENESIS_PREV_HASH) if row is None else (row[0] + 1, row[1])
            entry = build(next_seq, prev_hash)
            if entry.payload is None:
                raise ValueError("SQLite backend stores payload bytes; payload must not be None")
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
                    entry.entry_hash,
                    entry.payload,
                ),
            )
            conn.commit()
            return entry
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()

    def entries(self) -> Iterator[Entry]:
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT seq, ts, hash_version, payload_type, payload_hash,"
                " prev_hash, entry_hash, payload FROM entries ORDER BY rowid"
            )
            for seq, ts, hv, pt, ph, prev, eh, payload in rows:
                yield entry_from_fields(
                    seq=seq,
                    ts=ts,
                    hash_version=hv,
                    payload_type=pt,
                    payload_hash=ph,
                    prev_hash=prev,
                    entry_hash=eh,
                    payload=bytes(payload),
                )
        finally:
            conn.close()
