"""Postgres backend: advisory-lock-serialized appends.

The connection factory is INJECTED (psycopg-compatible, %s paramstyle):
waxseal keeps zero runtime dependencies and never imports a driver.

`pg_advisory_xact_lock` is taken BEFORE the tail read, inside the same
transaction as the insert, and releases on commit/rollback, the same
one-critical-section rule as every backend (CLAUDE.md rule 7). PRIMARY KEY on
seq is the storage-level backstop against forks. `rowpos` preserves insertion
order for the verifier (ordering by seq would hide reordering).
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import Any

from waxseal.adapters._envelope import entry_from_fields
from waxseal.domain.header import GENESIS_PREV_HASH, Entry

# Arbitrary but stable: int64 from ascii "waxseal!" (8 bytes).
ADVISORY_LOCK_KEY = int.from_bytes(b"waxseal!", "big", signed=True)

_DDL = """
CREATE TABLE IF NOT EXISTS waxseal_entries (
    rowpos       BIGSERIAL,
    seq          BIGINT PRIMARY KEY,
    ts           TEXT NOT NULL,
    hash_version TEXT NOT NULL,
    payload_type TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    prev_hash    TEXT NOT NULL,
    entry_hash   TEXT NOT NULL,
    payload      BYTEA NOT NULL
)
"""


class PostgresBackend:
    def __init__(self, connect: Callable[[], Any]) -> None:
        self._connect = connect
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        conn = self._connect()
        try:
            cur = conn.cursor()
            cur.execute(_DDL)
            conn.commit()
        finally:
            conn.close()

    def append(self, build: Callable[[int, str], Entry]) -> Entry:
        conn = self._connect()
        try:
            cur = conn.cursor()
            # Lock first: no other writer may read the same tail (rule 7).
            cur.execute("SELECT pg_advisory_xact_lock(%s)", (ADVISORY_LOCK_KEY,))
            cur.execute("SELECT seq, entry_hash FROM waxseal_entries ORDER BY seq DESC LIMIT 1")
            row = cur.fetchone()
            next_seq, prev_hash = (0, GENESIS_PREV_HASH) if row is None else (row[0] + 1, row[1])
            entry = build(next_seq, prev_hash)
            if entry.payload is None:
                raise ValueError("Postgres backend stores payload bytes; payload must not be None")
            cur.execute(
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
            cur = conn.cursor()
            cur.execute(
                "SELECT seq, ts, hash_version, payload_type, payload_hash,"
                " prev_hash, entry_hash, payload"
                " FROM waxseal_entries ORDER BY rowpos"
            )
            for seq, ts, hv, pt, ph, prev, eh, payload in cur.fetchall():
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
