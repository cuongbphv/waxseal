"""In-memory backend, for embedding, tests, and ephemeral sessions.

Same critical-section contract as every backend (CLAUDE.md rule 7): the lock
covers read-tail + append, so concurrent writers cannot fork the chain.
"""

from __future__ import annotations

import threading
from collections.abc import Callable, Iterator

from waxseal.domain.header import GENESIS_PREV_HASH, Entry


class MemoryBackend:
    def __init__(self) -> None:
        self._entries: list[Entry] = []
        self._lock = threading.Lock()

    def append(self, build: Callable[[int, str], Entry]) -> Entry:
        with self._lock:
            if self._entries:
                last = self._entries[-1]
                entry = build(last.header.seq + 1, last.entry_hash)
            else:
                entry = build(0, GENESIS_PREV_HASH)
            if entry.payload is None:
                raise ValueError("Memory backend stores payload bytes; payload must not be None")
            self._entries.append(entry)
            return entry

    def entries(self) -> Iterator[Entry]:
        with self._lock:
            snapshot = list(self._entries)
        yield from snapshot
