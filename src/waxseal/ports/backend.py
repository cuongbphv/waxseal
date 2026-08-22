"""Storage backend protocols.

``WriterBackend.append`` takes a builder instead of a finished entry so that
read-tail + append is ONE critical section owned by the backend (CLAUDE.md
rule 7): the builder receives (next_seq, prev_hash) while the lock is held.
Handing backends a pre-built entry is how a prior production system forked its
chain under a web-server threadpool.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import Protocol

from waxseal.domain.header import Entry


class WriterBackend(Protocol):
    def append(self, build: Callable[[int, str], Entry]) -> Entry:
        """Under the backend's write lock: read the tail, call
        ``build(next_seq, prev_hash)``, persist and return the entry.

        ``build`` MAY be invoked more than once per logical append: an
        optimistic (compare-and-set) backend re-invokes it with a fresh
        ``(next_seq, prev_hash)`` after losing a race, instead of holding a
        lock across the round trip (S3's conditional-write retry is the
        precedent). Callers MUST pass a builder that is side-effect-free and
        deterministic given ``(seq, prev_hash)`` — ``AuditLog.append``
        satisfies this by computing ``ts`` before the closure runs.
        """
        ...


class ReaderBackend(Protocol):
    def entries(self) -> Iterator[Entry]:
        """Yield entries in storage order."""
        ...
