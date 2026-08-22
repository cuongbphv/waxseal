"""Shared backend conformance contract (ports.backend.WriterBackend/ReaderBackend).

Every storage backend must satisfy this contract identically: genesis on the
first append, correct linking, insertion-order reads (never seq-sorted —
sorting would hide reordering from the verifier), and payload-None rejection.
Mix ``BackendContractTests`` into a ``Test*`` class with a ``backend``
fixture per adapter. The class is deliberately NOT named ``Test*`` so pytest
never collects it directly (it has no working fixture of its own).
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest

from tests.adapters.test_jsonl import build_entry
from waxseal.domain.header import GENESIS_PREV_HASH, Entry
from waxseal.domain.registry import VersionRegistry
from waxseal.domain.verify import verify_chain


class BackendContractTests:
    """Mix into a `Test*` class; override the `backend` fixture per adapter."""

    @pytest.fixture()
    def backend(self) -> Any:
        raise NotImplementedError("subclasses must provide a `backend` fixture")

    def test_first_append_gets_seq_0_and_genesis_prev(self, backend: Any) -> None:
        seen: list[tuple[int, str]] = []

        def build(seq: int, prev: str) -> Entry:
            seen.append((seq, prev))
            return build_entry(seq, prev)

        backend.append(build)
        assert seen == [(0, GENESIS_PREV_HASH)]

    def test_second_append_links_to_first(self, backend: Any) -> None:
        first = backend.append(lambda seq, prev: build_entry(seq, prev))
        seen: list[tuple[int, str]] = []

        def build(seq: int, prev: str) -> Entry:
            seen.append((seq, prev))
            return build_entry(seq, prev)

        backend.append(build)
        assert seen == [(1, first.entry_hash)]

    def test_entries_are_yielded_in_insertion_order(self, backend: Any) -> None:
        written = [backend.append(lambda seq, prev: build_entry(seq, prev)) for _ in range(5)]
        assert list(backend.entries()) == written

    def test_payload_none_is_rejected(self, backend: Any) -> None:
        def build_headerless(seq: int, prev: str) -> Entry:
            entry = build_entry(seq, prev)
            return Entry(header=entry.header, entry_hash=entry.entry_hash, payload=None)

        with pytest.raises(ValueError, match="payload"):
            backend.append(build_headerless)

    def test_entry_hash_round_trips(self, backend: Any) -> None:
        written = backend.append(lambda seq, prev: build_entry(seq, prev, b'{"k":"v"}'))
        [read_back] = list(backend.entries())
        assert read_back == written

    def test_n_thread_append_does_not_fork(self, backend: Any) -> None:
        threads, per_thread = 4, 10

        def worker(_: int) -> None:
            for _ in range(per_thread):
                backend.append(lambda seq, prev: build_entry(seq, prev))

        with ThreadPoolExecutor(max_workers=threads) as pool:
            list(pool.map(worker, range(threads)))
        entries = list(backend.entries())
        assert [e.header.seq for e in entries] == list(range(threads * per_thread))
        assert verify_chain(entries, VersionRegistry()).ok
