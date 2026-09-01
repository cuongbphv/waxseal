"""Tests for the in-memory backend (embedding + test doubles)."""

from concurrent.futures import ThreadPoolExecutor

import pytest

from tests.adapters.backend_contract import BackendContractTests
from tests.adapters.test_jsonl import build_entry
from waxseal import AuditLog, VersionRegistry, verify_chain
from waxseal.adapters.memory import MemoryBackend
from waxseal.domain.header import GENESIS_PREV_HASH, Entry

PT = "application/vnd.test.event+json"


class TestMemoryBackendContract(BackendContractTests):
    @pytest.fixture()
    def backend(self) -> MemoryBackend:
        return MemoryBackend()


class TestMemoryBackend:
    def test_first_append_gets_seq_0_and_genesis_prev(self) -> None:
        backend = MemoryBackend()
        seen: list[tuple[int, str]] = []

        def build(seq: int, prev: str) -> Entry:
            seen.append((seq, prev))
            return build_entry(seq, prev)

        backend.append(build)
        assert seen == [(0, GENESIS_PREV_HASH)]

    def test_round_trip_and_verify(self) -> None:
        backend = MemoryBackend()
        for _ in range(3):
            backend.append(lambda seq, prev: build_entry(seq, prev))
        assert verify_chain(backend.entries(), VersionRegistry()).checked == 3

    def test_auditlog_accepts_memory_backend_directly(self) -> None:
        log = AuditLog(MemoryBackend(), now_fn=lambda: "2026-08-21T06:00:00+00:00")
        log.append(payload={"i": 1}, payload_type=PT)
        assert log.verify().ok

    def test_parallel_appends_never_fork(self) -> None:
        backend = MemoryBackend()

        def worker(_: int) -> None:
            for _ in range(50):
                backend.append(lambda seq, prev: build_entry(seq, prev))

        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(worker, range(8)))
        seqs = [e.header.seq for e in backend.entries()]
        assert seqs == list(range(400))
