"""Concurrency: read-tail + append must be one critical section (CLAUDE.md rule 7).

Falsifiability receipt: with the JSONL file lock replaced by
contextlib.nullcontext, this test failed 5 out of 5 runs on macOS
(measured 2026-08-21 while developing this module). If it never failed on
broken code it would prove nothing.
"""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from waxseal import AuditLog

PT = "application/vnd.test.event+json"
THREADS = 8
APPENDS_PER_THREAD = 25


@pytest.mark.parametrize("filename", ["trail.jsonl", "trail.db"])
def test_parallel_appends_never_fork_the_chain(tmp_path: Path, filename: str) -> None:
    path = tmp_path / filename

    def worker(worker_id: int) -> None:
        log = AuditLog.open(path)
        for i in range(APPENDS_PER_THREAD):
            log.append(payload={"w": worker_id, "i": i}, payload_type=PT)

    with ThreadPoolExecutor(max_workers=THREADS) as pool:
        list(pool.map(worker, range(THREADS)))

    log = AuditLog.open(path)
    result = log.verify(measure_drops=False)
    assert result.ok, f"chain broken at seq={result.broken_seq}: {result.reason}"
    assert result.checked == THREADS * APPENDS_PER_THREAD

    # No fork: every seq unique and contiguous.
    seqs = [e.header.seq for e in log._backend.entries()]
    assert seqs == list(range(THREADS * APPENDS_PER_THREAD))
