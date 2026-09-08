"""The real waxseal client against this server, over real TCP.

This is the test that decides whether the server is a waxseal peer. Everything
else in this suite checks what the server *does*; this checks that the shipped
client — `RemoteBackend`, `HTTPAnchorSink`, `HTTPWitness`, unmodified — cannot
tell it apart from the backends waxseal ships with. The conformance class is the
library's own (`tests/adapters/backend_contract.py`), imported rather than
restated, so a contract change lands here without anyone remembering to copy it.

Real sockets, not an in-process ASGI shim: header handling, status codes and
connection behaviour are exactly the surface a wire contract is about, and an
in-process transport is precisely where those stop being tested.
"""

from __future__ import annotations

import socket
import threading
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest
import uvicorn
from waxseal_server.app import Settings, create_app

from tests.adapters.backend_contract import BackendContractTests
from tests.adapters.test_jsonl import build_entry
from waxseal.adapters.anchors import HTTPAnchorSink
from waxseal.adapters.remote import (
    RemoteBackend,
    RemoteError,
    RemoteRequest,
    RemoteResponse,
    urllib_transport,
)
from waxseal.adapters.witness import HTTPWitness
from waxseal.domain.registry import VersionRegistry
from waxseal.domain.verify import verify_chain


class LiveServer:
    def __init__(self, settings: Settings) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self.port = self._sock.getsockname()[1]
        config = uvicorn.Config(create_app(settings), log_level="warning", lifespan="off")
        self._server = uvicorn.Server(config)
        self._thread = threading.Thread(
            target=self._server.run, kwargs={"sockets": [self._sock]}, daemon=True
        )

    @property
    def base_url(self) -> str:
        # The origin, NOT the chain path: RemoteBackend appends
        # /v1/chains/{chain_id} itself.
        return f"http://127.0.0.1:{self.port}"

    def __enter__(self) -> LiveServer:
        self._thread.start()
        deadline = threading.Event()
        while not self._server.started:
            if deadline.wait(0.01):  # pragma: no cover - never set; a pure sleep
                break
        return self

    def __exit__(self, *_: object) -> None:
        self._server.should_exit = True
        self._thread.join(timeout=10)


@pytest.fixture
def live(tmp_path: Path) -> Iterator[LiveServer]:
    with LiveServer(Settings(data_dir=tmp_path / "data")) as server:
        yield server


@pytest.fixture
def keyed_live(tmp_path: Path) -> Iterator[LiveServer]:
    settings = Settings(
        data_dir=tmp_path / "data", api_key="chain-key", witness_api_key="witness-key"
    )
    with LiveServer(settings) as server:
        yield server


class TestServerSatisfiesTheBackendContract(BackendContractTests):
    """Every conformance test waxseal applies to JSONL, SQLite, S3 and memory."""

    @pytest.fixture()
    def backend(self, live: LiveServer) -> RemoteBackend:
        return RemoteBackend(live.base_url)


class TestChainVerifiesThroughTheClient:
    def test_a_chain_written_over_http_verifies_client_side(self, live: LiveServer) -> None:
        backend = RemoteBackend(live.base_url)
        for _ in range(5):
            backend.append(lambda seq, prev: build_entry(seq, prev))
        result = verify_chain(list(backend.entries()), VersionRegistry())
        assert result.ok
        assert result.broken_seq is None

    def test_two_chain_ids_stay_independent_over_the_wire(self, live: LiveServer) -> None:
        alpha = RemoteBackend(live.base_url, chain_id="alpha")
        beta = RemoteBackend(live.base_url, chain_id="beta")
        alpha.append(lambda seq, prev: build_entry(seq, prev))
        alpha.append(lambda seq, prev: build_entry(seq, prev))
        beta.append(lambda seq, prev: build_entry(seq, prev))
        assert len(list(alpha.entries())) == 2
        assert len(list(beta.entries())) == 1


def _synchronized_transport(barrier: threading.Barrier, conflicts: list[int]) -> Any:
    """Hold both writers at the same empty `/head`, then count the 409s.

    Forcing the collision at the transport rather than by hand-feeding a stale
    body keeps the client's own contract intact: `build` is re-invoked with the
    fresh `(seq, prev_hash)` after a loss, exactly as `WriterBackend.append`
    requires, so what is under test is the server's precondition and not a
    misuse of the client.
    """
    inner = urllib_transport()
    released = threading.Event()

    def transport(request: RemoteRequest) -> RemoteResponse:
        first_head = request.method == "GET" and request.url.endswith("/head")
        response = inner(request)
        if first_head and not released.is_set():
            barrier.wait(timeout=10)
            released.set()
        if response.status == 409:
            conflicts.append(1)
        return response

    return transport


class TestCompareAndSetRace:
    def test_two_writers_racing_one_seq_yield_one_409_and_no_fork(self, live: LiveServer) -> None:
        # The plan's acceptance criterion for the server: two writers race, one
        # gets a 409. Falsifiability receipt: remove the CAS check in
        # ChainStore.append's builder and no 409 is ever served — both land at
        # seq 0 and verify_chain reports the fork as seq_gap.
        barrier = threading.Barrier(2)
        conflicts: list[int] = []
        writers = [
            RemoteBackend(live.base_url, transport=_synchronized_transport(barrier, conflicts))
            for _ in range(2)
        ]

        def race(backend: RemoteBackend) -> int:
            return backend.append(lambda seq, prev: build_entry(seq, prev)).header.seq

        with ThreadPoolExecutor(max_workers=2) as pool:
            seqs = sorted(pool.map(race, writers))

        assert conflicts, "no writer was refused: the precondition never fired"
        # The loser's retry rebuilds against the fresh tail, so both writes
        # land — at DIFFERENT seqs. A 409 costs a round trip; a fork costs the
        # chain.
        assert seqs == [0, 1]
        entries = list(RemoteBackend(live.base_url).entries())
        assert [e.header.seq for e in entries] == [0, 1]
        assert verify_chain(entries, VersionRegistry()).ok

    def test_many_writers_never_fork_the_chain(self, live: LiveServer) -> None:
        backends = [RemoteBackend(live.base_url) for _ in range(6)]

        def write(backend: RemoteBackend) -> None:
            for _ in range(5):
                backend.append(lambda seq, prev: build_entry(seq, prev))

        with ThreadPoolExecutor(max_workers=len(backends)) as pool:
            list(pool.map(write, backends))

        entries = list(backends[0].entries())
        assert [e.header.seq for e in entries] == list(range(30))
        assert verify_chain(entries, VersionRegistry()).ok


class TestAuthenticationOverTheWire:
    def test_the_client_bearer_token_is_accepted(self, keyed_live: LiveServer) -> None:
        backend = RemoteBackend(keyed_live.base_url, api_key="chain-key")
        backend.append(lambda seq, prev: build_entry(seq, prev))
        assert len(list(backend.entries())) == 1

    def test_an_unauthenticated_client_cannot_write(self, keyed_live: LiveServer) -> None:
        backend = RemoteBackend(keyed_live.base_url)
        with pytest.raises(RemoteError, match="401"):
            backend.append(lambda seq, prev: build_entry(seq, prev))


class TestAnchorAndWitnessClients:
    def _checkpoint(self, seq: int) -> Any:
        from waxseal.domain.checkpoint import Checkpoint

        return Checkpoint(seq=seq, entry_hash="aa" * 32, root="bb" * 32)

    def test_the_shipped_anchor_sink_gets_a_receipt(self, live: LiveServer) -> None:
        sink = HTTPAnchorSink(f"{live.base_url}/v1/witness/w1")
        assert isinstance(sink.anchor(self._checkpoint(1)), str)

    def test_the_shipped_witness_reads_its_checkpoints_back(self, live: LiveServer) -> None:
        url = f"{live.base_url}/v1/witness/w1"
        HTTPAnchorSink(url).anchor(self._checkpoint(1))
        HTTPAnchorSink(url).anchor(self._checkpoint(2))
        observation = HTTPWitness(url).fetch()
        assert [c.seq for c in observation.checkpoints] == [1, 2]
        assert observation.unreadable == 0

    def test_a_witness_that_has_seen_nothing_is_an_answer_not_an_error(
        self, live: LiveServer
    ) -> None:
        # REMOTE.md section 8: 404 here means "seen nothing yet".
        observation = HTTPWitness(f"{live.base_url}/v1/witness/fresh").fetch()
        assert observation.checkpoints == ()

    def test_the_witness_credential_is_the_one_the_client_sends(
        self, keyed_live: LiveServer
    ) -> None:
        url = f"{keyed_live.base_url}/v1/witness/w1"
        HTTPAnchorSink(url, api_key="witness-key").anchor(self._checkpoint(1))
        assert len(HTTPWitness(url, api_key="witness-key").fetch().checkpoints) == 1

    def test_the_chain_write_key_does_not_open_the_witness(self, keyed_live: LiveServer) -> None:
        sink = HTTPAnchorSink(f"{keyed_live.base_url}/v1/witness/w1", api_key="chain-key")
        with pytest.raises(RuntimeError, match="401"):
            sink.anchor(self._checkpoint(1))
