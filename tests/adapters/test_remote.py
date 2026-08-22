"""Tests for RemoteBackend (SPEC/REMOTE.md wire contract v1).

Trust model under test: the server is a TRUSTED WRITER, not bound against a
malicious one (see adapters/remote.py's module docstring). The tamper-matrix
tests below prove the half of that claim that IS true locally: a server that
serves a corrupted, deleted, duplicated, or reordered entry is still caught
by client-side verify_chain, exactly as a corrupted local file would be.
"""

from __future__ import annotations

import http.server
import json
import threading
from pathlib import Path
from typing import Any

import pytest

from tests.adapters.backend_contract import BackendContractTests
from tests.adapters.fake_chain_server import FakeChainServer, fake_transport
from tests.adapters.test_jsonl import build_entry
from waxseal.adapters._envelope import to_obj
from waxseal.adapters.jsonl import JSONLBackend
from waxseal.adapters.remote import RemoteBackend, RemoteError, RemoteResponse, urllib_transport
from waxseal.domain.header import GENESIS_PREV_HASH, Entry
from waxseal.domain.registry import VersionRegistry
from waxseal.domain.verify import verify_chain


class TestRemoteBackendContract(BackendContractTests):
    @pytest.fixture()
    def backend(self) -> Any:
        server = FakeChainServer()
        return RemoteBackend("http://fake.local", transport=fake_transport(server))


def _quiet_handler_for(server: FakeChainServer) -> type[http.server.BaseHTTPRequestHandler]:
    class Handler(http.server.BaseHTTPRequestHandler):
        def _dispatch(self, method: str) -> None:
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length) if length else None
            status, resp_body = server.handle(method, self.path, dict(self.headers), body)
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(resp_body)

        def do_GET(self) -> None:
            self._dispatch("GET")

        def do_POST(self) -> None:
            self._dispatch("POST")

        def log_message(self, *args: object) -> None:
            pass  # keep test output quiet

    return Handler


class TestRealLocalhostServer:
    """One test through an actual TCP socket: covers urllib_transport's own
    request-building and HTTPError-capture branches, which the in-process
    fake_transport tests above cannot reach (they never touch urllib)."""

    def test_append_and_read_over_real_http(self) -> None:
        server = FakeChainServer()
        httpd = http.server.HTTPServer(("127.0.0.1", 0), _quiet_handler_for(server))
        port = httpd.server_address[1]
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            backend = RemoteBackend(
                f"http://127.0.0.1:{port}", transport=urllib_transport(timeout=5.0)
            )
            first = backend.append(lambda seq, prev: build_entry(seq, prev))
            second = backend.append(lambda seq, prev: build_entry(seq, prev))
            assert [e.entry_hash for e in backend.entries()] == [
                first.entry_hash, second.entry_hash,
            ]
        finally:
            httpd.shutdown()
            thread.join(timeout=5)

    def test_head_404_surfaces_through_urllib_as_empty_trail(self) -> None:
        server = FakeChainServer()
        httpd = http.server.HTTPServer(("127.0.0.1", 0), _quiet_handler_for(server))
        port = httpd.server_address[1]
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            backend = RemoteBackend(
                f"http://127.0.0.1:{port}", transport=urllib_transport(timeout=5.0)
            )
            assert list(backend.entries()) == []  # 404 -> empty, not an exception
        finally:
            httpd.shutdown()
            thread.join(timeout=5)


def _write_chain(server: FakeChainServer, n: int) -> list[Entry]:
    backend = RemoteBackend("http://fake.local", transport=fake_transport(server))
    return [backend.append(lambda seq, prev: build_entry(seq, prev)) for _ in range(n)]


def _read_back(server: FakeChainServer) -> list[Entry]:
    backend = RemoteBackend("http://fake.local", transport=fake_transport(server))
    return list(backend.entries())


class TestTamperMatrix:
    def test_corrupted_entry_is_caught_as_entry_hash_mismatch(self) -> None:
        server = FakeChainServer()
        _write_chain(server, 4)
        server.corrupt("default", 1, header={"ts": "2027-01-01T00:00:00+00:00"})
        result = verify_chain(_read_back(server), VersionRegistry())
        assert not result.ok
        assert result.broken_seq == 1
        assert result.reason == "entry_hash_mismatch"

    def test_deleted_entry_is_caught_as_seq_gap(self) -> None:
        server = FakeChainServer()
        _write_chain(server, 4)
        server.delete("default", 1)
        result = verify_chain(_read_back(server), VersionRegistry())
        assert not result.ok
        assert result.reason == "seq_gap"
        assert result.broken_seq == 2  # seq 2 now sits at position 1

    def test_duplicated_entry_is_caught_as_seq_gap(self) -> None:
        server = FakeChainServer()
        _write_chain(server, 4)
        server.insert_duplicate("default", 1)
        result = verify_chain(_read_back(server), VersionRegistry())
        assert not result.ok
        assert result.reason == "seq_gap"

    def test_reordered_entries_are_caught(self) -> None:
        server = FakeChainServer()
        _write_chain(server, 4)
        with server._lock:  # noqa: SLF001 - test-only direct swap, no client API for reorder
            entries = server._chains["default"]
            entries[1], entries[2] = entries[2], entries[1]
        result = verify_chain(_read_back(server), VersionRegistry())
        assert not result.ok
        assert result.reason in ("seq_gap", "prev_hash_mismatch")


class TestReentrantBuild:
    def test_409_causes_build_to_be_invoked_again_with_a_fresh_tail(self) -> None:
        server = FakeChainServer()
        real_transport = fake_transport(server)
        posts = 0

        def transport(request: Any) -> RemoteResponse:
            nonlocal posts
            if request.method == "POST":
                posts += 1
                if posts == 1:
                    # Simulate losing the race: another writer's entry lands
                    # in the server first, so THIS client's first attempt
                    # (built against the tail it read before the race) is
                    # rejected — never accepted alongside it.
                    server.handle(
                        "POST", request.url, {},
                        json.dumps(
                            to_obj(build_entry(0, GENESIS_PREV_HASH), backend="Remote")
                        ).encode(),
                    )
                    return RemoteResponse(status=409)
            return real_transport(request)

        backend = RemoteBackend("http://fake.local", transport=transport)
        seen: list[tuple[int, str]] = []

        def build(seq: int, prev: str) -> Entry:
            seen.append((seq, prev))
            return build_entry(seq, prev)

        entry = backend.append(build)
        assert posts == 2
        assert seen[0] == (0, GENESIS_PREV_HASH)
        assert seen[1][0] == 1  # re-invoked against the post-race tail
        assert entry.header.seq == 1


class TestEntryHashParity:
    def test_same_payload_same_entry_hash_as_jsonl(self, tmp_path: Path) -> None:
        jsonl = JSONLBackend(tmp_path / "trail.jsonl")
        remote = RemoteBackend("http://fake.local", transport=fake_transport(FakeChainServer()))
        for backend in (jsonl, remote):
            for i in range(3):
                backend.append(
                    lambda seq, prev, i=i: build_entry(seq, prev, f'{{"i":{i}}}'.encode())
                )
        assert [e.entry_hash for e in jsonl.entries()] == [
            e.entry_hash for e in remote.entries()
        ]


class TestPayloadRejection:
    def test_payload_none_raises_before_any_http_call(self) -> None:
        # Guarded by _envelope.to_obj itself — no transport should ever run.
        calls = 0

        def counting_transport(request: Any) -> RemoteResponse:
            # append() reads /head before invoking build() (same shape as
            # s3.py's _tail()-then-build) — that GET is expected. What must
            # never happen is a POST: to_obj's own payload=None guard fires
            # inside build(), before any entry is serialized for the wire.
            nonlocal calls
            calls += 1
            assert request.method == "GET"
            return RemoteResponse(status=404)

        backend = RemoteBackend("http://fake.local", transport=counting_transport)

        def build_headerless(seq: int, prev: str) -> Entry:
            e = build_entry(seq, prev)
            return Entry(header=e.header, entry_hash=e.entry_hash, payload=None)

        with pytest.raises(ValueError, match="payload"):
            backend.append(build_headerless)
        assert calls == 1  # the one /head GET, and nothing past it


class TestNonProtocolStatusRaisesRemoteError:
    def test_unexpected_status_on_post_raises(self) -> None:
        def transport(request: Any) -> RemoteResponse:
            if request.method == "GET":
                return RemoteResponse(status=404)
            return RemoteResponse(status=500, body=b"boom")

        backend = RemoteBackend("http://fake.local", transport=transport)
        with pytest.raises(RemoteError, match="500"):
            backend.append(lambda seq, prev: build_entry(seq, prev))

    def test_unexpected_status_on_entries_raises(self) -> None:
        def transport(request: Any) -> RemoteResponse:
            if request.method == "GET" and request.url.endswith("/head"):
                return RemoteResponse(status=404)
            return RemoteResponse(status=503, body=b"unavailable")

        backend = RemoteBackend("http://fake.local", transport=transport)
        with pytest.raises(RemoteError, match="503"):
            list(backend.entries())

    def test_unexpected_status_on_head_raises(self) -> None:
        def transport(request: Any) -> RemoteResponse:
            return RemoteResponse(status=500, body=b"boom")

        backend = RemoteBackend("http://fake.local", transport=transport)
        with pytest.raises(RemoteError, match="500"):
            backend.append(lambda seq, prev: build_entry(seq, prev))


class TestMalformedBody:
    def test_non_json_200_body_on_entries_raises_remote_error(self) -> None:
        # A 200 with an unparsable body (captive portal, proxy error page,
        # truncated response) must fail the same honest way a non-2xx status
        # does — not escape as an uncaught JSONDecodeError.
        def transport(request: Any) -> RemoteResponse:
            if request.method == "GET" and request.url.endswith("/head"):
                return RemoteResponse(status=404)
            return RemoteResponse(status=200, body=b"<html>proxy error</html>")

        backend = RemoteBackend("http://fake.local", transport=transport)
        with pytest.raises(RemoteError):
            list(backend.entries())

    def test_well_formed_json_missing_entries_key_raises_remote_error(self) -> None:
        def transport(request: Any) -> RemoteResponse:
            if request.method == "GET" and request.url.endswith("/head"):
                return RemoteResponse(status=404)
            return RemoteResponse(status=200, body=b'{"unexpected": true}')

        backend = RemoteBackend("http://fake.local", transport=transport)
        with pytest.raises(RemoteError):
            list(backend.entries())

    def test_non_json_200_body_on_head_raises_remote_error(self) -> None:
        def transport(request: Any) -> RemoteResponse:
            return RemoteResponse(status=200, body=b"not json at all")

        backend = RemoteBackend("http://fake.local", transport=transport)
        with pytest.raises(RemoteError):
            backend.append(lambda seq, prev: build_entry(seq, prev))


class TestURLConstruction:
    def test_chain_id_is_quoted_against_path_injection(self) -> None:
        captured = []

        def transport(request: Any) -> RemoteResponse:
            captured.append(request.url)
            return RemoteResponse(status=404)

        backend = RemoteBackend(
            "http://fake.local", transport=transport, chain_id="../../admin?x=1"
        )
        list(backend.entries())
        # The traversal/query-injection characters must not survive
        # unescaped into the request path.
        assert "../../admin" not in captured[0]
        assert "?x=1" not in captured[0]

    def test_cursor_is_quoted_in_the_pagination_url(self) -> None:
        seen_urls = []

        def transport(request: Any) -> RemoteResponse:
            seen_urls.append(request.url)
            if request.url.endswith("/head"):
                return RemoteResponse(status=404)
            if "cursor=" not in request.url:
                return RemoteResponse(
                    status=200,
                    body=json.dumps({"entries": [], "next_cursor": "a/b?c=1"}).encode(),
                )
            return RemoteResponse(status=200, body=json.dumps({"entries": []}).encode())

        backend = RemoteBackend("http://fake.local", transport=transport)
        list(backend.entries())
        assert any("cursor=a%2Fb%3Fc%3D1" in u for u in seen_urls)


class TestStuckPagination:
    def test_a_server_that_never_advances_the_cursor_fails_loudly(self) -> None:
        # A cursor that never changes cannot terminate the loop on its own —
        # this must raise rather than spin forever (same "fails loudly
        # instead of hanging" precedent as append's _MAX_RACE_RETRIES).
        def transport(request: Any) -> RemoteResponse:
            if request.url.endswith("/head"):
                return RemoteResponse(status=404)
            return RemoteResponse(
                status=200,
                body=json.dumps({"entries": [], "next_cursor": "stuck"}).encode(),
            )

        backend = RemoteBackend("http://fake.local", transport=transport)
        with pytest.raises(RemoteError):
            list(backend.entries())


class TestRaceExhaustion:
    def test_append_raises_after_max_retries_all_lose(self) -> None:
        def always_409(request: Any) -> RemoteResponse:
            if request.method == "GET":
                return RemoteResponse(status=404)
            return RemoteResponse(status=409)

        backend = RemoteBackend("http://fake.local", transport=always_409)
        with pytest.raises(RemoteError, match="pathological"):
            backend.append(lambda seq, prev: build_entry(seq, prev))


class TestAuth:
    def test_api_key_sent_as_bearer_header_never_in_url(self) -> None:
        captured = []

        def transport(request: Any) -> RemoteResponse:
            captured.append(request)
            return RemoteResponse(status=404)

        backend = RemoteBackend(
            "http://fake.local", transport=transport, api_key="secret-token-123"
        )
        list(backend.entries())
        assert all("secret-token-123" not in r.url for r in captured)
        assert captured[0].headers["Authorization"] == "Bearer secret-token-123"

    def test_no_api_key_means_no_authorization_header(self) -> None:
        captured = []

        def transport(request: Any) -> RemoteResponse:
            captured.append(request)
            return RemoteResponse(status=404)

        backend = RemoteBackend("http://fake.local", transport=transport)
        list(backend.entries())
        assert "Authorization" not in captured[0].headers


class TestPagination:
    def test_entries_page_across_cursor_boundary(self) -> None:
        server = FakeChainServer(page_size=2)
        _write_chain(server, 5)
        entries = _read_back(server)
        assert [e.header.seq for e in entries] == [0, 1, 2, 3, 4]


class TestConcurrencyFalsifiability:
    """Falsifiability receipts (CLAUDE.md's concurrency-test requirement,
    applied to the remote peer): both measured 2026-08-22, 5 runs each.
    """

    def test_strict_server_never_forks_under_concurrent_writers(self) -> None:
        # Receipt 1: enforce_precondition=True (strict, the real contract).
        # Measured 2026-08-22, 5 runs: 0 forks every time, rejected_races
        # exactly 3 every time. Two earlier designs were tried and measured
        # as failing before this one: a bare time.sleep between GET /head and
        # POST (0/5 rejections — the 4 threads never actually interleaved),
        # and a threading.Barrier gating the START of each thread's first GET
        # /head (also 0/5 — the GIL let each thread run head-read-through-POST
        # to completion before switching, so "starting together" never meant
        # "racing together"). What actually works: capture each thread's head
        # snapshot FIRST, then hold all 4 at the barrier BEFORE returning that
        # snapshot to the caller — guaranteeing all 4 build against the same
        # stale tail no matter how the GIL schedules them, so exactly 3 of the
        # 4 simultaneous POSTs the server serializes are rejected.
        import threading
        from concurrent.futures import ThreadPoolExecutor

        server = FakeChainServer(enforce_precondition=True)
        barrier = threading.Barrier(4)

        def gated_transport(inner: Any) -> Any:
            state = {"gated": False}

            def transport(request: Any) -> RemoteResponse:
                if request.method == "GET" and request.url.endswith("/head") and not state["gated"]:
                    state["gated"] = True
                    resp = inner(request)
                    barrier.wait()  # hold the stale snapshot until all 4 have theirs
                    return resp
                return inner(request)

            return transport

        backends = [
            RemoteBackend("http://fake.local", transport=gated_transport(fake_transport(server)))
            for _ in range(4)
        ]

        def worker(backend: RemoteBackend) -> None:
            for _ in range(10):
                backend.append(lambda seq, prev: build_entry(seq, prev))

        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(worker, backends))
        entries = _read_back(server)
        assert len(entries) == 40
        assert verify_chain(entries, VersionRegistry()).ok
        assert server.rejected_races == 3  # exactly the 3 losers of the forced first race

    def test_permissive_server_forks_a_deterministic_race(self) -> None:
        # Receipt 2 (deterministic, not timing-dependent): with the
        # precondition check disabled, two envelopes built against the SAME
        # (seq, prev_hash) are both accepted — the fork this contract exists
        # to prevent, reproduced without relying on thread scheduling luck.
        server = FakeChainServer(enforce_precondition=False)
        first = build_entry(0, GENESIS_PREV_HASH)
        second = build_entry(0, GENESIS_PREV_HASH)  # same (seq, prev_hash) as first
        for entry in (first, second):
            server.handle(
                "POST", "http://fake.local/v1/chains/default/entries", {},
                json.dumps(to_obj(entry, backend="Remote")).encode(),
            )
        result = verify_chain(_read_back(server), VersionRegistry())
        assert not result.ok
        assert result.reason == "seq_gap"  # two seq=0 rows: position 1 expects seq=1
