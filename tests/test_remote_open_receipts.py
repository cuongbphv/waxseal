"""`AuditLog.open(url, receipts_trail=...)` reaches the `.receipts` sidecar —
waxseal-fg4.24.

`RemoteBackend` has accepted `receipts_trail=` since 63dbe2d and every test of
it constructed the backend by hand. `AuditLog.open` — the only documented way
to get a remote log — did not pass the argument, so SPEC.md section 19's
per-append acknowledgment was unreachable from any documented entry point:
built, tested, and off the map.

So these tests never touch `RemoteBackend`. They call the public facade with a
URL, over a real socket, and then look on disk for the sidecar.

FALSIFIABILITY RECEIPT — measured 01/09/2026, baseline **7 tests, 0 failures**
in this file (`uv run --extra dev pytest tests/test_remote_open_receipts.py -q
-p no:randomly`, counts read out of the junit XML):

    1. `receipts_trail=receipts_trail` removed from the `RemoteBackend(...)`
       construction in `log.py` — i.e. the code exactly as it shipped
         -> exit 1, tests=7 failures=4:
            test_the_sidecar_is_written_beside_the_named_trail
            test_the_records_carry_the_servers_own_receipt_chain
            test_the_sidecar_reconciles_against_the_trails_own_hashes
            test_the_sidecar_is_json_lines_a_reader_can_parse_without_waxseal
         The other 3 still PASS: "no sidecar" and "a sidecar nothing ever
         wrote to" are indistinguishable from outside, which is how this
         shipped unnoticed.
    2. the local-target `ValueError` removed (a local trail silently
       accepting a `receipts_trail` nothing would ever write)
         -> exit 1, tests=7 failures=1:
            test_a_local_target_refuses_the_argument_instead_of_ignoring_it
"""

from __future__ import annotations

import http.server
import json
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest

from tests.adapters.fake_chain_server import FakeChainServer
from tests.adapters.test_remote import _quiet_handler_for
from waxseal import AuditLog
from waxseal.adapters.receipts import read_receipts, receipts_path
from waxseal.domain.receipts import ReceiptRecord, reconcile_receipts
from waxseal.domain.verdict import Verdict

PT = "application/vnd.test.event+json"


class LiveChainServer:
    """`FakeChainServer` over a real socket, because `AuditLog.open` builds its
    own transport — there is nowhere to inject one, which is the property
    under test."""

    def __init__(self, *, issue_receipts: bool = True) -> None:
        self.server = FakeChainServer(issue_receipts=issue_receipts)
        self._httpd = http.server.ThreadingHTTPServer(
            ("127.0.0.1", 0), _quiet_handler_for(self.server)
        )
        self.url = f"http://127.0.0.1:{self._httpd.server_address[1]}"
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    def __enter__(self) -> LiveChainServer:
        self._thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join(timeout=5)


@pytest.fixture
def live() -> Iterator[LiveChainServer]:
    with LiveChainServer() as server:
        yield server


@pytest.fixture
def no_key(monkeypatch: pytest.MonkeyPatch) -> None:
    # The fake server ignores credentials; an inherited one would only make
    # the request headers noisier.
    monkeypatch.delenv("WAXSEAL_API_KEY", raising=False)


def append_two(log: AuditLog) -> list[str]:
    return [log.append(payload={"i": i}, payload_type=PT).entry_hash for i in range(2)]


class TestTheDocumentedPathReachesTheSidecar:
    def test_the_sidecar_is_written_beside_the_named_trail(
        self, live: LiveChainServer, tmp_path: Path, no_key: None
    ) -> None:
        trail = tmp_path / "trail.jsonl"
        log = AuditLog.open(live.url, receipts_trail=trail)

        hashes = append_two(log)

        sidecar = read_receipts(trail)
        assert receipts_path(trail) == tmp_path / "trail.jsonl.receipts"
        assert sidecar.present
        records = [line for line in sidecar.lines if isinstance(line, ReceiptRecord)]
        assert [r.entry_hash for r in records] == hashes
        assert [r.seq for r in records] == [0, 1]

    def test_the_records_carry_the_servers_own_receipt_chain(
        self, live: LiveChainServer, tmp_path: Path, no_key: None
    ) -> None:
        # The acknowledgment is only worth something if it is the SERVER's:
        # these two fields are the server's receipt head, not anything the
        # client could have computed from the entry alone.
        trail = tmp_path / "trail.jsonl"
        append_two(AuditLog.open(live.url, receipts_trail=trail))

        records = [line for line in read_receipts(trail).lines if isinstance(line, ReceiptRecord)]
        assert [r.receipt_head for r in records] == live.server.receipt_heads
        assert [r.receipt_seq for r in records] == [0, 1]
        assert {r.source for r in records} == {live.url}

    def test_the_sidecar_reconciles_against_the_trails_own_hashes(
        self, live: LiveChainServer, tmp_path: Path, no_key: None
    ) -> None:
        # The closed loop: what the documented open() wrote is what the
        # documented reconciliation reads.
        trail = tmp_path / "trail.jsonl"
        log = AuditLog.open(live.url, receipts_trail=trail)
        append_two(log)

        result = reconcile_receipts(log.entry_hashes(), read_receipts(trail))

        assert result.verdict is Verdict.OK
        assert result.checked == 2
        assert result.latest_seq == 1


class TestNotRecordedStaysNotRecorded:
    def test_no_receipts_trail_writes_no_sidecar(
        self, live: LiveChainServer, tmp_path: Path, no_key: None
    ) -> None:
        # Opt-in, exactly as before the wiring: naming nowhere to keep
        # acknowledgments is "not recorded", never an error and never a file.
        trail = tmp_path / "trail.jsonl"
        append_two(AuditLog.open(live.url))
        assert not receipts_path(trail).exists()
        assert list(tmp_path.iterdir()) == []

    def test_a_server_that_issues_nothing_leaves_no_records(
        self, tmp_path: Path, no_key: None
    ) -> None:
        # REMOTE.md section 10 is OPTIONAL for a server. The sidecar location
        # was named and the appends succeeded; there is simply nothing to file.
        trail = tmp_path / "trail.jsonl"
        with LiveChainServer(issue_receipts=False) as server:
            append_two(AuditLog.open(server.url, receipts_trail=trail))
        assert not receipts_path(trail).exists()


class TestALocalTargetIsRefused:
    def test_a_local_target_refuses_the_argument_instead_of_ignoring_it(
        self, tmp_path: Path
    ) -> None:
        # The mirror image of `record_drops` against a URL. A silently ignored
        # argument would name a sidecar nothing writes, and "not recorded"
        # would then be indistinguishable from a server that issued nothing.
        with pytest.raises(ValueError, match="receipts_trail requires a remote"):
            AuditLog.open(tmp_path / "trail.jsonl", receipts_trail=tmp_path / "r.jsonl")
        assert list(tmp_path.iterdir()) == []


def test_the_sidecar_is_json_lines_a_reader_can_parse_without_waxseal(
    live: LiveChainServer, tmp_path: Path, no_key: None
) -> None:
    trail = tmp_path / "trail.jsonl"
    append_two(AuditLog.open(live.url, receipts_trail=trail))
    lines = receipts_path(trail).read_text(encoding="utf-8").splitlines()
    assert [json.loads(line)["seq"] for line in lines] == [0, 1]
