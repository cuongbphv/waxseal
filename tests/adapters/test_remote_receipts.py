"""The CLIENT half of the per-append receipt (adapters/remote.py + SPEC 19).

The server's half shipped first: every `201` carries `receipt_seq` and
`receipt_head` (REMOTE.md section 10). This file pins what the client does
with them.

Best-effort is the load-bearing word. The entry is already durable when the
`201` arrives, so a sidecar that cannot be written must never fail or retry
the append — but it must never fail SILENTLY either (CLAUDE.md rule 6). Both
halves of that sentence are tested here.
"""

from __future__ import annotations

import json
import warnings
from datetime import datetime
from pathlib import Path

import pytest

from tests.adapters.fake_chain_server import FakeChainServer, fake_transport
from waxseal import AuditLog
from waxseal.adapters.receipts import read_receipts, receipts_path
from waxseal.adapters.remote import RemoteBackend, RemoteRequest, RemoteResponse
from waxseal.domain.receipts import ReceiptRecord

PT = "application/vnd.test.event+json"


def make_log(
    server: FakeChainServer,
    *,
    receipts_trail: Path | None = None,
    ts: str = "2026-09-01T00:00:00+00:00",
) -> AuditLog:
    backend = RemoteBackend(
        "https://ledger.example",
        transport=fake_transport(server),
        receipts_trail=receipts_trail,
        now_fn=lambda: ts,
    )
    return AuditLog(backend)


class TestReceiptsAreRecorded:
    def test_every_acknowledged_append_lands_one_record(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        log = make_log(FakeChainServer(issue_receipts=True), receipts_trail=trail)
        entries = [log.append(payload={"i": i}, payload_type=PT) for i in range(3)]

        records = read_receipts(trail).lines
        assert [r.seq for r in records if isinstance(r, ReceiptRecord)] == [0, 1, 2]
        assert [r.entry_hash for r in records if isinstance(r, ReceiptRecord)] == [
            e.entry_hash for e in entries
        ]

    def test_the_record_carries_the_servers_own_receipt_chain_position(
        self, tmp_path: Path
    ) -> None:
        # The head is opaque to the client: it exists so a third party can
        # hold the server to its own acknowledgment chain (REMOTE.md 10).
        trail = tmp_path / "trail.jsonl"
        server = FakeChainServer(issue_receipts=True)
        log = make_log(server, receipts_trail=trail)
        log.append(payload={"i": 0}, payload_type=PT)
        log.append(payload={"i": 1}, payload_type=PT)

        heads = [json.loads(line) for line in receipts_path(trail).read_text().splitlines()]
        assert [h["receipt_seq"] for h in heads] == [0, 1]
        assert [h["receipt_head"] for h in heads] == server.receipt_heads

    def test_source_labels_the_server_that_issued_the_receipt(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        log = make_log(FakeChainServer(issue_receipts=True), receipts_trail=trail)
        log.append(payload={"i": 0}, payload_type=PT)
        assert json.loads(receipts_path(trail).read_text())["source"] == "https://ledger.example"

    def test_the_timestamp_is_injectable(self, tmp_path: Path) -> None:
        # Rule 8: tests never sleep to pin a time.
        trail = tmp_path / "trail.jsonl"
        log = make_log(FakeChainServer(issue_receipts=True), receipts_trail=trail, ts="T")
        log.append(payload={"i": 0}, payload_type=PT)
        assert json.loads(receipts_path(trail).read_text())["ts"] == "T"

    def test_the_default_clock_stamps_a_tz_aware_iso_timestamp(self, tmp_path: Path) -> None:
        # The injectable clock has a default, and a record whose `ts` no reader
        # can parse is metadata that lies about being metadata.
        trail = tmp_path / "trail.jsonl"
        backend = RemoteBackend(
            "https://ledger.example",
            transport=fake_transport(FakeChainServer(issue_receipts=True)),
            receipts_trail=trail,
        )
        AuditLog(backend).append(payload={"i": 0}, payload_type=PT)
        stamped = datetime.fromisoformat(json.loads(receipts_path(trail).read_text())["ts"])
        assert stamped.tzinfo is not None

    def test_a_record_never_carries_payload_content(self, tmp_path: Path) -> None:
        # Section 12's rule for section 12's reason: the record is metadata
        # only, so there is no field a payload could ever reach.
        trail = tmp_path / "trail.jsonl"
        log = make_log(FakeChainServer(issue_receipts=True), receipts_trail=trail)
        log.append(payload={"secret": "hunter2"}, payload_type=PT)
        assert "hunter2" not in receipts_path(trail).read_text()


class TestNothingToRecordIsNotAnError:
    def test_a_server_without_receipts_records_nothing_and_does_not_fail(
        self, tmp_path: Path
    ) -> None:
        # REMOTE.md 10: a `201` with no receipt fields is a server that does
        # not implement the section, never an error.
        trail = tmp_path / "trail.jsonl"
        log = make_log(FakeChainServer(issue_receipts=False), receipts_trail=trail)
        log.append(payload={"i": 0}, payload_type=PT)
        assert read_receipts(trail).present is False

    def test_no_sidecar_location_configured_records_nothing(self, tmp_path: Path) -> None:
        log = make_log(FakeChainServer(issue_receipts=True))
        log.append(payload={"i": 0}, payload_type=PT)
        assert list(tmp_path.iterdir()) == []


class TestBestEffortIsLabelledNeverSilent:
    def test_a_sidecar_write_failure_does_not_fail_the_append(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        # The one durable way to make the write fail without root: the sidecar
        # path is already a directory.
        receipts_path(trail).mkdir()
        server = FakeChainServer(issue_receipts=True)
        log = make_log(server, receipts_trail=trail)

        with pytest.warns(RuntimeWarning, match="receipt sidecar"):
            entry = log.append(payload={"i": 0}, payload_type=PT)

        assert entry.header.seq == 0
        assert len(list(log.entries())) == 1  # the entry is durable on the server

    @pytest.mark.parametrize(
        ("body", "why"),
        [
            (b'{"receipt_seq": 0}', "receipt_head missing — both or neither"),
            (b'{"receipt_head": "' + b"d" * 64 + b'"}', "receipt_seq missing"),
            (b'{"receipt_seq": "zero", "receipt_head": "' + b"d" * 64 + b'"}', "seq not an int"),
            (b'{"receipt_seq": 0, "receipt_head": "nope"}', "head not hex64"),
            (b"not json at all", "unparsable body"),
            (b"[]", "not an object"),
        ],
    )
    def test_a_receipt_this_client_cannot_use_is_labelled_and_never_written(
        self, tmp_path: Path, body: bytes, why: str
    ) -> None:
        # Writing a half-understood acknowledgment into OUR OWN format would
        # manufacture a `malformed_receipt_record` break later, out of a
        # server's bad field and no tampering at all.
        trail = tmp_path / "trail.jsonl"

        def transport(request: RemoteRequest) -> RemoteResponse:
            if request.method == "POST":
                return RemoteResponse(status=201, body=body)
            return RemoteResponse(status=404, body=b"{}")

        log = AuditLog(
            RemoteBackend("https://ledger.example", transport=transport, receipts_trail=trail)
        )
        with pytest.warns(RuntimeWarning, match="receipt sidecar"):
            log.append(payload={"i": 0}, payload_type=PT)
        assert read_receipts(trail).present is False, why

    @pytest.mark.parametrize("body", [b"", b"{}", b'{"other": 1}'])
    def test_a_201_that_claims_no_receipt_is_silent_not_a_degradation(
        self, tmp_path: Path, body: bytes
    ) -> None:
        # Distinct from the cases above: a server that never claimed to issue
        # receipts is not a degradation to label, it is a server doing its job.
        trail = tmp_path / "trail.jsonl"

        def transport(request: RemoteRequest) -> RemoteResponse:
            if request.method == "POST":
                return RemoteResponse(status=201, body=body)
            return RemoteResponse(status=404, body=b"{}")

        log = AuditLog(
            RemoteBackend("https://ledger.example", transport=transport, receipts_trail=trail)
        )
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            log.append(payload={"i": 0}, payload_type=PT)
        assert read_receipts(trail).present is False
