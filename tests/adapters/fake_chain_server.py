"""FakeChainServer: an in-memory reference implementation of REMOTE.md's wire
contract v1, shared by the in-process fake-transport tests and the real
localhost http.server smoke test (both must exercise the SAME server logic —
only the transport layer differs, mirroring FakeS3Client's role for s3.py).
"""

from __future__ import annotations

import hashlib
import json
import re
import struct
import threading
from typing import Any
from urllib.parse import parse_qs, urlsplit

from waxseal.adapters.remote import RemoteRequest, RemoteResponse, Transport
from waxseal.domain.header import GENESIS_PREV_HASH

_ROUTE = re.compile(r"/v1/chains/(?P<chain_id>[^/]+)/(?P<resource>head|entries)$")

# SPEC.md section 19's receipt frame, written out from the prose rather than
# imported from anywhere: the server implements it in
# server/waxseal_server/domain/receipts.py, and a fake that borrowed that
# implementation could only ever prove the client agrees with itself.
RECEIPT_FRAME_PREFIX = b"waxseal-receipt-v1\n"
RECEIPT_GENESIS = "0" * 64


def _lp(value: str) -> bytes:
    enc = b"\x01" + value.encode("utf-8")
    return struct.pack(">Q", len(enc)) + enc


def receipt_head(receipt_seq: int, prev_receipt_head: str, entry_hash: str) -> str:
    frame = (
        RECEIPT_FRAME_PREFIX
        + struct.pack(">Q", 3)
        + _lp(str(receipt_seq))
        + _lp(prev_receipt_head)
        + _lp(entry_hash)
    )
    return hashlib.sha256(frame).hexdigest()


class FakeChainServer:
    def __init__(
        self,
        *,
        enforce_precondition: bool = True,
        page_size: int = 1000,
        issue_receipts: bool = False,
    ) -> None:
        self._lock = threading.Lock()
        self._chains: dict[str, list[dict[str, Any]]] = {}
        self.enforce_precondition = enforce_precondition
        self.page_size = page_size
        # REMOTE.md section 10 is OPTIONAL for a server, so the default stays
        # off: a client must keep working against a server that issues nothing.
        self.issue_receipts = issue_receipts
        self.receipt_heads: list[str] = []
        # Falsifiability instrumentation: counts POSTs the server itself
        # rejected as a lost race (409), for the receipt tests to report.
        self.rejected_races = 0

    # -- entry point shared by fake_transport and the real HTTP handler --------
    def handle(
        self, method: str, url: str, headers: dict[str, str], body: bytes | None
    ) -> tuple[int, bytes]:
        parts = urlsplit(url)
        m = _ROUTE.fullmatch(parts.path)
        if not m:
            return 404, b'{"error":"no such route"}'
        chain_id, resource = m.group("chain_id"), m.group("resource")
        if resource == "head":
            return self._head(chain_id)
        if method == "GET":
            cursor = parse_qs(parts.query).get("cursor", [None])[0]
            return self._list(chain_id, cursor)
        if method == "POST":
            assert body is not None
            return self._post(chain_id, body)
        return 404, b'{"error":"no such route"}'  # pragma: no cover - unreachable via _ROUTE

    def _head(self, chain_id: str) -> tuple[int, bytes]:
        with self._lock:
            entries = self._chains.get(chain_id, [])
            if not entries:
                return 404, b'{"error":"empty"}'
            last = entries[-1]
            payload = {"seq": last["header"]["seq"], "entry_hash": last["entry_hash"]}
        return 200, json.dumps(payload).encode("utf-8")

    def _post(self, chain_id: str, body: bytes) -> tuple[int, bytes]:
        obj = json.loads(body)
        with self._lock:
            entries = self._chains.setdefault(chain_id, [])
            expected_seq = len(entries)
            expected_prev = entries[-1]["entry_hash"] if entries else GENESIS_PREV_HASH
            if self.enforce_precondition and (
                obj["header"]["seq"] != expected_seq or obj["header"]["prev_hash"] != expected_prev
            ):
                self.rejected_races += 1
                return 409, b'{"error":"conflict"}'
            entries.append(obj)
            if not self.issue_receipts:
                return 201, b"{}"
            prev = self.receipt_heads[-1] if self.receipt_heads else RECEIPT_GENESIS
            next_seq = len(self.receipt_heads)
            head = receipt_head(next_seq, prev, obj["entry_hash"])
            self.receipt_heads.append(head)
        return 201, json.dumps({"receipt_seq": next_seq, "receipt_head": head}).encode("utf-8")

    def _list(self, chain_id: str, cursor: str | None) -> tuple[int, bytes]:
        with self._lock:
            entries = list(self._chains.get(chain_id, []))
        if not entries:
            return 404, b'{"error":"not found"}'
        offset = int(cursor) if cursor else 0
        page = entries[offset : offset + self.page_size]
        next_offset = offset + len(page)
        next_cursor = str(next_offset) if next_offset < len(entries) else None
        body = json.dumps({"entries": page, "next_cursor": next_cursor}).encode("utf-8")
        return 200, body

    # -- test-only introspection ------------------------------------------------
    def corrupt(self, chain_id: str, seq: int, **fields: Any) -> None:
        """Directly mutate a stored envelope — simulates a compromised or
        buggy server, independent of any client-side write path."""
        with self._lock:
            obj = self._chains[chain_id][seq]
            for key, value in fields.items():
                if key in ("header",):
                    obj["header"].update(value)
                else:
                    obj[key] = value

    def delete(self, chain_id: str, seq: int) -> None:
        with self._lock:
            del self._chains[chain_id][seq]

    def insert_duplicate(self, chain_id: str, seq: int) -> None:
        with self._lock:
            entries = self._chains[chain_id]
            entries.insert(seq, dict(entries[seq]))


def fake_transport(server: FakeChainServer) -> Transport:
    def transport(request: RemoteRequest) -> RemoteResponse:
        status, body = server.handle(request.method, request.url, request.headers, request.body)
        return RemoteResponse(status=status, headers={}, body=body)

    return transport
