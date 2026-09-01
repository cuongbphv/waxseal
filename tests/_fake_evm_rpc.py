"""A minimal JSON-RPC HTTP server standing in for an EVM node, for CLI-level
tests of `waxseal ledger-status` / `verify --rpc` / the ledger write commands.

Not a mock: like `test_cli_witness.py`'s `WitnessService`, this opens a real
socket and answers real HTTP requests, because the CLI never exposes a
`Transport` injection seam of its own — it always builds `EvmLedgerReader`/
`EvmLedgerSink` against `urllib_transport()`. `tests/adapters/test_evm.py`
already covers `adapters/evm.py`'s own decoding against hand-built ABI bytes
with an injected fake `Transport`; this file exists one layer up, to drive
`waxseal.cli.main()` as a real operator would invoke it, over a real socket.

`eth_call` answers are keyed by the calldata's four-byte selector, mirroring
`tests/adapters/test_evm.py`'s own `calls()` helper (kept independent rather
than imported, since importing test code across files is the kind of
cross-test coupling this project's own tests avoid elsewhere).
"""

from __future__ import annotations

import http.server
import json
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from waxseal.domain import abi as _abi
from waxseal.domain.abi import SELECTOR_DEADLINE_OF as _DEADLINE_OF

WORD = 32


def word(value: int) -> bytes:
    return value.to_bytes(WORD, "big")


def hex32(text: str) -> bytes:
    return bytes.fromhex(text)


def hexdata(*chunks: bytes) -> str:
    return "0x" + b"".join(chunks).hex()


def dynamic_bytes(raw: bytes) -> str:
    pad = (-len(raw)) % WORD
    return hexdata(word(WORD), word(len(raw)), raw + b"\x00" * pad)


def rpc_ok(value: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": 1, "result": value}


def rpc_revert(
    selector: str = "45ed42e1", *, data: str | None = None, code: int = 3
) -> dict[str, Any]:
    payload = f"0x{selector}{'11' * 32}" if data is None else data
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "error": {
            "code": code,
            "message": f"execution reverted: custom error 0x{selector}",
            "data": payload,
        },
    }


CallHandler = Callable[[str, list[Any]], dict[str, Any]]


# ---------------------------------------------------------------- read node
#
# The same selectors adapters/evm.py itself uses, imported rather than
# retyped, so a selector drift shows up as an import error here rather than
# as two hand-copied hex strings quietly disagreeing.

LAST_SEEN = _abi.SELECTOR_LAST_SEEN.hex()
DEADLINE_OF = _DEADLINE_OF.hex()
IS_DELINQUENT = _abi.SELECTOR_IS_DELINQUENT.hex()
LOOKUP = _abi.SELECTOR_LOOKUP.hex()
BOND_OF = _abi.SELECTOR_BOND_OF.hex()


def bond_return(*, amount_wei: int = 0, slashed: bool = False) -> dict[str, Any]:
    return rpc_ok(hexdata(word(amount_wei), word(0), word(0), word(1 if slashed else 0)))


def head_return(*, seq: int, entry_hash: str, root: str, block_time: int) -> dict[str, Any]:
    return rpc_ok(hexdata(word(seq), hex32(entry_hash), hex32(root), word(block_time)))


def liveness_node(
    *, head: dict[str, Any] | None = None, deadline: int = 3600, delinquent: bool = False
) -> CallHandler:
    """A read node answering `lastSeen`/`deadlineOf`/`isDelinquent`, mirroring
    `tests/adapters/test_evm.py`'s own `liveness_node`. The default head is
    stamped at the CURRENT wall clock, matching `full_node`'s own default,
    so a caller not passing `head` gets a LIVE reading by default."""
    import time

    table = {
        LAST_SEEN: head
        if head is not None
        else head_return(seq=41, entry_hash="ab" * 32, root="cd" * 32, block_time=int(time.time())),
        DEADLINE_OF: rpc_ok(hexdata(word(deadline))),
        IS_DELINQUENT: rpc_ok(hexdata(word(1 if delinquent else 0))),
    }
    return calls_by_selector(table)


def registry_node(*, lookup: dict[str, Any]) -> CallHandler:
    return calls_by_selector({LOOKUP: lookup})


def bond_node(*, bond: dict[str, Any]) -> CallHandler:
    return calls_by_selector({BOND_OF: bond})


def full_node(
    *,
    head: dict[str, Any] | None = None,
    deadline: int = 3600,
    lookup: dict[str, Any] | None = None,
    bond: dict[str, Any] | None = None,
) -> CallHandler:
    """One node answering whichever of liveness/registry/bond selectors the
    caller configures, for `ledger-status --liveness --registry --bond`
    tests that need all three answered by one server. The default head is
    stamped at the CURRENT wall clock (not a fixed past timestamp) so a test
    exercising registry/bond in isolation gets a LIVE liveness reading by
    default, rather than an incidental DELINQUENT one from a stale fixture
    timestamp escalating a verdict the test never meant to touch."""
    import time

    table = {
        LAST_SEEN: head
        if head is not None
        else head_return(seq=41, entry_hash="ab" * 32, root="cd" * 32, block_time=int(time.time())),
        DEADLINE_OF: rpc_ok(hexdata(word(deadline))),
        IS_DELINQUENT: rpc_ok(hexdata(word(0))),
    }
    if lookup is not None:
        table[LOOKUP] = lookup
    if bond is not None:
        table[BOND_OF] = bond
    return calls_by_selector(table)


def calls_by_selector(
    table: Mapping[str, dict[str, Any]], *, default: dict[str, Any] | None = None
) -> CallHandler:
    """An `eth_call`-only node keyed by the calldata's four-byte selector."""

    def handler(method: str, params: list[Any]) -> dict[str, Any]:
        assert method == "eth_call"
        selector = params[0]["data"][2:10]
        answer = table.get(selector, default)
        assert answer is not None, f"fake node has no answer for selector {selector}"
        return answer

    return handler


# ------------------------------------------------------------- write fixtures
#
# The canned answers `EvmLedgerSink._send` needs, in the order it asks: a
# chain id, a nonce, a block (for baseFeePerGas), a priority fee, a gas
# estimate, a raw-transaction broadcast, a receipt, and a confirmation block.
# Every number here is immediately-final on purpose (receipt present and
# confirm block already past `blockNumber` on the FIRST poll) so no test
# sleeps: `EvmLedgerSink._poll` only calls the injected sleep_fn between
# attempts, never before the first one.

TX_HASH = "0x" + "ab" * 32
CHAIN_ID_HEX = "0x7a69"  # 31337, matching anvil's default — arbitrary otherwise.


def write_node(
    *,
    call_answer: dict[str, Any] | None = None,
    estimate_gas_answer: dict[str, Any] | None = None,
    chain_id_answer: dict[str, Any] | None = None,
) -> CallHandler:
    """A node that answers every RPC method `EvmLedgerSink._send` calls, in
    addition to `eth_call` (via `call_answer`, for a write command that also
    reads first, e.g. nothing today, but kept symmetric with `write_node`'s
    read-capable cousin for tests that mix the two). `chain_id_answer`
    overrides `eth_chainId` alone, for `_eth_chain_id`'s own error paths
    (`_describe_write` calls it before anything else on the write path)."""

    def handler(method: str, params: list[Any]) -> dict[str, Any]:
        if method == "eth_call":
            assert call_answer is not None, "fake write node has no eth_call answer configured"
            return call_answer
        if method == "eth_chainId":
            return chain_id_answer if chain_id_answer is not None else rpc_ok(CHAIN_ID_HEX)
        if method == "eth_getTransactionCount":
            return rpc_ok("0x0")
        if method == "eth_getBlockByNumber":
            return rpc_ok({"number": "0x2", "baseFeePerGas": "0x1"})
        if method == "eth_maxPriorityFeePerGas":
            return rpc_ok("0x1")
        if method == "eth_estimateGas":
            return estimate_gas_answer if estimate_gas_answer is not None else rpc_ok("0x5208")
        if method == "eth_sendRawTransaction":
            return rpc_ok(TX_HASH)
        if method == "eth_getTransactionReceipt":
            return rpc_ok({"status": "0x1", "blockNumber": "0x1"})
        raise AssertionError(f"fake write node has no handler for {method!r}")

    return handler


@dataclass
class RequestLog:
    bodies: list[dict[str, Any]] = field(default_factory=list)


def start_fake_node(
    handler: CallHandler, *, log: RequestLog | None = None
) -> tuple[str, http.server.HTTPServer]:
    """Serve `handler` over a real localhost socket. Returns the base URL and
    the server (caller must `.shutdown()` it, matching `test_cli_witness.py`'s
    own teardown shape)."""

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length)) if length else {}
            if log is not None:
                log.bodies.append(body)
            answer = handler(body["method"], body["params"])
            payload = json.dumps(answer).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args: object) -> None:
            pass

    httpd = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return f"http://127.0.0.1:{httpd.server_port}", httpd
