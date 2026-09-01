"""`waxseal anchor --evm-rpc --evm-liveness` (F4): publishing a checkpoint to
an AnchoringLiveness contract as a THIRD independently-recording anchor
sink, alongside the existing `--tsa-url`/`--ots-calendar`. Uses the same
fake-write-node fixture `test_cli_ledger_write.py` uses for `registry
publish`/`bond deposit|prove`, since `EvmAnchorSink` sits on the exact same
`EvmLedgerSink`/`_send` write path.
"""

from __future__ import annotations

import http.server
import json
import sys
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from tests._fake_evm_rpc import TX_HASH, start_fake_node, write_node
from waxseal import AuditLog
from waxseal.cli import main

LIVENESS_ADDR = "0x" + "11" * 20
PT = "application/vnd.test.event+json"

FAKE_SIGNER = '''
import sys

def main():
    verb = sys.argv[1] if len(sys.argv) > 1 else ""
    if verb == "address":
        sys.stdout.write("0x" + "aa" * 20)
    elif verb == "sign-digest":
        sys.stdout.write("0x" + "11" * 65)
    elif verb == "sign-tx":
        sys.stdin.read()
        sys.stdout.write("0x" + "22" * 40)
    else:
        sys.exit(2)

main()
'''


@pytest.fixture
def signer_cmd(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    script = tmp_path / "fake_signer.py"
    script.write_text(FAKE_SIGNER)
    cmd = f"{sys.executable} {script}"
    monkeypatch.setenv("WAXSEAL_EVM_SIGNER_CMD", cmd)
    return cmd


@pytest.fixture
def two_write_nodes() -> Iterator[Callable[[], list[str]]]:
    started: list[tuple[http.server.HTTPServer, http.server.HTTPServer]] = []

    def factory() -> list[str]:
        url_a, server_a = start_fake_node(write_node())
        url_b, server_b = start_fake_node(write_node())
        started.append((server_a, server_b))
        return [url_a, url_b]

    yield factory
    for server_a, server_b in started:
        server_a.shutdown()
        server_b.shutdown()


def make_trail(path: Path) -> None:
    log = AuditLog.open(path)
    log.append(payload={"i": 0}, payload_type=PT)


class TestEvmAnchor:
    def test_happy_path_records_an_evm_receipt(
        self, tmp_path: Path, signer_cmd: str, two_write_nodes: Callable[[], list[str]],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        path = tmp_path / "t.jsonl"
        make_trail(path)
        urls = two_write_nodes()
        code = main(
            [
                "anchor", str(path), "--evm-rpc", urls[0], "--evm-rpc", urls[1],
                "--evm-liveness", LIVENESS_ADDR,
            ]
        )
        out = capsys.readouterr().out
        assert code == 0
        record = json.loads(out.splitlines()[0])
        assert "seq" in record and "entry_hash" in record

        sidecar = json.loads((path.parent / (path.name + ".anchors")).read_text().splitlines()[0])
        assert sidecar["receipt"] == f"evm:31337:1:{TX_HASH}"

    def test_verify_anchors_sees_the_evm_receipt_as_structurally_ok_but_unverifiable_by_name(
        self, tmp_path: Path, signer_cmd: str, two_write_nodes: Callable[[], list[str]],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        # `verify --anchors` checks the checkpoint MATH (already correct,
        # hence "anchors ok" prints), but has no RFC 3161/OTS-shaped
        # verifier for an "evm:" receipt — an unrecognised receipt type is
        # unverifiable BY NAME, not evidence of tampering (RFC 6962 §4.6),
        # so this is exit 2, never exit 1. `ledger-status`/`verify
        # --liveness` are the commands that actually cross-check an EVM
        # anchor against the chain; this dimension only ever re-derives the
        # checkpoint frame locally.
        path = tmp_path / "t.jsonl"
        make_trail(path)
        urls = two_write_nodes()
        main(
            [
                "anchor", str(path), "--evm-rpc", urls[0], "--evm-rpc", urls[1],
                "--evm-liveness", LIVENESS_ADDR,
            ]
        )
        capsys.readouterr()
        code = main(["verify", str(path), "--anchors"])
        out = capsys.readouterr().out
        assert code == 2
        assert "anchors ok" in out
        assert "unknown_receipt_type" in out or "unverifiable by name" in out.lower()

    def test_missing_signer_cmd_exits_1_and_records_nothing(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        two_write_nodes: Callable[[], list[str]],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        monkeypatch.delenv("WAXSEAL_EVM_SIGNER_CMD", raising=False)
        path = tmp_path / "t.jsonl"
        make_trail(path)
        urls = two_write_nodes()
        code = main(
            [
                "anchor", str(path), "--evm-rpc", urls[0], "--evm-rpc", urls[1],
                "--evm-liveness", LIVENESS_ADDR,
            ]
        )
        err = capsys.readouterr().err
        assert code == 1
        assert "could not prepare the anchor sink" in err
        assert not (path.parent / (path.name + ".anchors")).exists()

    def test_too_few_evm_rpc_endpoints_exits_1(
        self, tmp_path: Path, signer_cmd: str, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = tmp_path / "t.jsonl"
        make_trail(path)
        code = main(
            [
                "anchor", str(path), "--evm-rpc", "http://only-one",
                "--evm-liveness", LIVENESS_ADDR,
            ]
        )
        err = capsys.readouterr().err
        assert code == 1
        assert "could not prepare the anchor sink" in err

    def test_unreadable_consistency_proof_file_exits_1(
        self, tmp_path: Path, signer_cmd: str, two_write_nodes: Callable[[], list[str]],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        path = tmp_path / "t.jsonl"
        make_trail(path)
        urls = two_write_nodes()
        code = main(
            [
                "anchor", str(path), "--evm-rpc", urls[0], "--evm-rpc", urls[1],
                "--evm-liveness", LIVENESS_ADDR,
                "--evm-consistency-proof-file", str(tmp_path / "nope.json"),
            ]
        )
        err = capsys.readouterr().err
        assert code == 1
        assert "could not prepare the anchor sink" in err

    def test_consistency_proof_file_is_read_and_passed_through(
        self, tmp_path: Path, signer_cmd: str, two_write_nodes: Callable[[], list[str]],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        path = tmp_path / "t.jsonl"
        make_trail(path)
        proof_path = tmp_path / "proof.json"
        proof_path.write_text(json.dumps(["ab" * 32, "cd" * 32]))
        urls = two_write_nodes()
        code = main(
            [
                "anchor", str(path), "--evm-rpc", urls[0], "--evm-rpc", urls[1],
                "--evm-liveness", LIVENESS_ADDR,
                "--evm-consistency-proof-file", str(proof_path),
            ]
        )
        capsys.readouterr()
        assert code == 0

    def test_evm_trail_id_override(
        self, tmp_path: Path, signer_cmd: str, two_write_nodes: Callable[[], list[str]],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        path = tmp_path / "t.jsonl"
        make_trail(path)
        urls = two_write_nodes()
        code = main(
            [
                "anchor", str(path), "--evm-rpc", urls[0], "--evm-rpc", urls[1],
                "--evm-liveness", LIVENESS_ADDR, "--evm-trail-id", "custom-trail",
            ]
        )
        capsys.readouterr()
        assert code == 0
