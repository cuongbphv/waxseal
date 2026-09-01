"""`waxseal registry publish` / `waxseal bond deposit|prove` (F4).

NOT chain-entry appends (CLAUDE.md's CLI contract forbids the CLI writing to
the audit TRAIL, not to an external ledger) — same footing as `anchor`,
which these tests confirm by never touching a trail path at all. Every
write command needs >=2 `--rpc` endpoints (the underlying `EvmLedgerReader`
refuses fewer, even on the write path — see `_evm_write_sink`'s own
docstring), so two REAL fake JSON-RPC servers back every happy-path test.

Credentials come only from `WAXSEAL_EVM_SIGNER_CMD` — tested here via the
same tiny fake signer script `test_cli_evm_signer.py` exercises directly;
this file only checks that the CLI PLUMBS it correctly (never a key on
argv), not the signer sub-protocol itself again.
"""

from __future__ import annotations

import http.server
import re
import sys
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from tests._fake_evm_rpc import rpc_ok, rpc_revert, start_fake_node, write_node
from waxseal.cli import main
from waxseal.domain.fingerprint import HEADER_FIELDS, fingerprint_for

REGISTRY_ADDR = "0x" + "22" * 20
BOND_ADDR = "0x" + "33" * 20
KNOWN_FINGERPRINT = fingerprint_for(HEADER_FIELDS)
UNKNOWN_FINGERPRINT = "ff" * 32

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


class TestRegistryPublish:
    def test_unknown_fingerprint_exits_1(
        self,
        signer_cmd: str,
        two_write_nodes: Callable[[], list[str]],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        urls = two_write_nodes()
        code = main(
            [
                "registry", "publish", "--descriptor-of", UNKNOWN_FINGERPRINT,
                "--registry", REGISTRY_ADDR, "--rpc", urls[0], "--rpc", urls[1],
            ]
        )
        err = capsys.readouterr().err
        assert code == 1
        assert "not a fingerprint" in err

    def test_missing_signer_cmd_exits_1(
        self, monkeypatch: pytest.MonkeyPatch, two_write_nodes: Callable[[], list[str]],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        monkeypatch.delenv("WAXSEAL_EVM_SIGNER_CMD", raising=False)
        urls = two_write_nodes()
        code = main(
            [
                "registry", "publish", "--descriptor-of", KNOWN_FINGERPRINT,
                "--registry", REGISTRY_ADDR, "--rpc", urls[0], "--rpc", urls[1],
            ]
        )
        err = capsys.readouterr().err
        assert code == 1
        assert "WAXSEAL_EVM_SIGNER_CMD is not set" in err

    def test_too_few_rpc_endpoints_exits_1(
        self, signer_cmd: str, capsys: pytest.CaptureFixture[str]
    ) -> None:
        code = main(
            [
                "registry", "publish", "--descriptor-of", KNOWN_FINGERPRINT,
                "--registry", REGISTRY_ADDR, "--rpc", "http://only-one",
            ]
        )
        err = capsys.readouterr().err
        assert code == 1
        assert "at least 2" in err

    def test_happy_path_prints_chain_id_and_tx(
        self,
        signer_cmd: str,
        two_write_nodes: Callable[[], list[str]],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        urls = two_write_nodes()
        code = main(
            [
                "registry", "publish", "--descriptor-of", KNOWN_FINGERPRINT,
                "--registry", REGISTRY_ADDR, "--rpc", urls[0], "--rpc", urls[1],
            ]
        )
        out = capsys.readouterr().out
        assert code == 0
        assert "chain_id=" in out
        assert re.search(r"tx=0x[0-9a-f]{64}", out)

    def test_write_rpc_selects_which_endpoint_receives_the_transaction(
        self, signer_cmd: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from tests._fake_evm_rpc import RequestLog

        log_a, log_b = RequestLog(), RequestLog()
        url_a, server_a = start_fake_node(write_node(), log=log_a)
        url_b, server_b = start_fake_node(write_node(), log=log_b)
        try:
            code = main(
                [
                    "registry", "publish", "--descriptor-of", KNOWN_FINGERPRINT,
                    "--registry", REGISTRY_ADDR,
                    "--rpc", url_a, "--rpc", url_b, "--write-rpc", url_b,
                ]
            )
        finally:
            server_a.shutdown()
            server_b.shutdown()
        assert code == 0
        # eth_sendRawTransaction only ever reaches the DESIGNATED write
        # endpoint, never the other one merely listed for the read quorum.
        sent_methods_a = {b["method"] for b in log_a.bodies}
        sent_methods_b = {b["method"] for b in log_b.bodies}
        assert "eth_sendRawTransaction" not in sent_methods_a
        assert "eth_sendRawTransaction" in sent_methods_b


class TestBondDeposit:
    def test_non_positive_amount_exits_1(
        self,
        signer_cmd: str,
        two_write_nodes: Callable[[], list[str]],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        urls = two_write_nodes()
        code = main(
            [
                "bond", "deposit", "--bond", BOND_ADDR, "--amount-wei", "0",
                "--rpc", urls[0], "--rpc", urls[1],
            ]
        )
        err = capsys.readouterr().err
        assert code == 1
        assert "must be positive" in err

    def test_happy_path_exits_0(
        self,
        signer_cmd: str,
        two_write_nodes: Callable[[], list[str]],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        urls = two_write_nodes()
        code = main(
            [
                "bond", "deposit", "--bond", BOND_ADDR, "--amount-wei", "1000",
                "--rpc", urls[0], "--rpc", urls[1],
            ]
        )
        out = capsys.readouterr().out
        assert code == 0
        assert "tx=0x" in out

    def test_too_few_rpc_endpoints_exits_1_before_sending(
        self, signer_cmd: str, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # Sink CONSTRUCTION failure (EvmLedgerReader's own >=2 invariant),
        # distinct from a SEND failure: nothing is broadcast at all.
        code = main(
            [
                "bond", "deposit", "--bond", BOND_ADDR, "--amount-wei", "1",
                "--rpc", "http://only-one",
            ]
        )
        err = capsys.readouterr().err
        assert code == 1
        assert "at least 2" in err

    def test_missing_signer_cmd_exits_1_before_sending(
        self, monkeypatch: pytest.MonkeyPatch, two_write_nodes: Callable[[], list[str]],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        monkeypatch.delenv("WAXSEAL_EVM_SIGNER_CMD", raising=False)
        urls = two_write_nodes()
        code = main(
            [
                "bond", "deposit", "--bond", BOND_ADDR, "--amount-wei", "1",
                "--rpc", urls[0], "--rpc", urls[1],
            ]
        )
        err = capsys.readouterr().err
        assert code == 1
        assert "WAXSEAL_EVM_SIGNER_CMD is not set" in err


class TestBondProve:
    def _checkpoint(self, seq: int, entry_hash: str, root: str) -> dict[str, object]:
        return {"seq": seq, "entry_hash": entry_hash, "root": root}

    def test_missing_file_exits_1(
        self, signer_cmd: str, two_write_nodes: Callable[[], list[str]], tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        urls = two_write_nodes()
        code = main(
            [
                "bond", "prove", str(tmp_path / "nope.json"), "--bond", BOND_ADDR,
                "--rpc", urls[0], "--rpc", urls[1],
            ]
        )
        err = capsys.readouterr().err
        assert code == 1
        assert "cannot read" in err

    def test_invalid_json_exits_1(
        self, signer_cmd: str, two_write_nodes: Callable[[], list[str]], tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        proof_path = tmp_path / "proof.json"
        proof_path.write_text("{not json")
        urls = two_write_nodes()
        code = main(
            [
                "bond", "prove", str(proof_path), "--bond", BOND_ADDR,
                "--rpc", urls[0], "--rpc", urls[1],
            ]
        )
        err = capsys.readouterr().err
        assert code == 1
        assert "not valid JSON" in err

    def test_missing_kind_exits_1(
        self, signer_cmd: str, two_write_nodes: Callable[[], list[str]], tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        proof_path = tmp_path / "proof.json"
        proof_path.write_text('{"chain_id": "t"}')
        urls = two_write_nodes()
        code = main(
            [
                "bond", "prove", str(proof_path), "--bond", BOND_ADDR,
                "--rpc", urls[0], "--rpc", urls[1],
            ]
        )
        err = capsys.readouterr().err
        assert code == 1
        assert "'kind' must be" in err

    def test_equivocation_missing_field_exits_1(
        self, signer_cmd: str, two_write_nodes: Callable[[], list[str]], tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        proof_path = tmp_path / "proof.json"
        proof_path.write_text('{"kind": "equivocation", "chain_id": "t"}')
        urls = two_write_nodes()
        code = main(
            [
                "bond", "prove", str(proof_path), "--bond", BOND_ADDR,
                "--rpc", urls[0], "--rpc", urls[1],
            ]
        )
        err = capsys.readouterr().err
        assert code == 1
        assert "malformed equivocation proof" in err

    def test_equivocation_structurally_inadmissible_exits_1(
        self, signer_cmd: str, two_write_nodes: Callable[[], list[str]], tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        # Same checkpoint on both sides: not divergent, so validate() names
        # a reason and submit_fraud_proof refuses BEFORE sending anything.
        cp = self._checkpoint(5, "ab" * 32, "cd" * 32)
        proof_path = tmp_path / "proof.json"
        import json

        proof_path.write_text(
            json.dumps(
                {
                    "kind": "equivocation",
                    "chain_id": "t",
                    "checkpoint_a": cp,
                    "signature_a": "0x" + "11" * 65,
                    "checkpoint_b": cp,
                    "signature_b": "0x" + "22" * 65,
                }
            )
        )
        urls = two_write_nodes()
        code = main(
            [
                "bond", "prove", str(proof_path), "--bond", BOND_ADDR,
                "--rpc", urls[0], "--rpc", urls[1],
            ]
        )
        err = capsys.readouterr().err
        assert code == 1
        assert "not_divergent" in err

    def test_equivocation_happy_path_exits_0(
        self, signer_cmd: str, two_write_nodes: Callable[[], list[str]], tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        import json

        proof_path = tmp_path / "proof.json"
        proof_path.write_text(
            json.dumps(
                {
                    "kind": "equivocation",
                    "chain_id": "t",
                    "checkpoint_a": self._checkpoint(5, "ab" * 32, "cd" * 32),
                    "signature_a": "0x" + "11" * 65,
                    "checkpoint_b": self._checkpoint(5, "ef" * 32, "01" * 32),
                    "signature_b": "0x" + "22" * 65,
                }
            )
        )
        urls = two_write_nodes()
        code = main(
            [
                "bond", "prove", str(proof_path), "--bond", BOND_ADDR,
                "--rpc", urls[0], "--rpc", urls[1],
            ]
        )
        out = capsys.readouterr().out
        assert code == 0
        assert "tx=0x" in out

    def test_non_extension_happy_path_calls_submit_non_extension(
        self, signer_cmd: str, two_write_nodes: Callable[[], list[str]], tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        import json

        proof_path = tmp_path / "proof.json"
        proof_path.write_text(
            json.dumps(
                {
                    "kind": "non_extension",
                    "chain_id": "t",
                    "older": self._checkpoint(5, "ab" * 32, "cd" * 32),
                    "older_signature": "0x" + "11" * 65,
                    "newer": self._checkpoint(9, "ef" * 32, "01" * 32),
                    "newer_signature": "0x" + "22" * 65,
                    "in_older": {"index": 3, "entry_hash": "aa" * 32, "proof": ["bb" * 32]},
                    "in_newer": {
                        "index": 3, "entry_hash": "cc" * 32, "proof": ["0xbb" + "bb" * 31],
                    },
                }
            )
        )
        urls = two_write_nodes()
        code = main(
            [
                "bond", "prove", str(proof_path), "--bond", BOND_ADDR,
                "--rpc", urls[0], "--rpc", urls[1],
            ]
        )
        out = capsys.readouterr().out
        assert code == 0
        assert "tx=0x" in out

    def test_an_inadmissible_non_extension_is_refused_before_the_gas(
        self, signer_cmd: str, two_write_nodes: Callable[[], list[str]], tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Two leaves that AGREE are not a contradiction.

        The contract reverts on it (`LeavesAgree`), and until the two
        non-extension shapes were reconciled this path could not check: the
        CLI built adapter-level leaf claims and called a second entry point
        that validated nothing, so an operator learned this from a revert
        and the gas that paid for it. `submit_fraud_proof` now validates both
        shapes, so the answer arrives before the transaction.
        """
        import json

        leaf = {"index": 3, "entry_hash": "aa" * 32, "proof": ["bb" * 32]}
        proof_path = tmp_path / "proof.json"
        proof_path.write_text(
            json.dumps(
                {
                    "kind": "non_extension",
                    "chain_id": "t",
                    "older": self._checkpoint(5, "ab" * 32, "cd" * 32),
                    "older_signature": "0x" + "11" * 65,
                    "newer": self._checkpoint(9, "ef" * 32, "01" * 32),
                    "newer_signature": "0x" + "22" * 65,
                    "in_older": leaf,
                    "in_newer": leaf,
                }
            )
        )
        urls = two_write_nodes()
        code = main(
            [
                "bond", "prove", str(proof_path), "--bond", BOND_ADDR,
                "--rpc", urls[0], "--rpc", urls[1],
            ]
        )
        err = capsys.readouterr().err
        assert code == 1
        assert "not a non-extension: leaves_agree" in err

    def test_checkpoint_not_an_object_is_malformed(
        self, signer_cmd: str, two_write_nodes: Callable[[], list[str]], tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        import json

        proof_path = tmp_path / "proof.json"
        proof_path.write_text(
            json.dumps(
                {
                    "kind": "equivocation",
                    "chain_id": "t",
                    "checkpoint_a": "not-an-object",
                    "signature_a": "0x" + "11" * 65,
                    "checkpoint_b": self._checkpoint(5, "ef" * 32, "01" * 32),
                    "signature_b": "0x" + "22" * 65,
                }
            )
        )
        urls = two_write_nodes()
        code = main(
            [
                "bond", "prove", str(proof_path), "--bond", BOND_ADDR,
                "--rpc", urls[0], "--rpc", urls[1],
            ]
        )
        err = capsys.readouterr().err
        assert code == 1
        assert "malformed equivocation proof" in err
        assert "must be a JSON object" in err

    def test_leaf_claim_not_an_object_is_malformed(
        self, signer_cmd: str, two_write_nodes: Callable[[], list[str]], tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        import json

        proof_path = tmp_path / "proof.json"
        proof_path.write_text(
            json.dumps(
                {
                    "kind": "non_extension",
                    "chain_id": "t",
                    "older": self._checkpoint(5, "ab" * 32, "cd" * 32),
                    "older_signature": "0x" + "11" * 65,
                    "newer": self._checkpoint(9, "ef" * 32, "01" * 32),
                    "newer_signature": "0x" + "22" * 65,
                    "in_older": "not-an-object",
                    "in_newer": {"index": 3, "entry_hash": "cc" * 32, "proof": []},
                }
            )
        )
        urls = two_write_nodes()
        code = main(
            [
                "bond", "prove", str(proof_path), "--bond", BOND_ADDR,
                "--rpc", urls[0], "--rpc", urls[1],
            ]
        )
        err = capsys.readouterr().err
        assert code == 1
        assert "malformed non_extension proof" in err
        assert "leaf claim must be a JSON object" in err

    def test_too_few_rpc_endpoints_exits_1_before_sending(
        self, signer_cmd: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        import json

        proof_path = tmp_path / "proof.json"
        proof_path.write_text(
            json.dumps(
                {
                    "kind": "equivocation",
                    "chain_id": "t",
                    "checkpoint_a": self._checkpoint(5, "ab" * 32, "cd" * 32),
                    "signature_a": "0x" + "11" * 65,
                    "checkpoint_b": self._checkpoint(5, "ef" * 32, "01" * 32),
                    "signature_b": "0x" + "22" * 65,
                }
            )
        )
        code = main(
            [
                "bond", "prove", str(proof_path), "--bond", BOND_ADDR,
                "--rpc", "http://only-one",
            ]
        )
        err = capsys.readouterr().err
        assert code == 1
        assert "at least 2" in err

    def test_a_contract_rejection_on_send_is_a_labelled_error_not_a_crash(
        self, signer_cmd: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        import json

        proof_path = tmp_path / "proof.json"
        proof_path.write_text(
            json.dumps(
                {
                    "kind": "equivocation",
                    "chain_id": "t",
                    "checkpoint_a": self._checkpoint(5, "ab" * 32, "cd" * 32),
                    "signature_a": "0x" + "11" * 65,
                    "checkpoint_b": self._checkpoint(5, "ef" * 32, "01" * 32),
                    "signature_b": "0x" + "22" * 65,
                }
            )
        )
        url_a, server_a = start_fake_node(write_node(estimate_gas_answer=rpc_revert()))
        url_b, server_b = start_fake_node(write_node(estimate_gas_answer=rpc_revert()))
        try:
            code = main(
                [
                    "bond", "prove", str(proof_path), "--bond", BOND_ADDR,
                    "--rpc", url_a, "--rpc", url_b,
                ]
            )
        finally:
            server_a.shutdown()
            server_b.shutdown()
        err = capsys.readouterr().err
        assert code == 1
        assert "the contract rejected this call" in err


class TestEthChainIdErrors:
    """`_eth_chain_id` is called before every write (`_describe_write`), so
    its own error paths are reachable from any write command; `registry
    publish` exercises them here for all three."""

    def test_malformed_response_is_a_labelled_error(
        self, signer_cmd: str, capsys: pytest.CaptureFixture[str]
    ) -> None:
        url_a, server_a = start_fake_node(
            write_node(chain_id_answer={"jsonrpc": "2.0", "id": 1})
        )
        url_b, server_b = start_fake_node(
            write_node(chain_id_answer={"jsonrpc": "2.0", "id": 1})
        )
        try:
            code = main(
                [
                    "registry", "publish", "--descriptor-of", KNOWN_FINGERPRINT,
                    "--registry", REGISTRY_ADDR, "--rpc", url_a, "--rpc", url_b,
                ]
            )
        finally:
            server_a.shutdown()
            server_b.shutdown()
        err = capsys.readouterr().err
        assert code == 1
        assert "unexpected response" in err

    def test_non_hex_result_is_a_labelled_error(
        self, signer_cmd: str, capsys: pytest.CaptureFixture[str]
    ) -> None:
        url_a, server_a = start_fake_node(write_node(chain_id_answer=rpc_ok("not-hex")))
        url_b, server_b = start_fake_node(write_node(chain_id_answer=rpc_ok("not-hex")))
        try:
            code = main(
                [
                    "registry", "publish", "--descriptor-of", KNOWN_FINGERPRINT,
                    "--registry", REGISTRY_ADDR, "--rpc", url_a, "--rpc", url_b,
                ]
            )
        finally:
            server_a.shutdown()
            server_b.shutdown()
        err = capsys.readouterr().err
        assert code == 1
        assert "could not determine chain id before sending" in err


class TestSendFailuresAreLabelledNotCrashes:
    def test_registry_publish_contract_rejection(
        self, signer_cmd: str, capsys: pytest.CaptureFixture[str]
    ) -> None:
        url_a, server_a = start_fake_node(write_node(estimate_gas_answer=rpc_revert()))
        url_b, server_b = start_fake_node(write_node(estimate_gas_answer=rpc_revert()))
        try:
            code = main(
                [
                    "registry", "publish", "--descriptor-of", KNOWN_FINGERPRINT,
                    "--registry", REGISTRY_ADDR, "--rpc", url_a, "--rpc", url_b,
                ]
            )
        finally:
            server_a.shutdown()
            server_b.shutdown()
        err = capsys.readouterr().err
        assert code == 1
        assert "the contract rejected this call" in err

    def test_bond_deposit_contract_rejection(
        self, signer_cmd: str, capsys: pytest.CaptureFixture[str]
    ) -> None:
        url_a, server_a = start_fake_node(write_node(estimate_gas_answer=rpc_revert()))
        url_b, server_b = start_fake_node(write_node(estimate_gas_answer=rpc_revert()))
        try:
            code = main(
                [
                    "bond", "deposit", "--bond", BOND_ADDR, "--amount-wei", "1",
                    "--rpc", url_a, "--rpc", url_b,
                ]
            )
        finally:
            server_a.shutdown()
            server_b.shutdown()
        err = capsys.readouterr().err
        assert code == 1
        assert "the contract rejected this call" in err
