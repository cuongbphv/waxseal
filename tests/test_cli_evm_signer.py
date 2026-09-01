"""`ExternalEvmSigner` / `_evm_signer()` (F4): the WAXSEAL_EVM_SIGNER_CMD
credential boundary. No network and no real chain needed here — this is the
subprocess sub-protocol itself (`<cmd> address`, `<cmd> sign-digest 0x<hex>`,
`<cmd> sign-tx` with fields on stdin), exercised against a tiny fake signer
script this file writes. `tests/adapters/test_evm_anvil.py`'s `CastSigner`
plays the same role against a real `cast wallet`; this file is one layer
below that, proving the CLI's OWN plumbing (subprocess invocation, hex
decoding, non-zero exit handling) independent of any real signing tool.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from waxseal.cli import ExternalEvmSigner, _evm_signer
from waxseal.ports.ledger import LedgerError

ADDRESS = "0x" + "aa" * 20
SIGNATURE = "11" * 65


FAKE_SIGNER = f'''
import sys

def main():
    verb = sys.argv[1] if len(sys.argv) > 1 else ""
    if verb == "address":
        sys.stdout.write("{ADDRESS}")
    elif verb == "sign-digest":
        sys.stdout.write("0x{SIGNATURE}")
    elif verb == "sign-tx":
        body = sys.stdin.read()
        sys.stdout.write("0x" + format(len(body), "064x"))
    elif verb == "fail":
        sys.stderr.write("deliberate failure\\n")
        sys.exit(1)
    elif verb == "print-garbage":
        sys.stdout.write("not-hex-at-all")
    else:
        sys.exit(2)

main()
'''


@pytest.fixture
def signer_cmd(tmp_path: Path) -> str:
    script = tmp_path / "fake_signer.py"
    script.write_text(FAKE_SIGNER)
    return f"{sys.executable} {script}"


class TestEvmSignerMissing:
    def test_missing_env_var_raises_ledger_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("WAXSEAL_EVM_SIGNER_CMD", raising=False)
        with pytest.raises(LedgerError, match="WAXSEAL_EVM_SIGNER_CMD is not set"):
            _evm_signer()

    def test_empty_env_var_is_treated_as_missing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("WAXSEAL_EVM_SIGNER_CMD", "")
        with pytest.raises(LedgerError, match="WAXSEAL_EVM_SIGNER_CMD is not set"):
            _evm_signer()

    def test_env_var_present_builds_a_real_signer(
        self, monkeypatch: pytest.MonkeyPatch, signer_cmd: str
    ) -> None:
        monkeypatch.setenv("WAXSEAL_EVM_SIGNER_CMD", signer_cmd)
        signer = _evm_signer()
        assert signer.address == ADDRESS
        assert signer.public_id == ADDRESS


class TestExternalEvmSignerProtocol:
    def test_address_is_fetched_at_construction(self, signer_cmd: str) -> None:
        signer = ExternalEvmSigner(signer_cmd)
        assert signer.address == ADDRESS
        assert signer.public_id == ADDRESS

    def test_sign_digest_decodes_hex(self, signer_cmd: str) -> None:
        signer = ExternalEvmSigner(signer_cmd)
        assert signer.sign(b"\\x00" * 32) == bytes.fromhex(SIGNATURE)

    def test_sign_transaction_pipes_fields_as_json_on_stdin(self, signer_cmd: str) -> None:
        signer = ExternalEvmSigner(signer_cmd)
        fields = {"chainId": 31337, "nonce": 0, "to": "0x" + "00" * 20}
        result = signer.sign_transaction(fields)
        expected_len = len(json.dumps(fields))
        assert int.from_bytes(result, "big") == expected_len

    def test_nonexistent_command_raises_ledger_error(self) -> None:
        with pytest.raises(LedgerError, match="could not run"):
            ExternalEvmSigner("this-command-does-not-exist-anywhere-xyz")

    def test_a_verb_exiting_nonzero_raises_ledger_error_naming_stderr(
        self, signer_cmd: str
    ) -> None:
        signer = ExternalEvmSigner(signer_cmd)
        with pytest.raises(LedgerError, match="deliberate failure"):
            signer._run("fail")

    def test_non_hex_output_raises_ledger_error(self, signer_cmd: str) -> None:
        signer = ExternalEvmSigner(signer_cmd)
        with pytest.raises(LedgerError, match="not hex"):
            signer._run_hex("print-garbage")
