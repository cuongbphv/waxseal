"""Compatibility re-exports for the CLI package split (b6a)."""

from __future__ import annotations

import subprocess
import sys


def test_the_thirteen_imported_names_are_on_waxseal_cli() -> None:
    from waxseal.cli import (
        ExternalEvmSigner,
        _anchor_sink,
        _evm_signer,
        _parse_declared_topology_spec,
        _read_segment,
        _receipt_verdict,
        _report,
        _split_signer_command,
        _survive_a_narrow_console,
        _tail,
        _verify,
        _verify_handoff,
        main,
    )

    assert callable(main)
    assert callable(_survive_a_narrow_console)
    assert callable(_verify)
    assert callable(_parse_declared_topology_spec)
    assert callable(_verify_handoff)
    assert callable(_read_segment)
    assert callable(_anchor_sink)
    assert callable(_receipt_verdict)
    assert callable(_report)
    assert callable(_tail)
    assert callable(_evm_signer)
    assert callable(_split_signer_command)
    assert ExternalEvmSigner is not None


def test_sys_on_the_package_is_the_stdlib_module() -> None:
    # tests/test_cli_audit.py monkeypatches waxseal.cli.sys.stdout/stderr.
    import waxseal.cli as cli

    assert cli.sys is sys


def test_python_m_waxseal_cli_help_exits_0() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "waxseal.cli", "--help"],
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    assert proc.returncode == 0, proc.stderr
    assert "verify" in proc.stdout


def test_the_main_module_rebinds_main() -> None:
    import waxseal.cli.__main__ as cli_main
    from waxseal.cli import main

    assert cli_main.main is main
