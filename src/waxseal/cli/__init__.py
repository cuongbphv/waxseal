"""Compatibility surface for `from waxseal.cli import ...`.

The console script and zipapp still call `waxseal.cli:main`. This file
re-exports the names tests and tools already import; it does not grow new
behaviour.
"""

from __future__ import annotations

import sys

from waxseal.cli._main import (
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

# Bound on the package so tests/test_cli_audit.py can still
# monkeypatch.setattr("waxseal.cli.sys.stdout", ...).
__all__ = (
    "ExternalEvmSigner",
    "_anchor_sink",
    "_evm_signer",
    "_parse_declared_topology_spec",
    "_read_segment",
    "_receipt_verdict",
    "_report",
    "_split_signer_command",
    "_survive_a_narrow_console",
    "_tail",
    "_verify",
    "_verify_handoff",
    "main",
    "sys",
)
