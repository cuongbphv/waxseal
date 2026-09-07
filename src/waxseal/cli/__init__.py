"""Compatibility surface for `from waxseal.cli import ...`.

The console script and zipapp still call `waxseal.cli:main`. This file
re-exports the names tests and tools already import; it does not grow new
behaviour.
"""

from __future__ import annotations

import sys

from waxseal.cli._anchors import _receipt_verdict
from waxseal.cli._common import _survive_a_narrow_console
from waxseal.cli._main import main
from waxseal.cli.anchor import _anchor_sink
from waxseal.cli.inspect import _tail
from waxseal.cli.ledger import ExternalEvmSigner, _evm_signer, _split_signer_command
from waxseal.cli.pin import _parse_declared_topology_spec
from waxseal.cli.report import _report, _verify_handoff
from waxseal.cli.segments import _read_segment
from waxseal.cli.verify import _verify

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
