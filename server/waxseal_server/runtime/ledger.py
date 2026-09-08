"""Assemble `waxseal ledger-status` argv from stored settings.

The HTTP handler still owns the JSON envelope (`configured` / `missing` /
`outcome`). This module is only the application-service question: given the
settings store, is there a command to run, and if so with which flags? A
caller cannot point this server's RPC client at a host of their choosing —
the endpoints come from the store, never from the request.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final

from waxseal_server.domain.settings import rpc_endpoints

_OPTIONAL_FLAGS: Final[tuple[tuple[str, str], ...]] = (
    ("ledger_registry_address", "--registry"),
    ("ledger_bond_address", "--bond"),
    ("ledger_writer_address", "--writer"),
    ("ledger_trail_id", "--trail-id"),
)


def ledger_status_argv(
    held: Mapping[str, str | None],
) -> tuple[str | None, list[str], list[str]]:
    """`(reason, missing, args)`.

    `reason` is None only when the command is ready to run. The two named
    refusals are states, never errors: nobody configured the liveness
    address, or `--bond` was stored without `--writer`.
    """
    liveness = held.get("ledger_liveness_address")
    if liveness is None:
        return "no_liveness_address", ["ledger_liveness_address"], []

    args: list[str] = []
    for endpoint in rpc_endpoints(held.get("ledger_rpc_urls")):
        args += ["--rpc", endpoint]
    args += ["--liveness", liveness]
    for key, flag in _OPTIONAL_FLAGS:
        value = held.get(key)
        if value is not None:
            args += [flag, value]

    # The command requires `--writer` with `--bond`. Refused here rather
    # than sent: argparse would answer with a usage error, which
    # `CliOutcome` correctly reports as `usage_error` — a server bug wearing
    # no verdict. Naming the missing setting instead is the useful answer.
    if "--bond" in args and "--writer" not in args:
        return "bond_without_writer", ["ledger_writer_address"], []
    return None, [], args
