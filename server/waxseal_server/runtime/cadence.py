"""Assemble `waxseal cadence` argv from operator-supplied measurements.

The one read that opens no trail: every input is a measurement, so a server
holding no chains at all can still answer it. Validation stays
`require_measurement` — this module does not invent defaults.
"""

from __future__ import annotations

from waxseal_server.domain.identifiers import require_measurement


def cadence_argv(supplied: dict[str, str]) -> list[str]:
    """`--flag value` pairs, in the order the handler supplied the flags.

    Raises `InvalidIdentifier` on the first value that is not a measurement,
    so each failure keeps the label of the field that failed.
    """
    args: list[str] = []
    for flag, value in supplied.items():
        args += [f"--{flag}", require_measurement(value, flag)]
    return args
