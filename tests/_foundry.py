"""Where the Foundry tools are, asked ONCE for the whole suite.

Three files needed the answer and each computed its own. Two of them looked
in foundryup's install directory when `PATH` did not carry the tools;
`tests/domain/test_abi.py` asked `shutil.which` and stopped there. So on a
machine where `foundryup` had installed Foundry — which only writes the
binaries and appends a line to the shell profile — a pytest run started
anywhere that had not sourced that profile got both answers at once: the
on-chain end-to-end suites MEASURED against real anvil chains, and the
selector cross-check reported 5x UNMEASURED in the same run.

That skip was labelled, and its label was the reason nobody chased it: it
said "Install Foundry (foundryup) and re-run to measure", and Foundry was
installed. Rule 5 one level up from the code — "unmeasured" is an honest
verdict only when the thing deciding it is not itself the defect. Made a
single module, and pinned there by
`tests/architecture/test_invariants.py::TestFoundryIsResolvedInOnePlace`, so
the next file to need Foundry cannot invent a sixth answer.

Absence is still reported, never worked around: there is no bundled toolchain
and no download here. A machine without Foundry skips WITH A LABEL, exactly
as before.
"""

from __future__ import annotations

import os
import shutil
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Final

import pytest

#: All three, because the suites that need one generally shell out to another:
#: the end-to-end files deploy with `forge`, run nodes with `anvil` and read
#: state with `cast`. A directory holding two of them is not an install.
TOOLS: Final = ("anvil", "forge", "cast")


def _install_dir() -> Path:
    """foundryup's install directory. `FOUNDRY_DIR` is honoured because
    foundryup itself honours it, so a relocated install is a real install."""
    root = os.environ.get("FOUNDRY_DIR") or Path.home() / ".foundry"
    return Path(root) / "bin"


def _candidates() -> Iterator[Path]:
    for name in TOOLS:
        found = shutil.which(name)
        if found is not None:
            yield Path(found).parent
            break
    yield _install_dir()


def _bin_dir() -> str | None:
    for candidate in _candidates():
        if all((candidate / name).exists() for name in TOOLS):
            return str(candidate)
    return None


#: The one directory holding the toolchain, or None on a machine without it.
FOUNDRY_BIN: Final = _bin_dir()


def tool(name: str) -> str | None:
    """The absolute path to one Foundry tool, or None if Foundry is absent."""
    if name not in TOOLS:
        raise ValueError(f"not a Foundry tool this suite uses: {name!r}")
    if FOUNDRY_BIN is None:
        return None
    return str(Path(FOUNDRY_BIN) / name)


def env(base: Mapping[str, str] | None = None) -> dict[str, str]:
    """`os.environ` (or `base`) with the toolchain appended to `PATH`.

    Appended, not prepended: a Foundry the operator deliberately put earlier
    on `PATH` stays the one that runs.
    """
    merged = dict(os.environ if base is None else base)
    if FOUNDRY_BIN is not None:
        merged["PATH"] = f"{merged.get('PATH', '')}:{FOUNDRY_BIN}"
    return merged


def skip_without_foundry(reason: str) -> pytest.MarkDecorator:
    """A skipif carrying the CALLER's label.

    The reason stays with the suite that is not being run, because what goes
    unmeasured differs per file and a shared sentence would say less than
    each of them does.
    """
    return pytest.mark.skipif(FOUNDRY_BIN is None, reason=reason)
