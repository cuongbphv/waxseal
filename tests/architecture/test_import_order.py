"""Every module under src/waxseal imports cleanly when it is the FIRST waxseal
module a process loads.

The 0.1.6 split of domain/report.py into report.py + _report_render.py left a
cycle held together by a bottom-of-module import: report.py imported the
renderer at line ~489 and the renderer imported CheckSummary from report.py.
`import waxseal.domain._report_render` on its own raised ImportError
("partially initialized module") while every test still passed, because the
suite always imported report.py first. This test loads each module in a fresh
module table so the import order of the test suite cannot hide such a cycle.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).parent.parent.parent
SRC = REPO / "src" / "waxseal"

_PROBE = r"""
import importlib, sys
failures = []
for name in sys.argv[1:]:
    for key in [k for k in sys.modules if k == "waxseal" or k.startswith("waxseal.")]:
        del sys.modules[key]
    try:
        importlib.import_module(name)
    except ModuleNotFoundError as exc:
        # integrations/ may import a host SDK (CLAUDE.md carve-out); a missing
        # host SDK is not an import cycle. A missing waxseal module is.
        if exc.name is None or exc.name.split(".")[0] == "waxseal":
            failures.append(f"{name}: {type(exc).__name__}: {exc}")
    except Exception as exc:  # noqa: BLE001 - the name of the failure is the finding
        failures.append(f"{name}: {type(exc).__name__}: {exc}")
print("\n".join(failures))
"""


def module_names() -> list[str]:
    names = []
    for path in sorted(SRC.rglob("*.py")):
        rel = path.relative_to(SRC.parent).with_suffix("")
        parts = list(rel.parts)
        if parts[-1] == "__init__":
            parts = parts[:-1]
        if parts[-1] == "__main__":
            continue
        names.append(".".join(parts))
    return names


def test_every_module_imports_when_loaded_first() -> None:
    result = subprocess.run(
        [sys.executable, "-c", _PROBE, *module_names()],
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout.strip() == "", result.stdout
