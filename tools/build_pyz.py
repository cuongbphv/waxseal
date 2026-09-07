#!/usr/bin/env python3
"""Build `dist/waxseal-<version>.pyz` — the whole verifier in one file.

This is possible only because `[project] dependencies` is `[]` (CLAUDE.md
rule 1). A zipapp carries no resolver and no install step: whatever is not in
the zip is not there at runtime. With one third-party import in the library the
artifact would either need those wheels vendored into it or would fail at the
first `import`, and the file would stop being a thing anyone could trust at a
glance.

What that buys is the reason the file exists. `waxseal-<version>.pyz` plus a
`python3` is a COMPLETE verifier: an auditor can carry it on a USB stick into
an air-gapped review room, point it at a trail, and get the same exit codes
(0 intact / 1 broken / 2 intact-but-unverifiable / 3 no such path) as a full
install, with nothing fetched and nothing installed. A verification tool that
can only run where a package index is reachable cannot be used in the room
where the evidence is.

Stdlib only, for the same reason: this script has to run in whatever
environment is building the release.

    python3 tools/build_pyz.py                  # -> dist/waxseal-<ver>.pyz
    python3 tools/build_pyz.py --out-dir /tmp/x

The contents come from the WHEEL, not from `src/` directly: the wheel is the
artifact the project already tests and publishes, so the zipapp holds exactly
what a `pip install waxseal` would put on disk and cannot drift from it by
picking up a file `[tool.hatch.build.targets.wheel]` would have left out.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
import zipapp
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

#: `waxseal = "waxseal.cli:main"` in pyproject's [project.scripts]. The zipapp
#: entry point is the same function the console script calls, so `python3
#: waxseal.pyz verify t.jsonl` and `waxseal verify t.jsonl` run the same code
#: and return the same exit code.
ENTRY_POINT = "waxseal.cli:main"

#: Written by hand instead of passing `main=` to `zipapp.create_archive`, and
#: the difference is the whole exit-code contract. zipapp's generated
#: `__main__` is `import waxseal.cli; waxseal.cli.main()` — it CALLS main and
#: DISCARDS what it returns, so the interpreter falls off the end and the
#: process exits 0. Measured on the first build of this script: a broken trail
#: and a missing path both came back 0 from the .pyz while the console script
#: returned 1 and 3. A verifier that reports "intact" for a chain it just
#: found broken is the one lie CLAUDE.md says a tamper-evidence mechanism must
#: never tell, and it would have been told by a helper flag nobody looks at.
#: tests/test_zipapp.py::test_a_broken_trail_exits_1 is the regression.
MAIN_PY = """import sys

from waxseal.cli import main

sys.exit(main())
"""

#: `/usr/bin/env python3` rather than a hard-coded interpreter path: the
#: artifact is meant to be copied onto a machine nobody configured for it.
INTERPRETER = "/usr/bin/env python3"


def _build_wheel(work: Path) -> Path:
    """Build the wheel into ``work`` and return its path."""
    for builder in (
        [sys.executable, "-m", "uv", "build", "--wheel", "--out-dir", str(work)],
        ["uv", "build", "--wheel", "--out-dir", str(work)],
        [sys.executable, "-m", "build", "--wheel", "--outdir", str(work)],
    ):
        if builder[0] != sys.executable and shutil.which(builder[0]) is None:
            continue
        proc = subprocess.run(builder, cwd=REPO_ROOT, capture_output=True, text=True)
        if proc.returncode == 0:
            break
    else:
        raise SystemExit(
            "no wheel builder available: install `uv` or `python -m build`"
        )
    wheels = sorted(work.glob("waxseal-*.whl"))
    if not wheels:
        raise SystemExit(f"the wheel build produced nothing in {work}")
    return wheels[-1]


def _version_of(wheel: Path) -> str:
    # waxseal-0.1.5-py3-none-any.whl -> 0.1.5. Read off the wheel rather than
    # importing the package or re-parsing pyproject: the wheel's own name is
    # what the release publishes under, and TestVersionIsStatedOnce exists
    # because a second place to state the version is a second place to get it
    # wrong.
    return wheel.name.split("-")[1]


def build(out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        wheel = _build_wheel(work / "wheel")
        staged = work / "app"
        staged.mkdir()
        with zipfile.ZipFile(wheel) as zf:
            zf.extractall(staged)
        # The wheel's .dist-info is install metadata for a package manager;
        # a zipapp has no package manager, and importlib.metadata cannot see
        # it inside the zip anyway. Dropping it keeps the artifact from
        # implying an installed distribution that is not there.
        for meta in staged.glob("*.dist-info"):
            shutil.rmtree(meta)
        (staged / "__main__.py").write_text(MAIN_PY, encoding="utf-8")
        target = out_dir / f"waxseal-{_version_of(wheel)}.pyz"
        zipapp.create_archive(
            staged,
            target=target,
            interpreter=INTERPRETER,
            compressed=True,
        )
    target.chmod(0o755)
    return target


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__ and __doc__.splitlines()[0])
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=REPO_ROOT / "dist",
        help="where to write the .pyz (default: ./dist)",
    )
    args = parser.parse_args(argv)
    target = build(args.out_dir)
    size_kb = target.stat().st_size // 1024
    print(f"{target} ({size_kb} KiB)")
    return 0


if __name__ == "__main__":  # pragma: no cover - script entry point
    raise SystemExit(main())
