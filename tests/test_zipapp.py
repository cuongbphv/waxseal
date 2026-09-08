"""The single-file zipapp is exercised as an artifact, not as an import.

`tools/build_pyz.py` builds `dist/waxseal-<ver>.pyz` — the file an auditor
carries into an air-gapped review. So the check here runs the built file in a
SUBPROCESS and reads its exit code, because that is the whole interface
(docs/architecture/deployment.md §4, "Exit codes are the interface") and it is
the part an in-process import cannot see. The first build of that script proved
why: `zipapp.create_archive(main="waxseal.cli:main")` generates a `__main__`
that calls `main()` and throws away its return value, so a broken trail exited
0 from the .pyz while the console script exited 1. Every import-level assertion
about the CLI would have passed over it.

Cost: the build shells out to `uv build --wheel` and re-zips the result.
Measured at roughly one second on the development machine, most of it uv's
wheel build. That is cheap enough to run unconditionally, and it is deliberately
not behind a marker or an environment variable — a release artifact whose only
end-to-end check is opt-in is an artifact nobody checks. If it ever does get
slow, the honest move is to say so here and keep running it, not to skip it.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from waxseal import AuditLog

PT = "application/vnd.test.event+json"


REPO_ROOT = Path(__file__).resolve().parent.parent
BUILDER = REPO_ROOT / "tools" / "build_pyz.py"


@pytest.fixture(scope="module")
def pyz(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """The built artifact. Module-scoped: one build serves every case below.

    Run as a subprocess rather than imported, so the builder's own command
    line — the one the Makefile and release.yml invoke — is what gets
    exercised. An importable `build()` that works while `python3
    tools/build_pyz.py` does not would leave the release path unchecked.
    """
    out = tmp_path_factory.mktemp("pyz")
    proc = subprocess.run(
        [sys.executable, str(BUILDER), "--out-dir", str(out)],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    built = sorted(out.glob("waxseal-*.pyz"))
    assert len(built) == 1, f"expected one .pyz in {out}, got {built}"
    return built[0]


def _run(pyz: Path, *args: str) -> subprocess.CompletedProcess[str]:
    # sys.executable, not a bare `python3`: the interpreter running the tests
    # is the one known to exist here, and server/scripts/_lib.sh carries the
    # same note for the same reason.
    return subprocess.run(
        [sys.executable, str(pyz), *args],
        capture_output=True,
        text=True,
    )


def _make_trail(path: Path, n: int = 4) -> None:
    log = AuditLog.open(path)
    for i in range(n):
        log.append(payload={"i": i}, payload_type=PT)


def test_help_runs_from_the_single_file(pyz: Path) -> None:
    proc = _run(pyz, "--help")
    assert proc.returncode == 0, proc.stderr
    assert "verify" in proc.stdout


def test_an_intact_trail_exits_0(pyz: Path, tmp_path: Path) -> None:
    trail = tmp_path / "trail.jsonl"
    _make_trail(trail)
    proc = _run(pyz, "verify", str(trail))
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_a_broken_trail_exits_1(pyz: Path, tmp_path: Path) -> None:
    """The regression for zipapp's return-value-discarding `__main__`.

    Before `tools/build_pyz.py` wrote its own `__main__.py`, this trail — the
    same edit tests/test_cli_audit.py::break_row makes — came back 0.
    """
    trail = tmp_path / "trail.jsonl"
    _make_trail(trail)
    lines = trail.read_text(encoding="utf-8").splitlines()
    obj = json.loads(lines[1])
    obj["header"]["ts"] = "2027-01-01T00:00:00+00:00"
    lines[1] = json.dumps(obj)
    trail.write_text("\n".join(lines) + "\n", encoding="utf-8")

    proc = _run(pyz, "verify", str(trail))
    assert proc.returncode == 1, proc.stdout + proc.stderr


def test_a_missing_trail_exits_3(pyz: Path, tmp_path: Path) -> None:
    proc = _run(pyz, "verify", str(tmp_path / "nope.jsonl"))
    assert proc.returncode == 3, proc.stdout + proc.stderr


def test_an_unknown_fingerprint_exits_2_not_1(pyz: Path, tmp_path: Path) -> None:
    """Unverifiable, never tampered — the library's central promise, run from
    the artifact an auditor actually holds. Same mechanism as
    tests/test_cli_audit.py::make_unverifiable, on the LAST row so the chain
    stays linked."""
    from waxseal.domain.hashing import compute_entry_hash
    from waxseal.domain.header import EntryHeader

    trail = tmp_path / "trail.jsonl"
    _make_trail(trail)
    lines = trail.read_text(encoding="utf-8").splitlines()
    obj = json.loads(lines[-1])
    obj["header"]["hash_version"] = "e" * 64
    obj["entry_hash"] = compute_entry_hash(EntryHeader(**obj["header"]))
    lines[-1] = json.dumps(obj)
    trail.write_text("\n".join(lines) + "\n", encoding="utf-8")

    proc = _run(pyz, "verify", str(trail))
    assert proc.returncode == 2, proc.stdout + proc.stderr


def test_the_artifact_carries_no_dist_info(pyz: Path) -> None:
    """A zipapp has no package manager, so install metadata inside it would
    describe a distribution that is not installed."""
    import zipfile

    with zipfile.ZipFile(pyz) as zf:
        names = zf.namelist()
    assert any(n.startswith("waxseal/") for n in names)
    assert not [n for n in names if ".dist-info" in n]
