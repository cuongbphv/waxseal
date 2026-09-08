"""Every text read or write of a repository file names its encoding.

The first Windows CI run of 0.1.6 failed five architecture tests with
`UnicodeDecodeError: 'charmap' codec can't decode byte 0x90`: the tests read
src/ with `Path.read_text()` and no encoding, Windows defaulted to cp1252, and
four domain modules had gained Vietnamese legal citations ("Điều", "NĐ-CP")
whose "Đ" is a byte cp1252 cannot decode. The same call on Linux and macOS
reads UTF-8 and passes, so the suite was green everywhere but the platform
whose default differs. `open()` in text mode is covered by ruff's PLW1514
(unspecified-encoding); ruff 0.16 does not extend that rule to pathlib, so
this test does, over every Python file this repository owns.
"""

from __future__ import annotations

import ast
from pathlib import Path

REPO = Path(__file__).parent.parent.parent
TREES = ("src/waxseal", "tests", "tools", "server/waxseal_server", "server/tests")
# tools/pm is vendored (see pyproject's ruff exclude); tests/vectors is frozen.
EXCLUDED = ("tools/pm", "tests/vectors")
METHODS = frozenset({"read_text", "write_text"})


def python_files() -> list[Path]:
    files: list[Path] = []
    for tree in TREES:
        for path in sorted((REPO / tree).rglob("*.py")):
            rel = path.relative_to(REPO).as_posix()
            if not rel.startswith(EXCLUDED):
                files.append(path)
    return files


def calls_without_encoding(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr not in METHODS:
            continue
        if any(kw.arg == "encoding" for kw in node.keywords):
            continue
        found.append(f"{path.relative_to(REPO).as_posix()}:{node.lineno}")
    return found


def test_every_read_text_and_write_text_names_its_encoding() -> None:
    offenders = [hit for path in python_files() for hit in calls_without_encoding(path)]
    assert offenders == [], "\n".join(offenders)


def test_the_scan_sees_the_trees_it_claims() -> None:
    seen = {p.relative_to(REPO).parts[0] for p in python_files()}
    assert {"src", "tests", "tools", "server"} <= seen
