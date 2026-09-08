"""Every text read or write of a repository file names its encoding.

The first Windows CI run of 0.1.6 failed five architecture tests with
`UnicodeDecodeError: 'charmap' codec can't decode byte 0x90`: the tests read
src/ with `Path.read_text()` and no encoding, Windows defaulted to cp1252, and
four domain modules had gained Vietnamese legal citations ("Điều", "NĐ-CP")
whose "Đ" is a byte cp1252 cannot decode. The same call on Linux and macOS
reads UTF-8 and passes, so the suite was green everywhere but the platform
whose default differs. `open()` in text mode is covered by ruff's PLW1514
(unspecified-encoding); ruff 0.16 does not extend that rule to pathlib, so
this test does, over every Python file this repository owns. subprocess in text
mode (`text=True`) decodes with the same platform default, so it is held to the
same rule.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

REPO = Path(__file__).parent.parent.parent
TREES = ("src/waxseal", "tests", "tools", "examples", "server/waxseal_server", "server/tests")
# tools/pm is vendored (see pyproject's ruff exclude); tests/vectors is frozen.
EXCLUDED = ("tools/pm", "tests/vectors")
METHODS = frozenset({"read_text", "write_text"})
MODE_RE = re.compile(r"[rwax][rwaxbt+]{0,3}")
SUBPROCESS = frozenset({"run", "check_output", "check_call", "call", "Popen"})
# `.open(...)` is checked too: text mode when the mode has no "b" (or is omitted).


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
        keywords = {kw.arg for kw in node.keywords}
        if node.func.attr in SUBPROCESS:
            text_mode = any(
                kw.arg in ("text", "universal_newlines")
                and isinstance(kw.value, ast.Constant)
                and kw.value.value is True
                for kw in node.keywords
            )
            if not text_mode:
                continue
        elif node.func.attr == "open":
            # Path.open with an explicit text mode (a mode string without "b").
            # ruff's PLW1514 covers the builtin open(), not the pathlib method.
            # A call with no mode is left alone: `AuditLog.open(url)` and
            # `Path.open()` are indistinguishable here, and only the latter is
            # a text read - a bare Path.open() is caught by the strict
            # EncodingWarning run the CHANGELOG describes, not by this scan.
            mode = node.args[0] if node.args else None
            if mode is None:
                mode = next((kw.value for kw in node.keywords if kw.arg == "mode"), None)
            if not (isinstance(mode, ast.Constant) and isinstance(mode.value, str)):
                continue
            # A mode string, not a path: AuditLog.open("https://...") has a
            # string first argument too, and it is not a file mode.
            if not MODE_RE.fullmatch(mode.value) or "b" in mode.value:
                continue
        elif node.func.attr not in METHODS:
            continue
        if "encoding" in keywords:
            continue
        found.append(f"{path.relative_to(REPO).as_posix()}:{node.lineno}")
    return found


def test_every_text_read_write_and_text_mode_subprocess_names_its_encoding() -> None:
    offenders = [hit for path in python_files() for hit in calls_without_encoding(path)]
    assert offenders == [], "\n".join(offenders)


def test_the_scan_sees_the_trees_it_claims() -> None:
    seen = {p.relative_to(REPO).parts[0] for p in python_files()}
    assert {"src", "tests", "tools", "examples", "server"} <= seen
