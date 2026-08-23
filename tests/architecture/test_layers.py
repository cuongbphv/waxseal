"""Layering tests: the facade boundary and the import DAG, scanned as text.

Same style as test_invariants.py: these test the shape of the code, not its
behavior — the rules an agent (or a tired human) is most likely to erode
gradually. AuditLog.entries() exists precisely so nothing outside log.py holds
the backend (its docstring: a caller holding the backend directly would be
free to append behind the attestation and anchoring the facade owns). Three
sources modules had already bypassed it when this file was written, which is
why the scan exists.
"""

import re
from pathlib import Path

REPO = Path(__file__).parent.parent.parent
SRC = REPO / "src" / "waxseal"


def source_files() -> list[Path]:
    return sorted(SRC.rglob("*.py"))


class TestFacadeEncapsulation:
    def test_only_log_py_touches_the_backend_attribute(self) -> None:
        # The token, not the import: a bypass reads `log._backend.entries()`,
        # and no legitimate use of that attribute exists outside the facade
        # that defines it.
        offenders = [
            str(path.relative_to(REPO))
            for path in source_files()
            if "._backend" in path.read_text(encoding="utf-8") and path.name != "log.py"
        ]
        assert offenders == []


class TestLayerImports:
    def test_sources_and_integrations_never_import_the_cli(self) -> None:
        # CLAUDE.md layer DAG: cli.py is the outermost shell — "Nothing
        # imports cli." Sources and integrations sit below it; an import in
        # that direction would make the DAG a cycle.
        offenders = []
        pattern = re.compile(
            r"^\s*(?:from\s+waxseal\.cli\b|import\s+waxseal\.cli\b"
            r"|from\s+waxseal\s+import\s+(?:[\w\s,]*\bcli\b))",
            re.M,
        )
        for subpackage in ("sources", "integrations"):
            for path in sorted((SRC / subpackage).glob("*.py")):
                if pattern.search(path.read_text(encoding="utf-8")):
                    offenders.append(str(path.relative_to(REPO)))
        assert offenders == []
