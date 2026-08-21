"""Architecture tests: source-tree invariants from CLAUDE.md.

These test the shape of the code, not its behavior — the rules an agent (or a
tired human) is most likely to erode gradually.
"""

import re
import sys
import tomllib
from pathlib import Path

REPO = Path(__file__).parent.parent.parent
SRC = REPO / "src" / "waxseal"


def source_files() -> list[Path]:
    return sorted(SRC.rglob("*.py"))


class TestZeroDependencies:
    def test_pyproject_declares_no_runtime_dependencies(self) -> None:
        # CLAUDE.md rule 1: dependencies stays [].
        data = tomllib.loads((REPO / "pyproject.toml").read_text())
        assert data["project"]["dependencies"] == []

    # Sole carve-out from the stdlib-only import scan: integration modules
    # subclass their host's hook base classes, so the host import cannot be
    # deferred. The zero-dependency rule is untouched — these hosts never
    # appear in [project] dependencies, `import waxseal` never imports the
    # integrations subpackage (tests/integrations/test_package.py), and each
    # module is only ever imported inside the host's own environment, where
    # the host is present by definition.
    HOST_IMPORTS_ALLOWED_IN_INTEGRATIONS = {
        "langchain_core",  # waxseal/integrations/langchain.py
        "crewai",          # waxseal/integrations/crewai.py
        "agents",          # waxseal/integrations/openai_agents.py
        "hermes_cli",      # waxseal/integrations/hermes.py (lazy, in-function)
    }

    def test_src_imports_stdlib_and_waxseal_only(self) -> None:
        stdlib = set(sys.stdlib_module_names)
        offenders = []
        for path in source_files():
            in_integrations = (SRC / "integrations") in path.parents
            for match in re.finditer(
                r"^(?:from|import)\s+([A-Za-z_][A-Za-z0-9_]*)", path.read_text(), re.M
            ):
                root = match.group(1)
                if root in stdlib or root == "waxseal":
                    continue
                if in_integrations and root in self.HOST_IMPORTS_ALLOWED_IN_INTEGRATIONS:
                    continue
                offenders.append(f"{path.relative_to(REPO)}: {root}")
        assert offenders == []


class TestDomainPurity:
    def test_domain_never_touches_io_modules(self) -> None:
        # CLAUDE.md: domain/ is pure logic — no filesystem, no db, no locks.
        forbidden = {"os", "io", "sqlite3", "pathlib", "fcntl", "msvcrt", "socket"}
        offenders = []
        for path in sorted((SRC / "domain").glob("*.py")):
            for match in re.finditer(
                r"^(?:from|import)\s+([A-Za-z_][A-Za-z0-9_]*)", path.read_text(), re.M
            ):
                if match.group(1) in forbidden:
                    offenders.append(f"{path.name}: {match.group(1)}")
        assert offenders == []

    def test_domain_does_not_import_ports_or_adapters(self) -> None:
        offenders = []
        for path in sorted((SRC / "domain").glob("*.py")):
            text = path.read_text()
            if "waxseal.ports" in text or "waxseal.adapters" in text:
                offenders.append(path.name)
        assert offenders == []


class TestSingleOwner:
    def test_only_adapters_atomic_may_call_os_replace(self) -> None:
        offenders = [
            str(path.relative_to(REPO))
            for path in source_files()
            if "os.replace" in path.read_text() and path.name != "atomic.py"
        ]
        assert offenders == []


class TestPublicApiFrozen:
    def test_public_api_is_exactly_the_frozen_set(self) -> None:
        # Additions require updating this test in the same commit, with
        # rationale. Removals/renames are breaking changes.
        import waxseal

        assert set(waxseal.__all__) == {
            "GENESIS_PREV_HASH",
            "AuditLog",
            "Entry",
            "EntryHeader",
            "VerifyResult",
            "VersionRegistry",
            "fingerprint_for",
            "fingerprint_v1",
            # External anchoring (RFC 6962 batch root + membership proofs)
            # added so an anchored root bounds the whole-chain-rewrite
            # threat the hash chain alone cannot resist.
            "batch_root",
            "membership_proof",
            "verify_chain",
            "verify_membership",
        }


class TestNoInternalNames:
    def test_no_internal_project_or_company_names_in_repo_files(self) -> None:
        # The repo is public OSS; origins are referred to only as "a prior
        # production system". Banned tokens are assembled from codepoints so
        # this file itself stays grep-clean.
        banned = ["".join(map(chr, cs)) for cs in ([118, 101, 108, 111, 120],
                                                   [102, 112, 116],
                                                   [102, 105, 115])]
        checked = [
            *REPO.glob("*.md"),
            *REPO.glob("*.toml"),
            *(REPO / "src").rglob("*.py"),
            *(REPO / "tests").rglob("*.py"),
            *(REPO / "tools").rglob("*.py"),
        ]
        offenders = []
        for path in checked:
            text = path.read_text(encoding="utf-8").lower()
            for token in banned:
                if re.search(rf"(?<![a-z0-9]){token}(?![a-z0-9])", text):
                    offenders.append(f"{path.relative_to(REPO)}: {token!r}")
        assert offenders == []
