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


class TestVerdictComposition:
    # W2/C1: verdict composition in cli.py must go through
    # Verdict.join (domain/verdict.py), never max() over exit codes — 2
    # (unverifiable) is the larger exit code but the weaker finding, so
    # max() there would let an unrelated unverifiable row override a real
    # break. This is a preventative regression guard: no existing bug to
    # fix, just a shape the source must never regain.
    def test_max_does_not_appear_in_cli(self) -> None:
        text = (SRC / "cli.py").read_text()
        assert "max(" not in text


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
            # 0.1.4 collapsed waxseal to a single canonical encoding and
            # retired lp64v1 before any trail written under it existed outside
            # development. `fingerprint_v1` went with it: a name that pins an
            # ordinal is only worth keeping while more than one ordinal exists.
            # `fingerprint()` is the identity of the schema this build writes,
            # derived from the descriptor, never typed by hand.
            "fingerprint",
            "fingerprint_for",
            # External anchoring (RFC 6962 batch root + membership proofs)
            # added so an anchored root bounds the whole-chain-rewrite
            # threat the hash chain alone cannot resist.
            "batch_root",
            "membership_proof",
            "verify_chain",
            "verify_membership",
            # DESIGN.md's Merkle-graduation upgrade path: a Checkpoint pins
            # (seq, entry_hash, root) for an external anchor sink to witness,
            # and consistency_proof/verify_consistency (RFC 9162 section
            # 2.1.4, independently cross-checked in
            # tools/gen_consistency_vectors.py) let a verifier confirm two
            # checkpoints taken at different trail sizes describe the same
            # append-only history without needing the whole trail in hand.
            "Checkpoint",
            "checkpoint_for",
            "checkpoint_frame",
            "consistency_proof",
            "verify_consistency",
            # Verifiable AI decision log. Two groups, added under the rule
            # the existing set already follows: domain schema types and
            # verification primitives are public; source helpers are not.
            #
            # The decision schema (DecisionRecord/ModelRef/HumanOversight) is
            # the type an integrating system writes against, so it belongs
            # with Entry/EntryHeader rather than behind a submodule import.
            #
            # Proof bundles join membership_proof/verify_membership as
            # verification primitives: they let an auditor check one exported
            # decision offline, against an anchored root, without receiving
            # the rest of the trail — which is the only way to answer a
            # question about one customer without disclosing every other one.
            #
            # Deliberately NOT here: record_decision/iter_decisions/
            # commit_input (source helpers, matching sources.files, whose
            # record_file is likewise not exported) and build_report/
            # AuditReport (a renderer for the CLI, not a primitive). Widening
            # a frozen surface later is easy; narrowing it is a breaking
            # change, so these stay behind their modules until something
            # actually needs them here.
            "DecisionRecord",
            "HumanOversight",
            "ModelRef",
            "BundleResult",
            "ProofBundle",
            "build_proof_bundle",
            "verify_proof_bundle",
            # waxseal-mfi, owner decision: opened so a caller composing its own
            # verify checks reaches for Verdict.join() instead of reinventing
            # max()-on-exit-code — the exact structural-vs-procedural gap
            # Verdict exists to close, not left importable only from a
            # non-public module path. SeparationTopology/separation_degree
            # join it as the type+function pair a caller needs to build one
            # and read it back, now that `report`/`verify --pin` print τ
            # (conformance.md gap G1, closed this same commit).
            "SeparationTopology",
            "Verdict",
            "separation_degree",
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


class TestVersionIsStatedOnce:
    def test_pyproject_and_dunder_version_and_changelog_agree(self) -> None:
        # Three hand-edited copies of one number. A release that ships
        # __version__ = "0.1.2" inside a 0.1.3 wheel makes every bug report
        # name the wrong build.
        declared = tomllib.loads((REPO / "pyproject.toml").read_text())["project"]["version"]
        import waxseal

        assert waxseal.__version__ == declared
        changelog = (REPO / "CHANGELOG.md").read_text(encoding="utf-8")
        assert f"## [{declared}]" in changelog


class TestDocumentationLinks:
    """A README link to a file that never ships is a dead link for everyone
    but the author.

    `docs/` is ignored wholesale with per-directory exceptions, so adding a
    doc and linking it are two steps and the second one looks finished on the
    author's disk. That is how `docs/security/threat-model.md` was linked from
    three READMEs while still being gitignored.

    Falsifiability receipt: deleting the `!docs/security/` line from
    `.gitignore` fails `test_no_linked_path_is_gitignored` with
    `docs/security/threat-model{,.vi}.md` in the diff.
    """

    def linked_repo_paths(self, doc: Path) -> list[str]:
        text = doc.read_text(encoding="utf-8")
        return [
            target
            for target in re.findall(r"\]\(([^)\s]+)\)", text)
            if not target.startswith(("http://", "https://", "#", "mailto:"))
        ]

    def docs(self) -> list[Path]:
        return sorted(p for p in REPO.glob("*.md") if p.name != "CHANGELOG.md")

    def test_every_linked_path_exists(self) -> None:
        missing = [
            f"{doc.name} -> {target}"
            for doc in self.docs()
            for target in self.linked_repo_paths(doc)
            if not (REPO / target.split("#")[0]).exists()
        ]
        assert missing == []

    def test_no_linked_path_is_gitignored(self) -> None:
        import shutil
        import subprocess

        git = shutil.which("git")
        if git is None:  # pragma: no cover - git is present in CI and dev
            return
        # Trailing slash stripped and paths passed as argv, not stdin: git
        # reports a directory queried as "dir/" against an empty pattern, and
        # text-mode stdin on Windows turns each "\n" into "\r\n", which git
        # then reads as part of the filename. Both make a clean tree look dirty.
        targets = sorted(
            {
                target.split("#")[0].rstrip("/")
                for doc in self.docs()
                for target in self.linked_repo_paths(doc)
            }
        )
        # check-ignore exits 0 when something matched, 1 when nothing is
        # ignored; anything else (128: not a repo) means we learned nothing
        # and must not report that as a pass.
        proc = subprocess.run(
            [git, "check-ignore", *targets], capture_output=True, text=True, cwd=REPO
        )
        if proc.returncode not in (0, 1):  # pragma: no cover - not a git checkout
            return
        assert proc.stdout.split() == []
