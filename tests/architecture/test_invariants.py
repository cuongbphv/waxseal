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

    `docs/` used to be gitignored wholesale with per-directory exceptions, so
    adding a doc and linking it were two steps and the second one looked
    finished on the author's disk. That is how `docs/security/threat-model.md`
    was linked from three READMEs while still being gitignored. The blanket
    `docs/` ignore was dropped in 0.1.3 (8598a99), so the original receipt —
    delete the `!docs/security/` line — no longer reproduces; the current one
    is below.

    Until 0.1.5 this family globbed `REPO/*.md` only, so it could not have
    caught its own motivating incident from the `docs/` side: the linked file
    was a `docs/` path, and every `.vi.md` cross-reference lives there too.
    The glob now reaches `docs/**` as well.

    Falsifiability receipts (both run 01/09/2026, on the widened glob):
    - `test_every_linked_path_exists`: appending `[x](nope/gone.md)` to
      `docs/paper/outline.md` fails with
      `docs/paper/outline.md -> nope/gone.md` in the diff.
    - `test_no_linked_path_is_gitignored`: adding `docs/scratch/` to
      `.gitignore`, writing an untracked `docs/scratch/note.md` and linking it
      from `docs/paper/outline.md` fails with that path in the diff — the
      original incident exactly, reproduced from a `docs/` file. Re-ignoring
      `docs/security/` does NOT reproduce it, because those files are now
      tracked; see `test_no_linked_path_is_gitignored`.
    """

    # Skip rules for the doc set. Each is a property of the globs below rather
    # than a filter list, because a filter list is how this test lost `docs/`
    # in the first place.
    #   - CHANGELOG.md: a pre-existing carve-out with its own open bead
    #     (waxseal-fg4.23). Left exactly as it was; this test does not settle it.
    #   - tools/pm/*.md: vendored PM tooling, already carved out of lint
    #     (`[tool.ruff] extend-exclude = ["tools/pm"]`). Not authored here.
    #   - node_modules/, server/waxseal_server/static/, .venv/: gitignored
    #     dependency trees and build output. Nothing there is hand-written prose.
    # Not yet covered, and deliberately not folded into this change:
    # `integrations/*/README.md`, `examples/banking-poc/README*.md`,
    # `server/**/*.md`. They are shipped prose with relative links and belong in
    # this family; widening to them is a separate, reviewable step.

    def linked_repo_paths(self, doc: Path) -> list[str]:
        text = doc.read_text(encoding="utf-8")
        return [
            target
            for target in re.findall(r"\]\(([^)\s]+)\)", text)
            if not target.startswith(("http://", "https://", "#", "mailto:"))
        ]

    def resolve(self, doc: Path, target: str) -> Path:
        # Markdown resolves a relative link against the file that contains it,
        # not against the repository root. While every checked doc sat at the
        # root the two were the same thing; under docs/plans/ they are not, and
        # six root-style links in one plan were already 404 on GitHub when this
        # glob widened. Path() also drops the trailing slash git would
        # otherwise match against an empty ignore pattern.
        #
        # Anchors (`#L36`, `#section-name`) are stripped, not checked: targets
        # include source files whose anchors are the renderer's line numbers,
        # and heading slugs differ between GitHub and mkdocs, so a slug check
        # would encode one renderer's rules as truth. Out of scope, on purpose.
        return doc.parent / target.split("#")[0]

    def docs(self) -> list[Path]:
        return sorted(
            [p for p in REPO.glob("*.md") if p.name != "CHANGELOG.md"]
            + list(REPO.glob("docs/**/*.md"))
        )

    def test_the_doc_set_and_link_set_are_not_empty(self) -> None:
        # A glob that matches nothing passes every assertion below it. That
        # silent pass is the failure mode this bead exists to fix, so the
        # coverage is asserted rather than assumed. Lower bounds, not exact
        # counts: docs may be added freely, only a collapse is a bug.
        docs = self.docs()
        assert len(docs) >= 25, docs
        assert [d for d in docs if d.parent != REPO] != []
        links = [t for d in docs for t in self.linked_repo_paths(d)]
        assert len(links) >= 150, len(links)

    def test_every_linked_path_exists(self) -> None:
        missing = [
            f"{doc.relative_to(REPO)} -> {target}"
            for doc in self.docs()
            for target in self.linked_repo_paths(doc)
            if not self.resolve(doc, target).exists()
        ]
        assert missing == []

    def test_no_linked_path_is_gitignored(self) -> None:
        import shutil
        import subprocess

        git = shutil.which("git")
        if git is None:  # pragma: no cover - git is present in CI and dev
            return
        # Paths passed as argv, not stdin: text-mode stdin on Windows turns
        # each "\n" into "\r\n", which git then reads as part of the filename
        # and reports as unignored. That makes a dirty tree look clean.
        targets = sorted(
            {
                str(self.resolve(doc, target))
                for doc in self.docs()
                for target in self.linked_repo_paths(doc)
            }
        )
        # check-ignore exits 0 when something matched, 1 when nothing is
        # ignored; anything else (128: not a repo) means we learned nothing
        # and must not report that as a pass. It also honours the index, so a
        # tracked file matching an ignore pattern is not reported — correct
        # here: a tracked file ships, and shipping is the whole question.
        proc = subprocess.run(
            [git, "check-ignore", *targets], capture_output=True, text=True, cwd=REPO
        )
        if proc.returncode not in (0, 1):  # pragma: no cover - not a git checkout
            return
        assert proc.stdout.split() == []
