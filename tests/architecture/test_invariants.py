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
            # 0.1.5's sealed segments, promoted by owner decision (01/09/2026)
            # once the shape had two real consumers: the hook integrations and
            # the chain server both already build on open_segmented, so the
            # "stays behind its module until something actually needs it here"
            # bar the decision-schema comment above sets is met. project_slug
            # and verify_segments are the read half: a third-party verifier
            # routing or checking a segment directory needs the same slug and
            # the same verdict arithmetic the writer used, not a re-derivation.
            # SegmentRead/SegmentState/SegmentsResult come along because a
            # verification primitive whose signature names non-public types is
            # not actually public. open_segmented is the one sources/ name
            # exported — the precedent that record_decision/record_file stay
            # unexported holds for *recorders of business events*; this is the
            # storage-lifecycle counterpart of AuditLog.open, not an ingester.
            "SegmentRead",
            "SegmentState",
            "SegmentsResult",
            "open_segmented",
            "project_slug",
            "verify_segments",
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


class TestCoverageFloorIsStatedOnce:
    """The coverage floor is a ratchet (CLAUDE.md), and it is written down in
    four places outside `pyproject.toml`. It was ratcheted 90 -> 100 on
    2026-08-23 and three of those copies were left saying 90, so a
    contributor reading CONTRIBUTING.md was told a gate that would fail them.
    A ratchet nobody can read the current notch of is not a ratchet.
    """

    #: Every file that quotes the floor to a human, and must therefore move
    #: with it. `CHANGELOG.md` is excluded on purpose: its "ratcheted from 90%
    #: to 100%" line is release history, and history is not a stale copy.
    QUOTING_THE_FLOOR = (
        "CONTRIBUTING.md",
        ".github/PULL_REQUEST_TEMPLATE.md",
        ".github/workflows/release.yml",
        "CLAUDE.md",
    )

    def test_every_documented_floor_matches_pyproject(self) -> None:
        config = tomllib.loads((REPO / "pyproject.toml").read_text())
        floor = str(config["tool"]["coverage"]["report"]["fail_under"])
        quoted = re.compile(r"(?i)coverage[^\n]*?(\d{2,3})\s*%")
        stale = []
        for name in self.QUOTING_THE_FLOOR:
            for number, line in (
                (match.group(1), match.string)
                for match in map(
                    quoted.search,
                    (REPO / name).read_text(encoding="utf-8").splitlines(),
                )
                if match is not None
            ):
                if number != floor:
                    stale.append(f"{name} says {number}%, pyproject says {floor}%: {line.strip()}")
        assert stale == []


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
    The glob reached `docs/**` in 065679d, and now reaches every remaining tree
    of shipped prose: `integrations/*/README*.md`, `examples/**`, `server/**`
    (waxseal-fg4.33) and `CHANGELOG.md` (waxseal-fg4.22). 32 files / 206 links
    before, 46 / 218 after; no pre-existing break was found in the new trees.

    Falsifiability receipts (all run 01/09/2026, on the widened glob):
    - `test_every_linked_path_exists`: appending `[x](nope/gone.md)` to
      `docs/paper/outline.md` fails with
      `docs/paper/outline.md -> nope/gone.md` in the diff.
    - `test_no_linked_path_is_gitignored`, untracked target: adding
      `docs/scratch/` to `.gitignore`, writing an untracked
      `docs/scratch/note.md` and linking it from `docs/paper/outline.md` fails
      with that path in the diff — the original incident exactly, reproduced
      from a `docs/` file.
    - `test_no_linked_path_is_gitignored`, TRACKED target (waxseal-fg4.34):
      appending `docs/research/landscape.md` to `.gitignore` — a file that is
      tracked and linked from `CHANGELOG.md`, `README.md`, `README.zh.md` and
      `docs/plans/waxseal-0.1.5-contract.md` — leaves the test GREEN while the
      subprocess omits `--no-index`, and turns it RED naming that path once
      `--no-index` is passed. Re-ignoring `docs/security/`, the original
      incident's own target, behaves the same way for the same reason: those
      files are tracked now. This receipt is the whole content of the switch;
      without it `--no-index` would be an unproven edit.
    - the widened trees: `[x](gone.md)` appended to
      `integrations/openclaw/README.md` fails naming that file, and again from
      `server/README.md` and `examples/banking-poc/README.md`.
    - `CHANGELOG.md`: rewriting its `docs/research/landscape.md` link to
      `docs/research/landscape-moved.md` fails naming `CHANGELOG.md`.
    """

    # Skip rules for the doc set. Each is a property of the globs below rather
    # than a filter list, because a filter list is how this test lost `docs/`
    # in the first place.
    #   - tools/pm/*.md and .claude/commands/*.md: vendored tooling installed by
    #     a skill and rewritten on every reinstall. tools/pm is already carved
    #     out of lint for that reason (`[tool.ruff] extend-exclude`); .claude/
    #     commands are the same property one directory over. Not authored here,
    #     so a link rotting in one is not this repo's to fix.
    #   - .github/**: issue and PR templates, consumed by GitHub's form
    #     renderer rather than read as documentation. Neither carries a
    #     relative link today, so covering them would assert nothing.
    #   - the NOT_PROSE_SEGMENTS trees below.
    #
    # CHANGELOG.md is NOT skipped (waxseal-fg4.22 settles the carve-out it
    # inherited). It is the root file most likely to accumulate links to docs
    # that later move — the `docs/security/` incident above is recorded in its
    # own 0.1.3 entry — and it was the only root `.md` nothing checked. All six
    # of its relative links resolve, so including it costs nothing today.
    # The argument for the old exclusion was that a released entry is history
    # and must not be edited when a path moves. That argument survives
    # inclusion: when this test goes red on CHANGELOG.md it is reporting that
    # a move orphaned a link recorded in the release history, and the fix is to
    # restore or redirect the target, never to rewrite the entry and never to
    # delete the link to go green. Reporting is the whole point (rule 4).

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

    # Named rather than inlined so the non-emptiness test can assert every
    # tree still contributes. A total-only lower bound cannot do that: a glob
    # that silently stops matching `server/**` hides behind the forty-odd files
    # the other trees supply, which is exactly how `docs/` went unchecked.
    DOC_GLOBS = (
        "*.md",
        "docs/**/*.md",
        "integrations/*/README*.md",
        "examples/**/*.md",
        "server/**/*.md",
    )

    # Path segments whose subtree is not hand-written prose: gitignored
    # dependency trees (node_modules, .venv) and build output
    # (server/waxseal_server/static, the compiled portal bundle). Matched as a
    # path segment, so a second copy of any of them — a node_modules under
    # server/web, say — is excluded by the same property rather than by a new
    # entry in a list someone has to remember to extend. `.pytest_cache` joined
    # the set 01/09/2026: pytest writes its own README there the first time it
    # runs under `server/`, and that real file inflates this corpus's count on
    # any machine that has run the server suite locally, while a fresh
    # checkout never sees it — excluding it makes the count deterministic
    # across environments instead of depending on local pytest history.
    NOT_PROSE_SEGMENTS = frozenset({"node_modules", ".venv", "static", ".pytest_cache"})

    def docs(self) -> list[Path]:
        return sorted(
            {
                path
                for pattern in self.DOC_GLOBS
                for path in REPO.glob(pattern)
                if self.NOT_PROSE_SEGMENTS.isdisjoint(path.parts)
            }
        )

    def test_the_doc_set_and_link_set_are_not_empty(self) -> None:
        # A glob that matches nothing passes every assertion below it. That
        # silent pass is the failure mode this bead exists to fix, so the
        # coverage is asserted rather than assumed. Lower bounds, not exact
        # counts: docs may be added freely, only a collapse is a bug.
        docs = self.docs()
        # Raised from 25/150 with the glob (waxseal-fg4.33): a bound left at
        # the old set's size stops protecting the trees that widened it.
        # Lowered from 40 to 35 (01/09/2026, owner decision): docs/plans/**
        # and docs/research/** (10 files) moved out of the published tree
        # entirely, into the gitignored .docs/ — a real, legitimate shrink
        # of the corpus, not a glob regression. 37 files remain scanned at
        # the time of this change; the bound stays a genuine floor below
        # that, not the exact count, per this test's own "lower bounds, not
        # exact counts" rule above.
        assert len(docs) >= 35, docs
        chosen = set(docs)
        for pattern in self.DOC_GLOBS:
            assert chosen.intersection(REPO.glob(pattern)) != set(), pattern
        links = [t for d in docs for t in self.linked_repo_paths(d)]
        assert len(links) >= 200, len(links)

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
        # and must not report that as a pass.
        #
        # --no-index because check-ignore otherwise honours the INDEX: a file
        # that is tracked stays "not ignored" however many patterns match it,
        # so a link to it passed. The owner settled that reading on 01/09/2026
        # (waxseal-fg4.34) against the recommendation on the bead — an ignore
        # pattern is intent to STOP shipping a file, so a link to one is a link
        # to something on its way out, whether or not git still holds it in the
        # index. Measured before the switch: 478 tracked files, none matched by
        # an ignore pattern, so the stricter reading orphaned no link and cost
        # nothing that day. It is future-proofing, and the receipt below is
        # what makes it more than a no-op edit.
        proc = subprocess.run(
            [git, "check-ignore", "--no-index", *targets],
            capture_output=True,
            text=True,
            cwd=REPO,
        )
        if proc.returncode not in (0, 1):  # pragma: no cover - not a git checkout
            return
        assert proc.stdout.split() == []


# CLAUDE.md's "Named principle" section carries its instance count in three
# hand-written places that must agree: the lead-in ("in (at least) N places"),
# the highest ordinal in the numbered list, and the closing challenge ("find a
# (N+1)-th place"). Spelled as English words, in prose, updated by hand.
#
# Written as a function over text rather than over the file, so the historical
# defect below can be replayed as a literal without any test mutating a frozen
# path. The numbers are PARSED, never hardcoded: a test that pins "nine" is the
# fourth copy of the number and the next thing to go stale.
_CARDINALS = {
    "one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7,
    "eight": 8, "nine": 9, "ten": 10, "eleven": 11, "twelve": 12,
    "thirteen": 13, "fourteen": 14, "fifteen": 15, "sixteen": 16,
    "seventeen": 17, "eighteen": 18, "nineteen": 19, "twenty": 20,
}
_ORDINALS = {
    "second": 2, "third": 3, "fourth": 4, "fifth": 5, "sixth": 6,
    "seventh": 7, "eighth": 8, "ninth": 9, "tenth": 10, "eleventh": 11,
    "twelfth": 12, "thirteenth": 13, "fourteenth": 14, "fifteenth": 15,
    "sixteenth": 16, "seventeenth": 17, "eighteenth": 18, "nineteenth": 19,
    "twentieth": 20, "twenty-first": 21,
}


def ternary_instance_counts(text: str) -> tuple[int, int, int]:
    """Return (lead-in, highest list ordinal, challenge) from CLAUDE.md's text.

    Raises rather than guessing if any of the three cannot be read: a section
    this test cannot parse is unmeasured, and returning a number for it would
    be the collapse the principle itself forbids (rule 5).
    """
    start = text.index("## Named principle")
    section = text[start : text.index("\n## ", start + 1)]

    lead_in = re.search(r"in \(at least\) ([a-z]+) places", section)
    challenge = re.search(r"find (?:a|an|the) ([a-z-]+) place", section)
    ordinals = [int(n) for n in re.findall(r"^(\d+)\. \*\*", section, re.M)]
    assert lead_in is not None, "no 'in (at least) N places' lead-in"
    assert challenge is not None, "no 'find a Nth place' challenge"
    assert ordinals != [], "no numbered instance list"
    assert lead_in[1] in _CARDINALS, lead_in[1]
    assert challenge[1] in _ORDINALS, challenge[1]
    return _CARDINALS[lead_in[1]], max(ordinals), _ORDINALS[challenge[1]]


class TestTernaryInstanceCount:
    # This is a test ABOUT a frozen path, not an edit to one: it reads
    # CLAUDE.md and never writes it.
    def test_claude_md_states_one_consistent_instance_count(self) -> None:
        lead_in, highest, challenge = ternary_instance_counts(
            (REPO / "CLAUDE.md").read_text(encoding="utf-8")
        )
        assert (lead_in, challenge) == (highest, highest + 1)

    # The defect is proven, not hypothetical. 841326f added instance 7 and
    # advanced the challenge to "an eighth" but left the lead-in reading "six"
    # over a seven-item list; it shipped that way and survived until d6c2170
    # overwrote the word as a side effect of an unrelated bead. The lead-in is
    # the part that rots, because it is the one the author is not editing.
    #
    # Reconstructed to that commit's exact shape (6 / 7 / 8) rather than pulled
    # from `git show`, so the receipt survives a shallow clone. The real
    # 841326f text was run through this parser while writing the test and
    # yields the same (6, 7, 8).
    HISTORICAL_841326F = (
        "## Named principle: the Ternary Evidence Principle\n\n"
        "This codebase already applies the principle, by name or not, "
        "in (at least) six places:\n\n"
        + "".join(f"{i}. **instance {i}**: prose.\n" for i in range(1, 8))
        + "\nRule 5 below is the SPECIFIC instance of this general principle. An "
        "implementer\nshould be able to find an eighth place it applies without "
        "being told.\n\n"
        "## Architecture (layer DAG)\n"
    )

    def test_the_shipped_841326f_inconsistency_is_caught(self) -> None:
        lead_in, highest, challenge = ternary_instance_counts(self.HISTORICAL_841326F)
        assert (lead_in, highest, challenge) == (6, 7, 8)
        # What the live test asserts, failing on the wording that shipped.
        assert (lead_in, challenge) != (highest, highest + 1)


class TestTestSuiteIsAPackage:
    def test_every_test_directory_holding_modules_is_a_package(self) -> None:
        # `tests/domain/` was reported as missing its `__init__.py`
        # (waxseal-fg4.25); it has carried one since 8aa2e23, and so does every
        # other directory here. Nothing was broken — which is the reason to
        # pin it. pytest's rootdir discovery collects a directory without an
        # `__init__.py` perfectly well, so the day one goes missing nothing
        # goes red; the cost lands later, on whoever adds a module whose
        # basename already exists elsewhere in the tree, as an import error
        # naming a file they never touched.
        tests_root = REPO / "tests"
        directories = [tests_root, *(d for d in tests_root.rglob("*") if d.is_dir())]
        missing = sorted(
            str(d.relative_to(REPO))
            for d in directories
            if list(d.glob("test_*.py")) and not (d / "__init__.py").exists()
        )
        assert missing == []


class TestFoundryIsResolvedInOnePlace:
    """One question — "is Foundry on this machine?" — had three answers.

    `tests/adapters/test_evm_anvil.py` and `tests/test_cli_ledger_e2e_anvil.py`
    both fell back to foundryup's own install directory under `$HOME` when
    `PATH` did not carry the tools;
    `tests/domain/test_abi.py` asked `shutil.which` for `cast` and nothing
    else.
    On a machine with Foundry installed by `foundryup` but not sourced into
    the shell — the default state of a fresh install — the first two MEASURED
    and the third reported 5x UNMEASURED. The skip was labelled and honest
    about itself, which is exactly why nobody chased it: the label said
    "install Foundry", and Foundry was installed.

    Rule 5's shape, one level up from the code: "unmeasured" is only an
    honest verdict when the thing that decides it is not itself the defect.
    """

    #: The one module allowed to answer it. Everything else imports from here.
    RESOLVER = "tests/_foundry.py"

    def test_no_test_module_resolves_the_foundry_tools_for_itself(self) -> None:
        # Assembled from parts so this file is not its own first offender:
        # the literals it searches for must not appear in it verbatim.
        tools = "|".join(("anvil", "forge", "cast"))
        home = "." + "foundry"
        pattern = re.compile(rf"""which\(\s*["']({tools})["']|{re.escape(home)}""")
        offenders = sorted(
            str(path.relative_to(REPO))
            for path in (REPO / "tests").rglob("*.py")
            if path.relative_to(REPO).as_posix() != self.RESOLVER
            and pattern.search(path.read_text(encoding="utf-8"))
        )
        assert offenders == []


class TestSelectorsAreFrozenInOnePlace:
    """Every four-byte function selector lives in `domain/abi.py` and nowhere
    else.

    Python cannot compute one (no keccak256 in the stdlib), so they are frozen
    constants, and `tests/domain/test_abi.py` cross-checks the whole table
    against `cast sig` AND against `forge inspect`'s own output. That
    cross-check iterates `abi.SELECTORS`. `adapters/evm.py` kept its OWN
    copies of five of them, dated from a period when the domain table
    described an earlier contract draft — and while the adapter's copies were
    cross-checked by a second, hand-maintained table in
    `tests/adapters/test_evm.py`, two hand-maintained tables of the same
    constants is the shape waxseal-fg4.40 already paid for once: six drifted
    and every gate stayed green.
    """

    def test_no_module_outside_domain_abi_freezes_a_selector(self) -> None:
        # `bytes.fromhex` is the tell: freezing four bytes nobody can
        # recompute here. An ALIAS of an already-frozen constant is not a
        # second source of truth, and `adapters/evm.py` keeps one
        # (`SELECTOR_SUBMIT_HEAD`) to say which `submit` it means.
        frozen = re.compile(
            r"^SELECTOR_\w+\s*:\s*Final\s*=\s*bytes\.fromhex", re.MULTILINE
        )
        offenders = sorted(
            str(path.relative_to(REPO))
            for path in source_files()
            if path != SRC / "domain" / "abi.py" and frozen.search(path.read_text())
        )
        assert offenders == []
