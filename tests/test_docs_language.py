"""Repo-wide invariant (waxseal-p8s / J4): no waxseal output or doc prints
"tamper-proof" without naming its scope in the same breath, per CLAUDE.md's
own line and DESIGN.md §11 — "the anchored prefix on a finalized external
ledger, WORM-archived segments — never the live tail, never write-time
honesty." Before this bead the rule was enforced by a manual repo-wide grep
at review time; this file turns that grep into a checked invariant so a
future doc edit or a new f-string in `adapters/s3.py`-shaped code cannot add
a bare, unscoped claim and drift past review unnoticed.

Scope of the check, and why it stops where it does: this walks waxseal's own
shipped ENGLISH surface — `src/**/*.py`, `examples/**/*.py`, and the
top-level and `docs/` Markdown files — and deliberately excludes one class
of file. A `*.xx.md` translation (`README.vi.md`, `threat-model.zh.md`, ...) is a
separate maintenance concern this bead does not own — keeping every
translation in lockstep with an English wording change is real work, and
claiming it here would be exactly the kind of asserted-but-not-verified
claim the reality-filter directive forbids. `tests/**` is excluded for the
mechanical reason that this file, and `test_cli_preflight.py`'s own
`test_a_bare_trail_...` assertion, reference the string "tamper-proof" to
test for its ABSENCE from real CLI output — that is not a claim needing a
scope, it is a test of one, and scanning it would make this file assert
against its own sibling. (Internal planning prose — the 0.1.5 contract and
its research/positioning notes — lives outside the published tree entirely,
by owner decision 01/09/2026, so there is no third class to carve out here
any more.)

The heuristic: a scope marker (DESIGN.md's own citation, the word "scope"/
"scoped", "tamper-evident" itself — the standard "X, not tamper-proof"
disclaiming pattern used throughout this codebase, a struck-through rejected
claim, or a "≠" clarification like "Tamper-proof ≠ truth-proof") within two
lines of the match. Two lines, not one: prose in this repository regularly
wraps a citation onto the following line (`adapters/s3.py`'s WORM-comment
block is the real example this margin was sized against), and a same-line-
only check would have to fail that comment to pass this test.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

_TRANSLATION_SUFFIX = re.compile(r"\.[a-z]{2}\.md$")

_EXCLUDED_DIR_NAMES = frozenset({".venv", "node_modules", ".git", "tests"})

_SCOPE_MARKERS = (
    "tamper-evident",  # the "X is tamper-evident, not tamper-proof" pattern
    "design.md §11",
    "design.md section 11",
    "scope",  # covers "scope", "scoped", "SCOPED", "in scope"
    "section 1",
    "≠",  # "≠", e.g. "Tamper-proof ≠ truth-proof"
    "~~",  # a struck-through, explicitly rejected claim
)


def _is_excluded(rel: tuple[str, ...]) -> bool:
    return any(part in _EXCLUDED_DIR_NAMES for part in rel)


def candidate_files() -> list[Path]:
    """waxseal's own shipped English *.py and *.md surface — see the module
    docstring for exactly which class of file is excluded and why.

    "Top-level and `docs/` Markdown files" (the module docstring's own words)
    is a claim about WHICH directories, not just which suffix: gating on
    ``rel[0]`` below is what keeps this out of gitignored, untracked, purely
    local scratch directories like ``.docs/`` (a real dot-prefixed directory
    found live in this repo, 01/09/2026 — a suffix-only check does not
    distinguish it from the tracked ``docs/`` this test means to cover, and
    a personal research note quoting someone else's GitHub issue title is
    not a waxseal claim needing a scope marker at all).
    """
    files: list[Path] = []
    for path in REPO_ROOT.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(REPO_ROOT).parts
        if _is_excluded(rel):
            continue
        is_shipped_py = path.suffix == ".py" and rel[0] in ("src", "examples")
        # `deploy/` joined the scan when that tree landed (0.1.6). It is prose
        # an operator reads before standing anything up, and prose about what a
        # deployment does and does not prove is exactly where an unscoped claim
        # would do the most damage.
        is_top_level_or_docs = len(rel) == 1 or rel[0] in ("docs", "deploy")
        is_english_md = (
            path.suffix == ".md"
            and is_top_level_or_docs
            and not _TRANSLATION_SUFFIX.search(path.name)
        )
        if is_shipped_py or is_english_md:
            files.append(path)
    return files


def _normalize(text: str) -> str:
    return text.lower().replace("*", "").replace("`", "")


def is_scoped(window: str) -> bool:
    """Does this window of lines name the claim's scope, per the module
    docstring's heuristic? Exposed at module level so the falsifiability
    tests below can drive it directly, not only through a full repo scan."""
    normalized = _normalize(window)
    return any(marker in normalized for marker in _SCOPE_MARKERS)


def _window(lines: list[str], index: int, radius: int = 2) -> str:
    return "\n".join(lines[max(0, index - radius) : index + radius + 1])


def test_no_unscoped_tamper_proof_claim_in_shipped_output_or_docs() -> None:
    failures: list[str] = []
    for path in candidate_files():
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:  # pragma: no cover - no binary files in scope
            continue
        lines = text.splitlines()
        for i, line in enumerate(lines):
            if "tamper-proof" not in line.lower():
                continue
            if not is_scoped(_window(lines, i)):
                rel = path.relative_to(REPO_ROOT)
                failures.append(f"{rel}:{i + 1}: {line.strip()}")
    assert not failures, (
        "bare 'tamper-proof' claim with no scope marker within two lines "
        "(CLAUDE.md / DESIGN.md §11 — every proof-like guarantee names its "
        "scope):\n" + "\n".join(failures)
    )


class TestFalsifiability:
    """The check above is not a tautology: it fires on a bare claim and
    passes a properly scoped one, checked directly against `is_scoped`
    rather than by planting a file in the real tree this test would then
    have to scan itself."""

    def test_a_bare_unscoped_claim_is_not_scoped(self) -> None:
        assert not is_scoped("This library is tamper-proof.")

    def test_the_disclaiming_pattern_used_throughout_this_repo_is_scoped(self) -> None:
        assert is_scoped("waxseal is tamper-evident, not tamper-proof.")

    def test_a_design_md_citation_is_scoped(self) -> None:
        assert is_scoped(
            "the anchored prefix on a finalized external ledger is the "
            "scoped half of the tamper-proof claim (DESIGN.md §11)"
        )

    def test_an_inequality_clarification_is_scoped(self) -> None:
        assert is_scoped("Tamper-proof ≠ truth-proof.")

    def test_a_struck_through_rejected_claim_is_scoped(self) -> None:
        assert is_scoped('~~"The log is tamper-proof."~~ Section 1.')

    def test_a_citation_wrapped_onto_the_next_line_is_scoped_by_the_window(
        self,
    ) -> None:
        lines = [
            "# Every line names its own SCOPE, because DESIGN.md §11 forbids printing a",
            "# tamper-proof claim without saying what it covers -- and the strength axis",
        ]
        assert is_scoped(_window(lines, 1))


class TestFileSelection:
    """`candidate_files` excludes exactly the one class the module
    docstring names, and nothing else in the repo's real *.py/*.md surface —
    checked against the actual tree, since a hand-picked fixture tree could
    pass while the real exclusion glob (a suffix regex anchored wrong) does
    not."""

    def test_it_excludes_translations(self) -> None:
        found = candidate_files()
        assert not any(_TRANSLATION_SUFFIX.search(p.name) for p in found)
        assert (REPO_ROOT / "docs" / "security" / "threat-model.vi.md").is_file()

    def test_it_excludes_the_tests_tree_itself(self) -> None:
        found = candidate_files()
        assert not any(p.relative_to(REPO_ROOT).parts[0] == "tests" for p in found)

    def test_it_includes_the_file_this_bead_edited(self) -> None:
        found = candidate_files()
        assert REPO_ROOT / "docs" / "security" / "threat-model.md" in found
        assert REPO_ROOT / "src" / "waxseal" / "cli" / "__init__.py" in found

    def test_it_includes_the_deploy_tree_and_still_excludes_its_translation(
        self,
    ) -> None:
        # The deploy tree is prose an operator reads before standing anything
        # up. It was outside every glob until 0.1.6, which meant a claim about
        # what a topology proves could sit there unscoped indefinitely.
        found = candidate_files()
        assert REPO_ROOT / "deploy" / "README.md" in found
        assert REPO_ROOT / "deploy" / "systemd" / "README.md" in found
        assert (REPO_ROOT / "deploy" / "README.vi.md").is_file()
        assert REPO_ROOT / "deploy" / "README.vi.md" not in found
