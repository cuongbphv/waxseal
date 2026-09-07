"""A wrapped line that begins with an HTML block tag silently ends the paragraph.

Found live in `CLAUDE.md` on 2026-09-07, present since well before that day and
mis-rendering the whole time. The CLI contract paragraph wrapped as:

    ... `receipt` is unchanged. `waxseal segments
    <dir>` takes the DIRECTORY holding a project's sealed segments, ...

`dir` is one of CommonMark's block tag names (the deprecated directory-list
element), so a line beginning `<dir>` starts an HTML block, and an HTML block
interrupts the paragraph above it. Three things then went wrong at once: the
paragraph ended early, the backtick before `waxseal segments` lost its partner
and rendered as a literal character, and every following line became raw HTML
inside a `<dir>` element, which browsers indent. Several screens of the
repository's own constitution rendered as an indented quotation of nothing.

Nothing failed. The full suite passed, the two documentation ratchets passed,
every link and anchor resolved. It was caught by a person looking at the
rendered page, which is the one reviewer this repository cannot schedule. Hence
this file: the fix is a line break, and a line break is exactly the kind of
thing a later reflow puts back.

Only line-INITIAL tags are reported, and only where the previous line is
non-blank. A deliberate HTML block after a blank line is legitimate markdown and
is left alone; so is `<td>` inside a fenced example, since a fence is not
prose.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# CommonMark 0.31 section 4.6, HTML blocks, condition 6. Copied from the spec
# rather than narrowed to the tags this repository happens to use today: the
# next one to bite will be whichever one somebody writes next.
BLOCK_TAGS = frozenset(
    """address article aside base basefont blockquote body caption center col
    colgroup dd details dialog dir div dl dt fieldset figcaption figure footer
    form frame frameset h1 h2 h3 h4 h5 h6 head header hr html iframe legend li
    link main menu menuitem nav noframes ol optgroup option p param section
    source summary table tbody td tfoot th thead title tr track ul""".split()
)

_OPENS_A_BLOCK = re.compile(
    r"^</?(" + "|".join(sorted(BLOCK_TAGS)) + r")(?=[\s/>])", re.IGNORECASE
)

_EXCLUDED_DIR_NAMES = frozenset({".venv", "node_modules", ".git", "build", "dist"})


def markdown_files() -> list[Path]:
    return sorted(
        p
        for p in REPO_ROOT.rglob("*.md")
        if _EXCLUDED_DIR_NAMES.isdisjoint(p.parts)
    )


def interrupted_paragraphs(text: str) -> list[int]:
    """1-based line numbers where an HTML block tag cuts a running paragraph.

    The HTML-block state has to be tracked, not just the previous line. A
    legitimate multi-line block opens after a blank line and runs until the next
    one, so every line inside it may begin with a tag and none of them
    interrupts anything. Only a tag that opens a block while a PARAGRAPH is
    still running is the defect. The first draft of this function checked the
    previous line alone and flagged `<tr>` on the second row of a hand-written
    table, which is how this paragraph came to be here.
    """
    offenders: list[int] = []
    in_fence = False
    in_html_block = False
    lines = text.split("\n")
    for index, line in enumerate(lines):
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        if not line.strip():
            in_html_block = False
            continue
        if not _OPENS_A_BLOCK.match(line):
            continue
        previous_is_blank = index == 0 or not lines[index - 1].strip()
        if previous_is_blank:
            in_html_block = True
        elif not in_html_block:
            offenders.append(index + 1)
    return offenders


def test_no_markdown_line_starts_an_html_block_mid_paragraph() -> None:
    offenders = [
        f"{path.relative_to(REPO_ROOT)}:{lineno}"
        for path in markdown_files()
        for lineno in interrupted_paragraphs(path.read_text(encoding="utf-8"))
    ]
    assert offenders == []


class TestFalsifiability:
    """The detector is exercised against known cases rather than trusted: a
    pattern that matches nothing passes the test above in silence."""

    def test_it_fires_on_the_shape_found_in_claude_md(self) -> None:
        # The real text, reconstructed, so the receipt survives a shallow clone.
        assert interrupted_paragraphs(
            "`receipt` is unchanged. `waxseal segments\n"
            "<dir>` takes the DIRECTORY holding a project's sealed segments\n"
        ) == [2]

    def test_a_deliberate_html_block_after_a_blank_line_is_allowed(self) -> None:
        assert interrupted_paragraphs("Some prose.\n\n<table>\n<tr><td>x</td></tr>\n</table>\n") == []

    def test_a_tag_inside_a_fence_is_not_prose(self) -> None:
        assert interrupted_paragraphs("Prose.\n```html\n<div>\n```\n") == []

    def test_a_non_block_tag_is_left_alone(self) -> None:
        # `<trail>`, `<path|url>`, `<target>` and friends are placeholders this
        # repository writes constantly; none of them is a block tag.
        assert interrupted_paragraphs("Run it as\n<trail>` and it reads only.\n") == []

    def test_a_closing_tag_counts_too(self) -> None:
        assert interrupted_paragraphs("Prose continues\n</div> and then more.\n") == [2]

    def test_the_corpus_is_not_empty(self) -> None:
        # A glob that stopped matching would make the test above vacuous.
        found = markdown_files()
        assert len(found) > 20
        assert REPO_ROOT / "CLAUDE.md" in found
