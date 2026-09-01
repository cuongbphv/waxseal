"""Architecture test: the epistemic tag is controlled vocabulary, in one language.

`[Unverified]` / `[Inference]` / `[Speculation]` mark a claim the repository has
not verified. Rule 5 and the Ternary Evidence Principle both depend on such a
claim staying *findable*: an unverified claim that no one can grep for has been
silently promoted to a verified one, which is the collapse the whole codebase
exists to prevent.

Before waxseal-fg4.13 the repository disagreed with itself — two documents
translated the tag to `[Chưa xác minh]` while `docs/paper/conformance.vi.md` and
`docs/research/*.vi.md` kept it in English — so no single grep found every hedge
across both languages, and the thing you forget to search for is the thing you
never find. Owner decision, 01/09/2026: **English tags everywhere**, because the
tag is controlled vocabulary rather than prose. Only the bracketed token is
English; the basis after the dash stays in the document's own language, since a
label whose basis is lost is a weaker label.

This test is the ratchet on that decision.
"""

import re
import unicodedata
from pathlib import Path

REPO = Path(__file__).parent.parent.parent

# The sanctioned vocabulary. Sourced from the standing reporting directive, not
# from whatever the corpus happens to contain today — a set derived from the
# corpus would ratify a drifted corpus.
SANCTIONED_TAGS = ("Unverified", "Inference", "Speculation")

SANCTIONED_RE = re.compile(r"\[\s*(?:" + "|".join(SANCTIONED_TAGS) + r")\b")

# Every bracketed token, tag or not. The scan is over brackets rather than over
# raw prose so that "chưa xác minh" as an ordinary Vietnamese phrase — which is
# what the *basis* clause is written in, and must stay — is untouched. Only the
# label position is controlled.
BRACKETED_RE = re.compile(r"\[([^\]\n]{1,80})\]")

# Translated renderings of the three sanctioned tags, ASCII-folded. A blocklist
# cannot know a rendering nobody has written yet; its job is to stop the ones
# this repository actually produced from coming back. The positive half of the
# guarantee is the non-emptiness test below, which proves the scanner reads the
# corpus and that both languages are inside it.
TRANSLATED_TAGS = (
    "chua xac minh",
    "chua duoc xac minh",
    "chua kiem chung",
    "khong xac minh",
    "suy luan",
    "suy dien",
    "suy doan",
    "phong doan",
    "phan doan",
)


def fold(text: str) -> str:
    """Lowercase and strip Vietnamese diacritics, so one entry catches every
    way a writer (or an editor stripping accents) can spell the same word."""
    stripped = "".join(
        ch for ch in unicodedata.normalize("NFD", text) if not unicodedata.combining(ch)
    )
    return stripped.replace("đ", "d").replace("Đ", "D").lower()


# Named so the non-emptiness test can assert every tree still contributes: a
# total-only lower bound lets one glob silently stop matching while the others
# cover for it. That is the same failure this file guards against in prose.
DOC_GLOBS = (
    "*.md",
    "docs/**/*.md",
    "examples/**/*.md",
    "integrations/*/README*.md",
    "server/**/*.md",
    "tools/**/*.md",
)

# Not hand-written prose: gitignored dependency trees and build output.
NOT_PROSE_SEGMENTS = frozenset({"node_modules", ".venv", "static"})


def docs() -> list[Path]:
    return sorted(
        {
            path
            for pattern in DOC_GLOBS
            for path in REPO.glob(pattern)
            if NOT_PROSE_SEGMENTS.isdisjoint(path.parts)
        }
    )


def translated_tags_in(text: str) -> list[str]:
    return [
        match.group(0)
        for match in BRACKETED_RE.finditer(text)
        if any(phrase in fold(match.group(1)) for phrase in TRANSLATED_TAGS)
    ]


class TestEpistemicTagVocabulary:
    def test_no_document_translates_the_epistemic_tag(self) -> None:
        offenders = []
        for doc in docs():
            for lineno, line in enumerate(doc.read_text().splitlines(), start=1):
                offenders += [
                    f"{doc.relative_to(REPO)}:{lineno}: {tag}"
                    for tag in translated_tags_in(line)
                ]
        assert offenders == []

    def test_the_detector_fires_on_a_translated_tag(self) -> None:
        # A pattern that matches nothing passes the test above in silence. The
        # detector is therefore exercised against known-positive samples rather
        # than trusted, including the accent-stripped spelling.
        assert translated_tags_in("**`[Chưa xác minh]`** Bộ byte chính xác") == [
            "[Chưa xác minh]"
        ]
        assert translated_tags_in("[Chua xac minh] can cu: ...") == ["[Chua xac minh]"]
        assert translated_tags_in("[Suy luận — căn cứ: ngày tạo công khai]") != []
        # ...and does not fire on the sanctioned form, nor on a Vietnamese
        # *basis* clause, which stays Vietnamese by the same owner decision.
        assert translated_tags_in("[Unverified — chỉ dựa trên README]") == []
        assert translated_tags_in("Điều này chưa được xác minh đối chiếu.") == []

    def test_the_scanned_corpus_is_not_empty_and_spans_both_languages(self) -> None:
        # Lower bounds, not exact counts: documents may be added freely, only a
        # collapse of the scan is a bug.
        scanned = docs()
        assert len(scanned) >= 40, scanned
        chosen = set(scanned)
        for pattern in DOC_GLOBS:
            assert chosen.intersection(REPO.glob(pattern)) != set(), pattern

        tagged = {
            doc.relative_to(REPO): len(SANCTIONED_RE.findall(doc.read_text()))
            for doc in scanned
        }
        # The English half of the corpus carries hedges...
        assert sum(tagged.values()) >= 20, tagged
        # ...and so does the Vietnamese half, in English. Without this the file
        # would still pass if every `.vi.md` tag vanished instead of being
        # translated, which loses the claim just as thoroughly.
        # Lowered from 10 to 6 (01/09/2026, owner decision): docs/research/*.vi.md
        # (landscape.vi.md, hedera-lessons.vi.md) carried several of the
        # counted hedges and moved out of the published tree into the
        # gitignored .docs/ — a real shrink of the Vietnamese corpus, not a
        # translation regression. 8 remain at the time of this change; the
        # bound stays a genuine floor below that.
        vietnamese = sum(n for path, n in tagged.items() if path.name.endswith(".vi.md"))
        assert vietnamese >= 6, tagged
