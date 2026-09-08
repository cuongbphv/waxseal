"""The scope statement: what waxseal's outputs do NOT claim.

An audit trail's output gets quoted. "waxseal says ok" travels into a ticket,
a control narrative, a regulator's evidence pack — and somewhere along that
path "the links hold" turns into "the obligation was met". No output of this
library asserts that an obligation was met, that payload content is truthful,
or that unrecorded events did not occur, and every verdict-bearing output now
says so in its own text rather than relying on a reader having read the docs.

The three non-assertions are asserted here individually: a future edit that
drops one of them (the payload-truth clause is the tempting one to trim) fails
a test rather than quietly narrowing what the document disclaims.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from waxseal import AuditLog, VerifyResult
from waxseal.cli import main
from waxseal.domain.report import SCOPE_ID, SCOPE_LINE, SCOPE_STATEMENT, build_report

PT = "application/vnd.test.event+json"


def make_trail(path: Path, n: int = 3) -> None:
    log = AuditLog.open(path)
    for i in range(n):
        log.append(payload={"i": i}, payload_type=PT)


def empty_result() -> VerifyResult:
    return VerifyResult(
        ok=True, checked=0, broken_seq=None, reason=None, unverifiable=(), dropped_writes=None
    )


class TestScopeText:
    def test_scope_id_is_stable(self) -> None:
        # The id is the machine handle auditors key off; the prose may be
        # clarified only under a NEW id (append-only discipline), so a changed
        # id here is a deliberate act, not a typo fix.
        assert SCOPE_ID == "waxseal-scope-v1"

    def test_states_the_three_non_assertions(self) -> None:
        text = SCOPE_STATEMENT.lower()
        assert "obligation" in text
        assert "truthful" in text or "truth" in text
        assert "unrecorded" in text

    def test_scopes_itself_to_recorded_entries(self) -> None:
        assert "recorded" in SCOPE_STATEMENT.lower()

    def test_the_text_under_this_id_is_frozen_byte_for_byte(self) -> None:
        # Keyword checks let the prose drift while the id stays put, which is
        # the one thing SPEC 16 forbids: a control narrative citing
        # "waxseal-scope-v1" must still be able to say what those words were.
        # Reword the statement and this fails — that failure means "issue a
        # new id", not "update the expected string".
        assert SCOPE_STATEMENT == (
            "This output attests hash-chain integrity and completeness measurements of "
            "RECORDED entries only. It does not attest that any obligation was met, that "
            "payload content is truthful, or that unrecorded events did not occur."
        )
        assert SCOPE_LINE == (
            "scope: attests chain integrity of RECORDED entries only — not that an "
            "obligation was met, not that payload content is truthful, not that "
            "unrecorded events did not occur"
        )

    def test_the_short_line_asserts_nothing_the_long_one_does_not(self) -> None:
        # Two wordings ship under one id. The abbreviation is allowed to say
        # less; it is not allowed to say anything more.
        for term in ("obligation", "truthful", "unrecorded", "recorded"):
            assert term in SCOPE_LINE.lower()


class TestReportRendering:
    def test_json_carries_scope_id_and_statement(self) -> None:
        obj = json.loads(build_report(empty_result(), []).to_json())
        assert obj["scope"] == {"id": SCOPE_ID, "statement": SCOPE_STATEMENT}

    def test_markdown_ends_with_a_scope_section(self) -> None:
        md = build_report(empty_result(), []).to_markdown()
        assert "## Scope" in md
        assert SCOPE_STATEMENT in md
        # Last section, so it never pushes the verdict down the page.
        assert md.index("## Scope") > md.index("## Chain integrity")


class TestUnverifiableCheckRendering:
    """A sidecar check can be unreadable-by-name too, not just a chain row.
    The report has to spell that as its own third state, or the reader gets
    either a false pass or a false alarm."""

    def test_markdown_says_unverifiable_and_not_tampering(self) -> None:
        from waxseal.domain.report import CheckSummary

        md = build_report(
            empty_result(),
            [],
            pin=CheckSummary(ok=True, checked=0, reason="pin_version_unknown", unverifiable=True),
        ).to_markdown()
        assert "unverifiable" in md
        assert "NOT evidence of tampering" in md


class TestVerifyOutput:
    def test_printed_on_an_intact_trail(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = tmp_path / "trail.jsonl"
        make_trail(path)
        assert main(["verify", str(path)]) == 0
        assert "scope:" in capsys.readouterr().out

    def test_printed_on_a_broken_trail(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # The verdict most likely to be quoted out of context is the alarming
        # one, so the caveat has to travel with it too.
        path = tmp_path / "trail.jsonl"
        make_trail(path, 3)
        lines = path.read_text(encoding="utf-8").splitlines()
        obj = json.loads(lines[1])
        obj["header"]["ts"] = "2027-01-01T00:00:00+00:00"
        lines[1] = json.dumps(obj)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        assert main(["verify", str(path)]) == 1
        assert "scope:" in capsys.readouterr().out

    def test_printed_on_an_unverifiable_trail(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from waxseal.domain.hashing import compute_entry_hash
        from waxseal.domain.header import EntryHeader

        path = tmp_path / "trail.jsonl"
        make_trail(path, 2)
        lines = path.read_text(encoding="utf-8").splitlines()
        obj = json.loads(lines[1])
        obj["header"]["hash_version"] = "e" * 64
        obj["entry_hash"] = compute_entry_hash(EntryHeader(**obj["header"]))
        lines[1] = json.dumps(obj)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        assert main(["verify", str(path)]) == 2
        assert "scope:" in capsys.readouterr().out

    def test_does_not_change_the_exit_code(self, tmp_path: Path) -> None:
        path = tmp_path / "trail.jsonl"
        make_trail(path)
        assert main(["verify", str(path)]) == 0


class TestDataCommandsStaySilent:
    """`tail`/`inspect`/`head`/`checkpoint` print data, not verdicts. A scope
    caveat on machine-readable output is noise at best and a parse break at
    worst — `head` and `checkpoint` emit a single JSON object by contract."""

    @pytest.mark.parametrize("command", ["tail", "inspect", "head", "checkpoint"])
    def test_no_scope_line(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str], command: str
    ) -> None:
        path = tmp_path / "trail.jsonl"
        make_trail(path)
        assert main([command, str(path)]) == 0
        assert "scope:" not in capsys.readouterr().out
