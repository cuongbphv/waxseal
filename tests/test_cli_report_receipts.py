"""`report` carries the receipts dimension too — waxseal-fg4.24.

`verify` has said something about the `.receipts` sidecar on every run since
J2. `report` said nothing at all: `_Check`/`CheckSummary` were shared, but
`AuditReport` had no field for receipts, so the artifact an auditor still has
six months later was the one surface where receipt coverage was invisible.
Reading it, you could not tell a trail whose every append was acknowledged
from one where acknowledgment was never measured.

The distinction this file holds is the one a shared renderer would have
collapsed. Both of these are `ok=True, checked=0`:

* no `.receipts` file at all -> **not recorded**: never measured;
* a `.receipts` file holding nothing -> **present, 0 records**: measured, and
  it covers no entry.

Neither may render as a flavour of "ok (0 checked)", and neither may render as
the other. Rule 5, one sidecar over from `dropped_writes`.

FALSIFIABILITY RECEIPT — measured 01/09/2026, baseline **14 tests, 0
failures** in this file (`uv run --extra dev pytest
tests/test_cli_report_receipts.py -q -p no:randomly`, counts read out of the
junit XML):

    1. `receipts=receipts` removed from `_report`'s `build_report(...)` call
       — i.e. `report` exactly as it shipped
         -> exit 1, tests=14 failures=9 (every state assertion, both
            renderings, and both verdict cases).
    2. `_receipts_text` replaced by the generic `_summary_text`
         -> exit 1, tests=14 failures=3:
            test_no_sidecar_reads_as_not_recorded_not_as_ok
            test_an_empty_sidecar_reads_as_present_and_empty
            test_the_markdown_never_calls_an_unmeasured_trail_ok
         NOT test_the_three_ok_states_render_differently, and that near-miss
         is worth recording: `_summary_text` does emit three DISTINCT strings
         ("ok (0 checked) — `no_receipts_recorded`", "ok (0 checked)", "ok (3
         checked)"), so distinctness alone is too weak a property. What it
         gets wrong is that two of the three open with "ok". The test that
         catches it is the one that refuses that word, not the one that
         counts strings.
    3. `receipts` dropped from `_report`'s exit-code loop (a report that
       PRINTS "RECEIPTS BROKEN" and exits 0)
         -> exit 1, tests=14 failures=2:
            test_a_broken_receipt_is_exit_1_in_report_as_well_as_verify
            test_an_unreadable_record_version_is_exit_2_never_exit_1
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.test_cli_receipt_sidecar import acknowledged_trail, rewrite_sidecar
from waxseal import AuditLog
from waxseal.adapters.receipts import receipts_path
from waxseal.cli import main
from waxseal.domain.report import (
    RECEIPTS_NOT_RECORDED_REASON,
    AuditReport,
    CheckSummary,
    build_report,
)
from waxseal.domain.verify import VerifyResult

PT = "application/vnd.test.event+json"


def plain_trail(tmp_path: Path) -> Path:
    path = tmp_path / "trail.jsonl"
    log = AuditLog.open(path)
    for i in range(2):
        log.append(payload={"i": i}, payload_type=PT)
    return path


def report_json(trail: Path, capsys: pytest.CaptureFixture[str]) -> dict[str, object]:
    code = main(["report", str(trail), "--json"])
    obj = json.loads(capsys.readouterr().out)
    assert isinstance(obj, dict)
    obj["__exit__"] = code
    return obj


def report_markdown(trail: Path, capsys: pytest.CaptureFixture[str]) -> tuple[int, str]:
    code = main(["report", str(trail)])
    return code, capsys.readouterr().out


def receipts_line(markdown: str) -> str:
    [line] = [ln for ln in markdown.splitlines() if ln.startswith("- Receipts:")]
    return line


class TestTheThreeOkStates:
    def test_no_sidecar_reads_as_not_recorded_not_as_ok(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        code, markdown = report_markdown(plain_trail(tmp_path), capsys)
        line = receipts_line(markdown)
        assert code == 0
        assert "**not recorded**" in line
        assert "never measured" in line
        assert "ok (" not in line

    def test_an_empty_sidecar_reads_as_present_and_empty(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        trail = plain_trail(tmp_path)
        receipts_path(trail).write_text("", encoding="utf-8")
        code, markdown = report_markdown(trail, capsys)
        line = receipts_line(markdown)
        assert code == 0
        assert "**0 record(s)**" in line
        assert "not the same as no sidecar at all" in line.lower()

    def test_an_acknowledged_trail_reads_as_checked(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        trail = acknowledged_trail(tmp_path)
        code, markdown = report_markdown(trail, capsys)
        line = receipts_line(markdown)
        assert code == 0
        assert "ok (3 checked)" in line
        # The caveat travels into the ARTIFACT, not only into the terminal:
        # the sidecar is as attacker-writable as the trail beside it.
        assert "attacker-writable" in markdown

    def test_the_three_ok_states_render_differently(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # The collapse this whole file exists to prevent, asserted head-on.
        absent = plain_trail(tmp_path / "a")
        _, absent_md = report_markdown(absent, capsys)

        empty = plain_trail(tmp_path / "b")
        receipts_path(empty).write_text("\n\n", encoding="utf-8")
        _, empty_md = report_markdown(empty, capsys)

        checked = acknowledged_trail(tmp_path / "c")
        _, checked_md = report_markdown(checked, capsys)

        lines = [receipts_line(md) for md in (absent_md, empty_md, checked_md)]
        assert len(set(lines)) == 3

    def test_the_markdown_never_calls_an_unmeasured_trail_ok(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _, markdown = report_markdown(plain_trail(tmp_path), capsys)
        assert "- Receipts: ok" not in markdown


class TestTheJsonStateIsNamed:
    def test_no_sidecar_is_state_not_recorded(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        obj = report_json(plain_trail(tmp_path), capsys)
        receipts = obj["receipts"]
        assert isinstance(receipts, dict)
        assert receipts["state"] == "not_recorded"
        assert receipts["reason"] == RECEIPTS_NOT_RECORDED_REASON
        assert receipts["checked"] == 0

    def test_an_empty_sidecar_is_state_present_empty(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        trail = plain_trail(tmp_path)
        receipts_path(trail).write_text("", encoding="utf-8")
        receipts = report_json(trail, capsys)["receipts"]
        assert isinstance(receipts, dict)
        # Same ok and same checked as the absent case: `state` is the only
        # field that keeps them apart for a machine consumer.
        assert (receipts["ok"], receipts["checked"]) == (True, 0)
        assert receipts["state"] == "present_empty"

    def test_an_acknowledged_trail_is_state_checked(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        receipts = report_json(acknowledged_trail(tmp_path), capsys)["receipts"]
        assert isinstance(receipts, dict)
        assert receipts["state"] == "checked"
        assert receipts["checked"] == 3


class TestTheVerdictTravelsToo:
    def test_a_broken_receipt_is_exit_1_in_report_as_well_as_verify(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        trail = acknowledged_trail(tmp_path)
        rewrite_sidecar(trail, lambda rs: rs[1].update(entry_hash="0" * 64))

        code, markdown = report_markdown(trail, capsys)

        assert "**BROKEN**" in receipts_line(markdown)
        assert "receipt_mismatch" in receipts_line(markdown)
        assert code == 1

    def test_an_unreadable_record_version_is_exit_2_never_exit_1(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # A record only a NEWER build understands: unverifiable by name, the
        # beads-v1.2.2 distinction, carried into the report's exit code.
        trail = acknowledged_trail(tmp_path)
        rewrite_sidecar(trail, lambda rs: rs[0].update(v=99))

        code, markdown = report_markdown(trail, capsys)

        line = receipts_line(markdown)
        assert "**unverifiable**" in line
        assert "NOT evidence of tampering" in line
        assert code == 2

    def test_a_clean_trail_with_receipts_still_exits_zero(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert report_markdown(acknowledged_trail(tmp_path), capsys)[0] == 0


class TestNobodyLooked:
    """The fourth state, reachable only from the library: a report built
    without a receipts check at all."""

    @staticmethod
    def bare() -> AuditReport:
        return build_report(
            VerifyResult(
                ok=True,
                checked=0,
                broken_seq=None,
                reason=None,
                unverifiable=(),
                dropped_writes=None,
            ),
            [],
        )

    def test_an_unsupplied_check_is_not_checked_never_a_pass(self) -> None:
        line = receipts_line(self.bare().to_markdown())
        assert "**not checked**" in line
        assert "absence of a check is not a pass" in line

    def test_the_json_names_that_state_too(self) -> None:
        receipts = json.loads(self.bare().to_json())["receipts"]
        assert receipts["state"] == "not_checked"
        assert "nobody looked" in receipts["note"]


def test_a_summary_with_notes_keeps_them_in_the_receipts_line() -> None:
    # `report` is where a caveat has to survive: a note only `verify` prints
    # is a note the auditor never sees.
    report = build_report(
        VerifyResult(
            ok=True,
            checked=1,
            broken_seq=None,
            reason=None,
            unverifiable=(),
            dropped_writes=None,
        ),
        [],
        receipts=CheckSummary(ok=True, checked=1, notes=("a caveat",)),
    )
    assert "note: a caveat" in report.to_markdown()
    assert json.loads(report.to_json())["receipts"]["notes"] == ["a caveat"]
