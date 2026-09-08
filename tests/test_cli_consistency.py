"""CLI: `waxseal consistency` — does the current head extend an earlier state?

Wires domain/anchoring.py's RFC 9162 section 2.1.4 consistency proofs (until
now, zero consumers in src/) into a read-only subcommand. The operator's
workflow is the split-view check: record `waxseal checkpoint` output somewhere
the trail's writer cannot reach, and later ask whether today's trail still
extends it. A failure is EVIDENCE of a split view or rewritten history —
which row is honest is an operator's decision (CLAUDE.md rule 4: verify
reports, never repairs).

Exit codes: 0 = consistent, 1 = INCONSISTENT (checked and false),
2 = unverifiable (inputs this run cannot check — never spelled "tampered"),
3 = trail missing.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from waxseal import AuditLog
from waxseal.cli import main

PT = "application/vnd.test.event+json"


def trail_of(tmp_path: Path, n: int) -> Path:
    path = tmp_path / "trail.jsonl"
    log = AuditLog.open(path)
    for i in range(n):
        log.append(payload={"i": i}, payload_type=PT)
    return path


def checkpoint_output(path: Path, capsys: pytest.CaptureFixture[str]) -> dict[str, object]:
    # The command's inputs are exactly what `waxseal checkpoint` printed —
    # the round-trip is the contract, not an implementation detail.
    assert main(["checkpoint", str(path)]) == 0
    result: dict[str, object] = json.loads(capsys.readouterr().out)
    return result


class TestConsistent:
    def test_a_grown_trail_extends_its_recorded_checkpoint(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = trail_of(tmp_path, 3)
        old = checkpoint_output(path, capsys)
        log = AuditLog.open(path)
        for i in range(4):
            log.append(payload={"more": i}, payload_type=PT)

        code = main(
            [
                "consistency",
                str(path),
                "--old-seq",
                str(old["seq"]),
                "--old-root",
                str(old["root"]),
            ]
        )
        assert code == 0
        assert "consistent" in capsys.readouterr().out

    def test_the_unchanged_head_is_consistent_with_itself(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = trail_of(tmp_path, 2)
        old = checkpoint_output(path, capsys)
        assert (
            main(
                [
                    "consistency",
                    str(path),
                    "--old-seq",
                    str(old["seq"]),
                    "--old-root",
                    str(old["root"]),
                ]
            )
            == 0
        )


class TestInconsistent:
    def test_a_root_the_trail_cannot_reproduce_is_exit_1_with_evidence(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = trail_of(tmp_path, 3)
        assert main(["consistency", str(path), "--old-seq", "1", "--old-root", "a" * 64]) == 1
        out = capsys.readouterr().out
        assert "INCONSISTENT" in out
        # Evidence, not a verdict: the line names WHAT diverged (the root the
        # current prefix actually produces) and says split-view/rewrite is
        # what this is evidence OF — never "tampered" as a pronouncement.
        assert "evidence" in out
        assert ("a" * 64)[:12] in out

    def test_a_rewritten_early_entry_no_longer_extends_the_old_head(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = trail_of(tmp_path, 3)
        old = checkpoint_output(path, capsys)
        lines = path.read_text(encoding="utf-8").splitlines()
        first = json.loads(lines[0])
        first["entry_hash"] = "f" * 64
        path.write_text("\n".join([json.dumps(first), *lines[1:]]) + "\n", encoding="utf-8")

        assert (
            main(
                [
                    "consistency",
                    str(path),
                    "--old-seq",
                    str(old["seq"]),
                    "--old-root",
                    str(old["root"]),
                ]
            )
            == 1
        )


class TestUnverifiable:
    def test_an_old_seq_beyond_the_current_head_is_exit_2_not_1(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # A trail shorter than the recorded state COULD be a truncation — but
        # from here it is indistinguishable from a mistyped --old-seq, and a
        # proof over entries that are not there cannot be computed. Reported
        # as unverifiable, with the ambiguity stated, never as "tampered".
        path = trail_of(tmp_path, 2)
        assert main(["consistency", str(path), "--old-seq", "9", "--old-root", "a" * 64]) == 2
        out = capsys.readouterr().out
        assert "cannot" in out
        assert "truncat" in out  # the honest half of the ambiguity is stated

    def test_a_negative_old_seq_is_exit_2(self, tmp_path: Path) -> None:
        path = trail_of(tmp_path, 2)
        assert main(["consistency", str(path), "--old-seq", "-1", "--old-root", "a" * 64]) == 2

    def test_a_non_hex_root_is_exit_2_not_inconsistent(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # verify_consistency would just return False on bad hex — reporting
        # that as INCONSISTENT would turn an operator's typo into split-view
        # evidence, so malformed input is screened out first.
        path = trail_of(tmp_path, 2)
        assert main(["consistency", str(path), "--old-seq", "0", "--old-root", "z" * 64]) == 2
        assert "INCONSISTENT" not in capsys.readouterr().out

    def test_a_wrong_length_root_is_exit_2(self, tmp_path: Path) -> None:
        path = trail_of(tmp_path, 2)
        assert main(["consistency", str(path), "--old-seq", "0", "--old-root", "abcd"]) == 2

    def test_a_root_with_whitespace_is_exit_2(self, tmp_path: Path) -> None:
        # bytes.fromhex tolerates spaces, so a 64-char "root" with one inside
        # would otherwise slip past both the length check and the decode.
        path = trail_of(tmp_path, 2)
        spaced = "a" * 32 + " " + "a" * 31
        assert main(["consistency", str(path), "--old-seq", "0", "--old-root", spaced]) == 2

    def test_an_empty_but_existing_trail_is_exit_2(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # No entries means no tree, so no state can be extended — but an
        # empty file is not a missing trail (that is exit 3).
        path = tmp_path / "trail.jsonl"
        path.write_text("", encoding="utf-8")
        assert main(["consistency", str(path), "--old-seq", "0", "--old-root", "a" * 64]) == 2
        assert "empty trail" in capsys.readouterr().out


class TestTrailMissing:
    def test_a_missing_trail_is_exit_3(self, tmp_path: Path) -> None:
        assert (
            main(
                [
                    "consistency",
                    str(tmp_path / "absent.jsonl"),
                    "--old-seq",
                    "0",
                    "--old-root",
                    "a" * 64,
                ]
            )
            == 3
        )
