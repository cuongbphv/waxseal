"""CLI: what `--tsa-ca-file` adds to `verify --anchors` and `report --anchors`.

`tests/test_cli_receipts.py` freezes the STRUCTURAL exit-code table, and this
file does not touch it: without `--tsa-ca-file` every exit code there is
unchanged, because a dimension the operator did not engage is not part of a
run's verdict -- the same reason `--anchors` is itself opt-in, and the same
argument `_receipt_verdict` already makes for a pending OpenTimestamps proof
(an operator who sees exit 2 on every healthy run learns to ignore exit 2).

What the flag adds is the third column, and the rule that once the dimension
IS engaged it can never come back 0 without an answer:

  signature_valid      -> 0
  signature_invalid    -> 1, ANCHOR BROKEN, checked and false
  signature_unchecked  -> 2, with a label naming its cause and its remedy

The one that must never regress is the third. An absent extra that exits 0 is
false confidence over a token nobody authenticated.

Condition R throughout: every criterion here is asserted through `main()`'s
own stdout, and one through a real subprocess, because "it prints" is the
claim being made.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from tests.adapters.test_rfc3161_verify import (
    ca_bundle,
    issue,
    signed_token,
)
from tests.test_cli_receipts import frame_of, rfc3161_receipt, trail_with_receipt
from waxseal.cli import main


@pytest.fixture
def anchored(tmp_path: Path) -> tuple[Path, Path, Path]:
    """(trail, ca bundle the signer chains to, a bundle it does not)."""
    path = trail_with_receipt(tmp_path, None)
    ca_key, ca_cert = issue("waxseal test root", ca=True)
    leaf_key, leaf_cert = issue("waxseal test TSA", issuer_key=ca_key, issuer_name=ca_cert.subject)
    der = signed_token(key=leaf_key, cert=leaf_cert, message=frame_of(path))
    path = trail_with_receipt(tmp_path, rfc3161_receipt(der))
    _, stranger = issue("some other root", ca=True)
    return (
        path,
        ca_bundle(tmp_path, ca_cert),
        ca_bundle(tmp_path, stranger, name="stranger.pem"),
    )


class TestSignatureValid:
    def test_a_token_from_the_named_anchor_verifies_and_stays_exit_0(
        self, anchored: tuple[Path, Path, Path], capsys: pytest.CaptureFixture[str]
    ) -> None:
        trail, ca_file, _ = anchored
        assert main(["verify", str(trail), "--anchors", "--tsa-ca-file", str(ca_file)]) == 0
        out = capsys.readouterr().out
        assert "signature_valid" in out

    def test_the_valid_line_still_names_what_it_did_not_check(
        self, anchored: tuple[Path, Path, Path], capsys: pytest.CaptureFixture[str]
    ) -> None:
        # Rule 6, and the reason this library never prints an unqualified
        # "verified": a chain to the named anchor is not a live certificate.
        trail, ca_file, _ = anchored
        main(["verify", str(trail), "--anchors", "--tsa-ca-file", str(ca_file)])
        out = capsys.readouterr().out
        assert "revocation" in out
        assert "NOT checked" in out


class TestSignatureInvalid:
    def test_a_signer_outside_the_bundle_is_exit_1(
        self, anchored: tuple[Path, Path, Path], capsys: pytest.CaptureFixture[str]
    ) -> None:
        trail, _, stranger = anchored
        assert main(["verify", str(trail), "--anchors", "--tsa-ca-file", str(stranger)]) == 1
        out = capsys.readouterr().out
        assert "ANCHOR BROKEN" in out
        assert "signature_invalid" in out

    def test_a_signature_that_does_not_verify_is_exit_1(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = trail_with_receipt(tmp_path, None)
        ca_key, ca_cert = issue("root", ca=True)
        leaf_key, leaf_cert = issue("tsa", issuer_key=ca_key, issuer_name=ca_cert.subject)
        der = signed_token(
            key=leaf_key, cert=leaf_cert, message=frame_of(path), wrong_signature=True
        )
        path = trail_with_receipt(tmp_path, rfc3161_receipt(der))
        ca_file = ca_bundle(tmp_path, ca_cert)
        assert main(["verify", str(path), "--anchors", "--tsa-ca-file", str(ca_file)]) == 1
        assert "signature_invalid" in capsys.readouterr().out

    def test_the_structural_break_still_wins_over_the_signature(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # A token attesting other bytes is already exit 1 on its own terms;
        # engaging the signature dimension must not renumber that finding.
        path = trail_with_receipt(tmp_path, None)
        ca_key, ca_cert = issue("root", ca=True)
        leaf_key, leaf_cert = issue("tsa", issuer_key=ca_key, issuer_name=ca_cert.subject)
        der = signed_token(key=leaf_key, cert=leaf_cert, message=b"other bytes entirely")
        path = trail_with_receipt(tmp_path, rfc3161_receipt(der))
        ca_file = ca_bundle(tmp_path, ca_cert)
        assert main(["verify", str(path), "--anchors", "--tsa-ca-file", str(ca_file)]) == 1
        assert "receipt_imprint_mismatch" in capsys.readouterr().out


class TestSignatureUnchecked:
    """Exit 2, never 0. This is the class the whole extra exists to make
    impossible to get wrong."""

    def test_the_absent_extra_is_exit_2_and_says_how_to_install_it(
        self, anchored: tuple[Path, Path, Path], capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """FALSIFIABILITY RECEIPT (the branch whose absence is the hazard).
        Make the ``except ImportError`` arm in
        ``adapters/rfc3161_verify.py::_verify`` return ``SIGNATURE_VALID`` and
        this test fails on ``assert 0 == 2`` -- exit 0 over a token nobody
        authenticated. Delete the arm outright and the exit code survives (the
        never-raise net catches it) but the printed remedy does not; delete the
        net too and this run ERRORS instead of exiting. Real numbers are in the
        bead's report, and the adapter-level twin of this test carries the same
        receipt.
        """
        trail, ca_file, _ = anchored
        monkeypatch.setitem(sys.modules, "cryptography", None)
        assert main(["verify", str(trail), "--anchors", "--tsa-ca-file", str(ca_file)]) == 2
        out = capsys.readouterr().out
        assert "signature_unchecked" in out
        assert "waxseal[rfc3161]" in out

    def test_a_bundle_that_is_not_there_is_exit_2(
        self, anchored: tuple[Path, Path, Path], tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        trail, _, _ = anchored
        missing = tmp_path / "not-here.pem"
        assert main(["verify", str(trail), "--anchors", "--tsa-ca-file", str(missing)]) == 2
        assert "signature_unchecked" in capsys.readouterr().out

    def test_unchecked_is_never_rendered_as_a_pass(
        self, anchored: tuple[Path, Path, Path], tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        trail, _, _ = anchored
        assert main(
            ["verify", str(trail), "--anchors", "--tsa-ca-file", str(tmp_path / "gone.pem")]
        ) != 0


class TestNotEngaged:
    """Without the flag, nothing about the exit-code table moves -- but the
    run is not silent about it either."""

    def test_the_structural_run_is_still_exit_0(
        self, anchored: tuple[Path, Path, Path], capsys: pytest.CaptureFixture[str]
    ) -> None:
        trail, _, _ = anchored
        assert main(["verify", str(trail), "--anchors"]) == 0

    def test_it_says_the_signature_dimension_was_not_engaged(
        self, anchored: tuple[Path, Path, Path], capsys: pytest.CaptureFixture[str]
    ) -> None:
        # Rule 6: a check that did not run is stated. The line names the flag,
        # so an operator does not have to already know the feature exists.
        trail, _, _ = anchored
        main(["verify", str(trail), "--anchors"])
        out = capsys.readouterr().out
        assert "signature_unchecked" in out
        assert "--tsa-ca-file" in out

    def test_it_says_waxseal_picks_no_default_trust_anchor(
        self, anchored: tuple[Path, Path, Path], capsys: pytest.CaptureFixture[str]
    ) -> None:
        trail, _, _ = anchored
        main(["verify", str(trail), "--anchors"])
        assert "no default trust store" in capsys.readouterr().out


class TestReport:
    def test_the_json_report_carries_the_signature_state_as_data(
        self, anchored: tuple[Path, Path, Path], capsys: pytest.CaptureFixture[str]
    ) -> None:
        # The artifact an auditor still has six months later. A caveat that
        # only `verify` prints is a caveat that never reaches them.
        trail, ca_file, _ = anchored
        rc = main(
            ["report", str(trail), "--anchors", "--json", "--tsa-ca-file", str(ca_file)]
        )
        assert rc == 0
        notes = json.loads(capsys.readouterr().out)["anchors"]["notes"]
        assert any("signature_valid" in note for note in notes)

    def test_the_report_carries_an_unchecked_state_too(
        self, anchored: tuple[Path, Path, Path], tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        trail, _, _ = anchored
        rc = main(
            [
                "report", str(trail), "--anchors", "--json",
                "--tsa-ca-file", str(tmp_path / "absent.pem"),
            ]
        )
        assert rc == 2
        anchors = json.loads(capsys.readouterr().out)["anchors"]
        assert anchors["reason"] == "signature_unchecked"

    def test_the_markdown_report_states_it_in_prose(
        self, anchored: tuple[Path, Path, Path], capsys: pytest.CaptureFixture[str]
    ) -> None:
        trail, ca_file, _ = anchored
        assert main(["report", str(trail), "--anchors", "--tsa-ca-file", str(ca_file)]) == 0
        assert "signature_valid" in capsys.readouterr().out


class TestConditionR:
    def test_a_real_subprocess_prints_the_verdict_and_exits_2(
        self, anchored: tuple[Path, Path, Path], tmp_path: Path
    ) -> None:
        # Not `main()` in-process: the claim is that an operator running the
        # installed console script sees this, so one test runs the real thing.
        trail, _, _ = anchored
        proc = subprocess.run(
            [
                sys.executable, "-m", "waxseal.cli", "verify", str(trail), "--anchors",
                "--tsa-ca-file", str(tmp_path / "nowhere.pem"),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 2
        assert "signature_unchecked" in proc.stdout

    def test_the_help_text_names_the_extra(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(SystemExit):
            main(["verify", "--help"])
        assert "waxseal[rfc3161]" in capsys.readouterr().out
