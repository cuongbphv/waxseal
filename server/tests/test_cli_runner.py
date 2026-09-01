"""Reading a trail by shelling out to the waxseal CLI.

The plan fixes this split deliberately: the WRITE path uses waxseal as a
library, and every READ/verify surface goes through the CLI, because the CLI's
exit codes are a stable, documented contract and the server has no business
re-deriving verdicts of its own. The job here is to carry 0/1/2/3 up to the UI
without collapsing any of them into another.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from conftest import NO_ABSENT_COMMAND, PAYLOAD_TYPE, planned_but_absent, withhold
from waxseal_server.runtime import cli as cli_module
from waxseal_server.runtime.cli import READ_ONLY_COMMANDS, WaxsealCli, _classify

from waxseal import AuditLog, Verdict


@pytest.fixture
def cli() -> WaxsealCli:
    return WaxsealCli()


@pytest.fixture
def trail(tmp_path: Path) -> Path:
    path = tmp_path / "trail.jsonl"
    log = AuditLog.open(path)
    for i in range(3):
        log.append(payload={"i": i}, payload_type=PAYLOAD_TYPE)
    return path


class TestAvailability:
    def test_the_shipped_read_commands_are_present(self, cli: WaxsealCli) -> None:
        assert {"verify", "report", "inspect", "tail", "head"} <= cli.available()

    def test_a_command_this_build_does_not_have_is_reported_unavailable(
        self, cli: WaxsealCli, trail: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Running it anyway would make argparse's exit 2 look like the verifier's
        # exit 2 — "unverifiable" — which is a verdict nobody computed. Absent
        # capability is its own state.
        #
        # The fixture withholds a command that DOES ship rather than naming one
        # that does not, because this test used to name `segments` and inverted
        # the day Workstream B shipped it (waxseal-fg4.16). What is being tested
        # is the condition — a name absent from `available()` — and a server
        # pointed at an older or newer waxseal is exactly how that arises in
        # production.
        withhold(monkeypatch, cli, "verify")
        outcome = cli.run("verify", str(trail))
        assert outcome.status == "unavailable"
        assert outcome.verdict is None
        assert outcome.exit_code is None

    def test_every_read_this_build_really_lacks_is_reported_unavailable(
        self, cli: WaxsealCli, trail: Path
    ) -> None:
        # The real, unmonkeypatched gate: whatever this server offers that the
        # wheel behind it does not have, parsed from `--help` and refused before
        # argv is built. The SET is derived, so nothing here inverts when a
        # planned command ships — that is precisely what happened to this test
        # twice, as `assert "segments" not in available()` and then as
        # `assert "preflight" not in available()` (waxseal-fg4.16, -fg4.36).
        #
        # When the set is empty the case is SKIPPED with a label rather than
        # passing vacuously: a green tick standing for zero invocations is the
        # unmeasured-reported-as-measured collapse this library exists to make
        # unrepresentable. The withheld form above covers the property meanwhile.
        absent = planned_but_absent(cli)
        if not absent:
            pytest.skip(NO_ABSENT_COMMAND)
        for command in sorted(absent):
            outcome = cli.run(command, str(trail))
            assert outcome.status == "unavailable"
            assert outcome.verdict is None
            assert outcome.exit_code is None

    @pytest.mark.parametrize("command", ["segments", "preflight"])
    def test_a_planned_command_that_has_shipped_is_reported_available(
        self, cli: WaxsealCli, command: str
    ) -> None:
        # `segments` shipped in 0.1.5 Workstream B and `preflight` in Workstream
        # E one batch later. `available()` parses `--help` precisely so the flag
        # flips with the build and not with a frozen list; this is the assertion
        # that the flip really happens, for both.
        assert command in cli.available()

    def test_an_unavailable_command_is_never_executed(
        self, cli: WaxsealCli, trail: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # "Never executed" asserted literally, not inferred from empty stdout:
        # the subprocess call is replaced by one that fails the test if it is
        # reached. Running the command anyway would hand argparse's exit 2 up as
        # the verifier's exit 2 — "unverifiable", a verdict nobody computed.
        withhold(monkeypatch, cli, "verify")
        monkeypatch.setattr(
            cli_module.subprocess,
            "run",
            lambda *a, **k: pytest.fail("an unavailable command reached the CLI"),
        )
        outcome = cli.run("verify", str(trail))
        assert outcome.stdout == ""
        assert outcome.exit_code is None
        assert "no 'verify' subcommand" in outcome.stderr

    def test_a_command_outside_the_read_only_set_is_refused(self, cli: WaxsealCli) -> None:
        # `install` and `anchor` write. They must not be reachable from an HTTP
        # request at all, so the refusal happens before argv is built.
        with pytest.raises(ValueError, match="read-only"):
            cli.run("install", "claude-code")

    def test_the_read_only_set_holds_no_writing_command(self) -> None:
        assert not READ_ONLY_COMMANDS & {"anchor", "install"}


class TestVerdictMapping:
    def test_an_intact_trail_is_exit_0_and_ok(self, cli: WaxsealCli, trail: Path) -> None:
        outcome = cli.run("verify", str(trail))
        assert outcome.exit_code == 0
        assert outcome.verdict is Verdict.OK
        assert outcome.status == "ok"

    def test_a_tampered_trail_is_exit_1_and_broken(self, cli: WaxsealCli, trail: Path) -> None:
        lines = trail.read_text().splitlines()
        record = json.loads(lines[1])
        record["header"]["ts"] = "2000-01-01T00:00:00+00:00"
        lines[1] = json.dumps(record, sort_keys=True, separators=(",", ":"))
        trail.write_text("\n".join(lines) + "\n")

        outcome = cli.run("verify", str(trail))
        assert outcome.exit_code == 1
        assert outcome.verdict is Verdict.BROKEN
        assert "entry_hash_mismatch" in outcome.stdout

    def test_an_unknown_fingerprint_is_exit_2_and_unverifiable_not_broken(
        self, cli: WaxsealCli, trail: Path
    ) -> None:
        # The founding rule: a row signed under a fingerprint this build cannot
        # reproduce is unverifiable by name. Never "tampered".
        lines = trail.read_text().splitlines()
        record = json.loads(lines[1])
        record["header"]["hash_version"] = "ff" * 32
        lines[1] = json.dumps(record, sort_keys=True, separators=(",", ":"))
        trail.write_text("\n".join(lines) + "\n")

        outcome = cli.run("verify", str(trail))
        assert outcome.exit_code == 2
        assert outcome.verdict is Verdict.UNVERIFIABLE
        assert outcome.status == "unverifiable"

    def test_a_missing_trail_is_exit_3_and_absent_never_broken(
        self, cli: WaxsealCli, tmp_path: Path
    ) -> None:
        # Exit 3 is "nothing was read". Folding it into 1 would report a tamper
        # against a file that does not exist.
        outcome = cli.run("verify", str(tmp_path / "nope.jsonl"))
        assert outcome.exit_code == 3
        assert outcome.status == "absent"
        assert outcome.verdict is None

    def test_a_usage_error_is_not_reported_as_unverifiable(
        self, cli: WaxsealCli, trail: Path
    ) -> None:
        # argparse also exits 2. A server bug in flag construction must surface
        # as a server bug, not as a verdict about the operator's trail.
        outcome = cli.run("verify", str(trail), "--no-such-flag")
        assert outcome.status == "usage_error"
        assert outcome.verdict is None


class TestReadCommands:
    def test_report_json_is_parseable(self, cli: WaxsealCli, trail: Path) -> None:
        report = json.loads(cli.run("report", str(trail), "--json").stdout)
        assert report["inventory"]["entries_total"] == 3

    def test_report_json_carries_the_scope_statement_for_the_ui_to_print(
        self, cli: WaxsealCli, trail: Path
    ) -> None:
        # The plan requires the dashboard to show the scope statement verbatim.
        # It comes from the report, never retyped into the UI, so it cannot
        # drift from what the library actually claims.
        report = json.loads(cli.run("report", str(trail), "--json").stdout)
        assert report["scope"]["id"] == "waxseal-scope-v1"
        assert "does not attest" in report["scope"]["statement"]

    def test_report_json_keeps_dropped_writes_null_when_unmeasured(
        self, cli: WaxsealCli, trail: Path
    ) -> None:
        report = json.loads(cli.run("report", str(trail), "--json").stdout)
        assert report["completeness"]["dropped_writes"] is None

    def test_tail_honours_its_count(self, cli: WaxsealCli, trail: Path) -> None:
        outcome = cli.run("tail", str(trail), "-n", "2")
        assert len(outcome.stdout.strip().splitlines()) == 2

    def test_head_prints_the_tail_identity(self, cli: WaxsealCli, trail: Path) -> None:
        assert json.loads(cli.run("head", str(trail)).stdout)["seq"] == 2

    def test_inspect_summarizes(self, cli: WaxsealCli, trail: Path) -> None:
        assert cli.run("inspect", str(trail)).exit_code == 0

    def test_export_proof_emits_a_bundle_verify_proof_accepts(
        self, cli: WaxsealCli, trail: Path, tmp_path: Path
    ) -> None:
        bundle = tmp_path / "bundle.json"
        bundle.write_text(cli.run("export-proof", str(trail), "1").stdout)
        assert cli.run("verify-proof", str(bundle)).verdict is Verdict.OK


class TestNoShell:
    def test_arguments_are_never_interpreted_by_a_shell(
        self, cli: WaxsealCli, tmp_path: Path
    ) -> None:
        # argv is a list and `shell=False`. A path carrying shell metacharacters
        # is a path, not a command.
        canary = tmp_path / "canary"
        outcome = cli.run("verify", f"{tmp_path}/x.jsonl; touch {canary}")
        assert outcome.exit_code == 3
        assert not canary.exists()

    def test_the_argv_is_recorded_for_the_operator(self, cli: WaxsealCli, trail: Path) -> None:
        # An auditor UI that shows a verdict without showing the command that
        # produced it is asking to be trusted. The argv travels with the result.
        outcome = cli.run("verify", str(trail))
        assert outcome.argv[-2:] == ("verify", str(trail))


class TestUnexpectedExitCode:
    def test_a_code_outside_the_contract_is_labelled_not_guessed(self) -> None:
        # No shipped subcommand returns anything but 0/1/2/3. If a future one
        # does, the server says so rather than coercing it into the nearest
        # verdict — a wrong verdict is worse than an admitted unknown.
        outcome = _classify("verify", ("waxseal", "verify", "t.jsonl"), 42, "", "boom")
        assert outcome.status == "unexpected_exit"
        assert outcome.verdict is None
        assert outcome.exit_code == 42
