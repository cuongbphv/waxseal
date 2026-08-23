"""Tests for the OpenClaw ingest runner (`python -m waxseal.integrations.openclaw`).

The runner is meant for cron / a systemd timer, so the property under test is
that it returns 0 on every path — a missing binary, a stopped gateway, an
unwritable trail. A timer that flaps on a degraded audit is an audit nobody
keeps running.

One test drives the REAL default runner through a stub `openclaw` on PATH:
every other test injects `run_fn`, so without it the subprocess plumbing
(binary resolution, utf-8 decoding, exit-code handling) would be untested.
"""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

import pytest

from waxseal import AuditLog
from waxseal.integrations.openclaw import main, resolve_trail
from waxseal.sources.openclaw import OPENCLAW_AUDIT_PAYLOAD_TYPE, run_openclaw_audit

RECORD = {
    "schemaVersion": 1,
    "sequence": 12,
    "eventId": "evt-12",
    "sourceSequence": 12,
    "occurredAt": 1_700_000_000_012,
    "redaction": "metadata_only",
    "kind": "tool_action",
    "action": "tool.action.finished",
    "status": "succeeded",
    "actorType": "agent",
    "actorId": "main",
    "agentId": "main",
    "runId": "run-1",
    "toolName": "Bash",
}


def stub_openclaw(bin_dir: Path, body: str, *, exit_code: int = 0) -> None:
    """Put a fake `openclaw` on PATH. On Windows a .cmd wrapper is the only
    name subprocess/PATHEXT resolution will find for a bare "openclaw"."""
    bin_dir.mkdir(parents=True, exist_ok=True)
    script = bin_dir / "stub.py"
    # buffer.write, not stdout.write: the child's text layer defaults to the
    # locale encoding (cp1252 on Windows) and would mangle the export.
    script.write_text(
        "import sys\n"
        f"sys.stdout.buffer.write({body.encode()!r})\n"
        f"sys.exit({exit_code})\n",
        encoding="utf-8",
    )
    if sys.platform == "win32":
        (bin_dir / "openclaw.cmd").write_text(
            f'@"{sys.executable}" "{script}" %*\n', encoding="utf-8"
        )
    else:
        launcher = bin_dir / "openclaw"
        launcher.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{script}" "$@"\n')
        launcher.chmod(launcher.stat().st_mode | stat.S_IXUSR)


class TestResolveTrail:
    def test_waxseal_trail_wins(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("WAXSEAL_TRAIL", str(tmp_path / "custom.jsonl"))
        monkeypatch.setenv("OPENCLAW_HOME", str(tmp_path / "home"))
        assert resolve_trail() == tmp_path / "custom.jsonl"

    def test_openclaw_home_next(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("WAXSEAL_TRAIL", raising=False)
        monkeypatch.setenv("OPENCLAW_HOME", str(tmp_path / "oc"))
        assert resolve_trail() == tmp_path / "oc" / "audit" / "trail.jsonl"

    def test_home_is_read_before_path_home(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # ntpath resolves "~" from USERPROFILE and ignores HOME, so a host
        # that launches this runner with HOME set would otherwise strand the
        # trail in the wrong profile on Windows.
        monkeypatch.delenv("WAXSEAL_TRAIL", raising=False)
        monkeypatch.delenv("OPENCLAW_HOME", raising=False)
        monkeypatch.setenv("HOME", str(tmp_path / "unixhome"))
        assert resolve_trail() == tmp_path / "unixhome" / ".openclaw" / "audit" / "trail.jsonl"


class TestRunner:
    def test_ingests_through_the_real_subprocess_path(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        stub_openclaw(tmp_path / "bin", json.dumps({"events": [RECORD]}))
        monkeypatch.setenv("PATH", str(tmp_path / "bin") + os.pathsep + os.environ["PATH"])
        trail = tmp_path / "trail.jsonl"

        assert main(["--trail", str(trail)]) == 0

        log = AuditLog.open(trail)
        stored = [
            e for e in log._backend.entries()
            if e.header.payload_type == OPENCLAW_AUDIT_PAYLOAD_TYPE
        ]
        assert len(stored) == 1
        assert json.loads(stored[0].payload)["eventId"] == "evt-12"
        assert log.verify().ok

    def test_returns_zero_when_the_binary_is_absent(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("PATH", str(tmp_path / "empty-bin"))
        monkeypatch.setenv("WAXSEAL_OPENCLAW_BIN", "definitely-not-installed-openclaw")

        assert main(["--trail", str(tmp_path / "trail.jsonl")]) == 0

        assert "[waxseal-audit]" in capsys.readouterr().err

    def test_returns_zero_when_the_export_command_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        stub_openclaw(tmp_path / "bin", "gateway not running", exit_code=1)
        monkeypatch.setenv("PATH", str(tmp_path / "bin") + os.pathsep + os.environ["PATH"])

        assert main(["--trail", str(tmp_path / "trail.jsonl")]) == 0

        assert "[waxseal-audit]" in capsys.readouterr().err

    def test_returns_zero_when_the_trail_is_unusable(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        blocked = tmp_path / "trail.jsonl"
        blocked.mkdir()  # a directory where the trail should be

        assert main(["--trail", str(blocked)]) == 0

        # Whether the open or the first read is what fails is a platform
        # detail; that it is labelled and non-fatal is the contract.
        err = capsys.readouterr().err
        assert "[waxseal-audit]" in err
        assert "trail" in err

    def test_reports_the_ingest_summary_on_stderr(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        stub_openclaw(tmp_path / "bin", json.dumps({"events": [RECORD]}))
        monkeypatch.setenv("PATH", str(tmp_path / "bin") + os.pathsep + os.environ["PATH"])

        main(["--trail", str(tmp_path / "trail.jsonl")])

        err = capsys.readouterr().err
        assert "ingested 1" in err
        assert "sequence 12" in err

    def test_never_writes_to_stdout(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # Same discipline as the stdin hooks: stdout belongs to the host.
        stub_openclaw(tmp_path / "bin", json.dumps({"events": [RECORD]}))
        monkeypatch.setenv("PATH", str(tmp_path / "bin") + os.pathsep + os.environ["PATH"])

        main(["--trail", str(tmp_path / "trail.jsonl")])

        assert capsys.readouterr().out == ""


class TestDefaultRunFn:
    def test_raises_a_labelled_error_on_a_nonzero_exit(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        stub_openclaw(tmp_path / "bin", "boom", exit_code=3)
        monkeypatch.setenv("PATH", str(tmp_path / "bin") + os.pathsep + os.environ["PATH"])

        with pytest.raises(RuntimeError, match="exit 3"):
            run_openclaw_audit(["audit", "--json", "--limit", "1"])

    def test_raises_when_the_binary_is_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("WAXSEAL_OPENCLAW_BIN", "definitely-not-installed-openclaw")
        with pytest.raises(FileNotFoundError):
            run_openclaw_audit(["audit", "--json"])

    def test_decodes_utf8_regardless_of_locale(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # cp1252 is the Windows locale default and has already broken this
        # repo once (install shims, 0.1.0); the export must be read as utf-8.
        record = dict(RECORD, agentId="tác-nhân")
        stub_openclaw(tmp_path / "bin", json.dumps({"events": [record]}, ensure_ascii=False))
        monkeypatch.setenv("PATH", str(tmp_path / "bin") + os.pathsep + os.environ["PATH"])

        out = run_openclaw_audit(["audit", "--json", "--limit", "1"])

        assert json.loads(out)["events"][0]["agentId"] == "tác-nhân"


class TestUnopenableTrail:
    def test_returns_zero_when_the_log_cannot_be_opened_at_all(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        import waxseal.integrations.openclaw as runner

        def refuse(*args: object, **kwargs: object) -> AuditLog:
            raise OSError("read-only file system")

        monkeypatch.setattr(runner.AuditLog, "open", refuse)

        assert main(["--trail", str(tmp_path / "trail.jsonl")]) == 0

        err = capsys.readouterr().err
        assert "cannot open trail" in err
        assert "read-only file system" in err
