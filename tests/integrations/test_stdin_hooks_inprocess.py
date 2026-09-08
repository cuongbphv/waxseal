"""In-process runs of the stdin hook mains (claude_code / codex / cursor).

The sibling test files exercise these hooks the way the hosts do — a
subprocess per event — which is the honest contract test but invisible to
coverage (pytest-cov does not instrument subprocesses here). These tests
drive the same main() in-process so the measured suite actually covers the
shipped hook logic; assertions mirror the subprocess files.
"""

from __future__ import annotations

import importlib
import io
import json
import sys
import types
from pathlib import Path

import pytest

from waxseal import AuditLog

MODULES = [
    "waxseal.integrations.claude_code",
    "waxseal.integrations.codex",
    "waxseal.integrations.cursor",
]


@pytest.fixture(params=MODULES)
def hook(request: pytest.FixtureRequest) -> types.ModuleType:
    module: types.ModuleType = importlib.import_module(request.param)
    return module


def run_main(
    monkeypatch: pytest.MonkeyPatch, hook: types.ModuleType, stdin_text: str, trail: Path
) -> int:
    monkeypatch.setenv("WAXSEAL_TRAIL", str(trail))
    monkeypatch.setattr(sys, "stdin", io.StringIO(stdin_text))
    exit_code: int = hook.main()
    return exit_code


def test_event_is_appended_and_verifies(
    monkeypatch: pytest.MonkeyPatch,
    hook: types.ModuleType,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    trail = tmp_path / "trail.jsonl"
    event = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "ls"}}
    assert run_main(monkeypatch, hook, json.dumps(event), trail) == 0
    # stdout is parsed by the hosts as decision JSON — must stay empty.
    assert capsys.readouterr().out == ""
    result = AuditLog.open(trail).verify(measure_drops=False)
    assert result.ok
    assert result.checked == 1


def test_secret_is_redacted_before_disk(
    monkeypatch: pytest.MonkeyPatch, hook: types.ModuleType, tmp_path: Path
) -> None:
    trail = tmp_path / "trail.jsonl"
    secret = "sk-abcdef1234567890abcdef"
    event = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": f"export KEY={secret}"},
    }
    run_main(monkeypatch, hook, json.dumps(event), trail)
    assert secret.encode() not in trail.read_bytes()


def test_malformed_stdin_exits_zero_with_labelled_drop(
    monkeypatch: pytest.MonkeyPatch,
    hook: types.ModuleType,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Nonzero would veto the user's tool call or prompt on some hosts.
    assert run_main(monkeypatch, hook, "not json {", tmp_path / "trail.jsonl") == 0
    err = capsys.readouterr().err
    assert "dropped" in err


def test_json_that_is_not_an_object_is_reported_unreadable_not_crashed(
    monkeypatch: pytest.MonkeyPatch,
    hook: types.ModuleType,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Valid JSON of the wrong shape: a list parses, and then every
    # event.get() in build_payload would raise. Unrecognized input is
    # opaque, never a crash and never an exit code the host reads as a veto.
    trail = tmp_path / "trail.jsonl"
    assert run_main(monkeypatch, hook, "[1, 2]", trail) == 0
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "unreadable hook event" in captured.err
    assert "dropped" in captured.err
    # Nothing was read into the chain, so nothing may be written to it —
    # a placeholder entry would be an invented record of an event.
    assert not trail.exists()


def test_unopenable_trail_exits_zero_with_labelled_drop(
    monkeypatch: pytest.MonkeyPatch,
    hook: types.ModuleType,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    blocker = tmp_path / "blocker"
    blocker.write_text("a file where the trail dir should be")
    event = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {}}
    assert run_main(monkeypatch, hook, json.dumps(event), blocker / "trail.jsonl") == 0
    assert "dropped" in capsys.readouterr().err
    # Honest limit (adapters/drops.py's own docstring): the SAME broken
    # directory that blocks the trail also blocks the .drops sidecar next to
    # it — a disk too broken to hold a write cannot bear witness to its own
    # failure either. FileDropRecorder swallows that, it does not fake it.
    assert not (blocker / "trail.jsonl.drops").exists()


def test_open_failure_still_leaves_a_drop_record(
    monkeypatch: pytest.MonkeyPatch,
    hook: types.ModuleType,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Unlike the blocker-file case above, the trail's OWN directory is
    # writable here — only AuditLog.open() itself fails (e.g. a corrupt
    # backend) — so the sidecar write in the except-branch can and must
    # succeed (M5: every failure path stays silent on stdout AND leaves a
    # measurable drop record).
    monkeypatch.setattr(
        AuditLog, "open", staticmethod(lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("x")))
    )
    trail = tmp_path / "trail.jsonl"
    event = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {}}
    assert run_main(monkeypatch, hook, json.dumps(event), trail) == 0
    assert capsys.readouterr().out == ""

    drops = trail.parent / (trail.name + ".drops")
    assert drops.exists()
    assert len(drops.read_text().splitlines()) == 1


class TestToolResultFieldNaming:
    """One action must not split across two field names because the host
    renamed the field between releases — a reviewer filtering the trail on
    the spelling they know would silently miss half the results."""

    def test_claude_code_folds_the_legacy_spelling_into_tool_output(self) -> None:
        claude_code = importlib.import_module("waxseal.integrations.claude_code")
        documented = claude_code.build_payload(
            {"hook_event_name": "PostToolUse", "tool_output": "total 0\n"}
        )
        legacy = claude_code.build_payload(
            {"hook_event_name": "PostToolUse", "tool_response": {"stdout": "ok"}}
        )
        assert documented["tool_output"] == "total 0\n"
        assert legacy["tool_output"] == {"stdout": "ok"}
        assert "tool_response" not in legacy

    def test_codex_records_its_own_tool_response_field(self) -> None:
        # Codex only ever sent tool_response (rust-v0.149.0); recording it
        # under a Claude-shaped name would misdescribe the host.
        codex = importlib.import_module("waxseal.integrations.codex")
        payload = codex.build_payload(
            {"hook_event_name": "PostToolUse", "tool_response": "total 0\n"}
        )
        assert payload["tool_response"] == "total 0\n"


#: 0.1.5: the local branch of `_trail_target` routes per project, so it now
#: takes the hook event that carries the project key. The remote branch these
#: tests are about is unchanged — it still resolves before any path is built.
_ROUTING_EVENT = {"hook_event_name": "PreToolUse", "cwd": "/work/project"}


class TestClaudeCodeRemoteTargetInProcess:
    """The remote branch of the Claude Code hook, measured.

    `test_claude_code_remote.py` drives this through a subprocess, which is the
    honest contract test and invisible to coverage. These run the same code
    in-process so the shipped logic is actually measured, and assert the same
    facts.
    """

    @pytest.fixture()
    def claude(self) -> types.ModuleType:
        module: types.ModuleType = importlib.import_module("waxseal.integrations.claude_code")
        return module

    def test_an_http_trail_is_kept_as_a_string(
        self, monkeypatch: pytest.MonkeyPatch, claude: types.ModuleType
    ) -> None:
        # Path("http://host") collapses the // and drops the scheme, so the
        # target would silently become a local file named `http:`.
        monkeypatch.setenv("WAXSEAL_TRAIL", "http://127.0.0.1:9/")
        target = claude._trail_target(_ROUTING_EVENT)
        assert isinstance(target, str)
        assert target == "http://127.0.0.1:9/"

    def test_an_https_trail_is_kept_as_a_string(
        self, monkeypatch: pytest.MonkeyPatch, claude: types.ModuleType
    ) -> None:
        monkeypatch.setenv("WAXSEAL_TRAIL", "https://audit.example.test")
        assert isinstance(claude._trail_target(_ROUTING_EVENT), str)

    def test_a_local_trail_is_still_a_path(
        self, monkeypatch: pytest.MonkeyPatch, claude: types.ModuleType, tmp_path: Path
    ) -> None:
        monkeypatch.setenv("WAXSEAL_TRAIL", str(tmp_path / "trail.jsonl"))
        assert isinstance(claude._trail_target(_ROUTING_EVENT), Path)

    def test_an_explicit_chain_id_wins(
        self, monkeypatch: pytest.MonkeyPatch, claude: types.ModuleType
    ) -> None:
        monkeypatch.setenv("WAXSEAL_CHAIN_ID", "waxseal")
        assert claude._chain_id({"cwd": "/somewhere/else"}) == "waxseal"

    def test_the_project_directory_names_the_chain(
        self, monkeypatch: pytest.MonkeyPatch, claude: types.ModuleType
    ) -> None:
        monkeypatch.delenv("WAXSEAL_CHAIN_ID", raising=False)
        assert claude._chain_id({"cwd": "/Users/dev/Projects/waxseal"}) == "waxseal"

    @pytest.mark.parametrize(
        ("cwd", "expected"),
        [
            ("/Users/dev/My Project (v2)", "my-project-v2"),
            ("/Users/dev/UPPER", "upper"),
            ("/Users/dev/__weird__", "weird"),
            ("/Users/dev/...", "default"),
        ],
    )
    def test_a_directory_name_is_folded_to_a_safe_chain_id(
        self, monkeypatch: pytest.MonkeyPatch, claude: types.ModuleType, cwd: str, expected: str
    ) -> None:
        monkeypatch.delenv("WAXSEAL_CHAIN_ID", raising=False)
        assert claude._chain_id({"cwd": cwd}) == expected

    @pytest.mark.parametrize("event", [{}, {"cwd": ""}, {"cwd": 7}])
    def test_an_absent_or_unusable_cwd_falls_back_to_default(
        self, monkeypatch: pytest.MonkeyPatch, claude: types.ModuleType, event: dict[str, object]
    ) -> None:
        monkeypatch.delenv("WAXSEAL_CHAIN_ID", raising=False)
        assert claude._chain_id(event) == "default"

    def test_an_unreachable_server_exits_zero_and_records_no_sidecar(
        self,
        monkeypatch: pytest.MonkeyPatch,
        claude: types.ModuleType,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        # The observer contract, and the reason record_drops is off for a URL:
        # a remote trail has no next-to for a sidecar, and asking for one raises
        # in AuditLog.open before the append is ever attempted.
        monkeypatch.setenv("WAXSEAL_TRAIL", "http://127.0.0.1:1")
        monkeypatch.setenv("WAXSEAL_CHAIN_ID", "waxseal")
        monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps({"hook_event_name": "Stop"})))

        assert claude.main() == 0
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "waxseal-audit" in captured.err
        assert not list(tmp_path.iterdir())

    def test_a_remote_trail_that_cannot_be_opened_writes_no_sidecar(
        self,
        monkeypatch: pytest.MonkeyPatch,
        claude: types.ModuleType,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        # The local path records the loss in a `.drops` sidecar NEXT TO the
        # trail. A URL has no next-to, so this branch must return without
        # inventing a location — a file called `http:` in the working directory
        # would be a worse outcome than the unrecorded drop it was avoiding.
        #
        # Forced, because `AuditLog.open` on a URL builds a backend without
        # connecting and so has no natural failure: the branch is defensive, and
        # a defensive branch nothing exercises is a branch nobody has run.
        def refuse(*_args: object, **_kwargs: object) -> object:
            raise RuntimeError("simulated: cannot construct the remote backend")

        monkeypatch.setenv("WAXSEAL_TRAIL", "http://127.0.0.1:1")
        monkeypatch.setenv("WAXSEAL_CHAIN_ID", "waxseal")
        monkeypatch.setattr(claude.AuditLog, "open", refuse)
        monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps({"hook_event_name": "Stop"})))
        monkeypatch.chdir(tmp_path)

        assert claude.main() == 0
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "cannot open trail" in captured.err
        assert not list(tmp_path.iterdir())
