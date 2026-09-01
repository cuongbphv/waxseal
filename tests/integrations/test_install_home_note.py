"""`waxseal install <target> --home X` silently ignored the flag for the four
targets that place nothing on disk (langchain, crewai, openai-agents,
openclaw): install() returned before `home` was ever read. Same labelling rule
as the CLI's remote `--anchors` note (CLAUDE.md rule 6): a flag that does
nothing must say so in the output, or the operator has no way to notice it was
ignored."""

import sys
from pathlib import Path

import pytest

from waxseal.integrations._install import install

_NO_HOME_TARGETS = ("langchain", "crewai", "openai-agents", "openclaw")


class TestHomeNoteForNoInstallTargets:
    @pytest.mark.parametrize("target", _NO_HOME_TARGETS)
    def test_explicit_home_prints_note_and_still_exits_zero(
        self, target: str, capsys: pytest.CaptureFixture[str], tmp_path: Path
    ) -> None:
        code = install(target, tmp_path / "custom-home", force=False)
        assert code == 0
        captured = capsys.readouterr()
        assert f"note: --home has no effect for {target}" in captured.err

    @pytest.mark.parametrize("target", _NO_HOME_TARGETS)
    def test_no_home_flag_prints_no_note(
        self, target: str, capsys: pytest.CaptureFixture[str]
    ) -> None:
        code = install(target, None, force=False)
        assert code == 0
        captured = capsys.readouterr()
        assert "note: --home" not in captured.err
        assert "note: --home" not in captured.out

    @pytest.mark.parametrize("target", _NO_HOME_TARGETS)
    def test_usage_guidance_still_printed_alongside_the_note(
        self, target: str, capsys: pytest.CaptureFixture[str], tmp_path: Path
    ) -> None:
        install(target, tmp_path / "custom-home", force=False)
        captured = capsys.readouterr()
        # The note supplements the guidance, never replaces it.
        assert "nothing to install" in captured.out


class TestConfigSnippetNamesThisInterpreter:
    """`python3` on PATH is not necessarily the interpreter that has waxseal.

    This is 0.1.5 Workstream D1, and it is written from a real incident on the
    repository owner's machine: the snippet said `python3`, that interpreter
    could not import waxseal, every hook event was dropped with a label nobody
    was reading, and the trail stayed empty while the hooks looked installed.

    The shim keeps its `#!/usr/bin/env python3` shebang — that is a fail-open
    the host may override. The snippet an operator PASTES must name the
    interpreter that just ran `waxseal install`, because that one demonstrably
    has waxseal.
    """

    def test_the_snippet_uses_the_running_interpreter(self, tmp_path: Path) -> None:
        from waxseal.integrations._install import _config_snippet

        snippet = _config_snippet("claude-code", tmp_path / "hook.py")
        assert sys.executable in snippet

    def test_the_snippet_does_not_say_bare_python3(self, tmp_path: Path) -> None:
        from waxseal.integrations._install import _config_snippet

        snippet = _config_snippet("claude-code", tmp_path / "hook.py")
        assert '"command": "python3 ' not in snippet

    def test_the_openclaw_cron_line_also_names_it(self) -> None:
        # openclaw is a timer target, not a hook shim, so its guidance is a
        # crontab line rather than a settings.json snippet — and it had the
        # same bare-interpreter bug.
        from waxseal.integrations._install import _RUNNER_USAGE

        assert sys.executable in _RUNNER_USAGE["openclaw"]
        assert "* * * * * python -m waxseal" not in _RUNNER_USAGE["openclaw"]
