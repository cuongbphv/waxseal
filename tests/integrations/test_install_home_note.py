"""`waxseal install <target> --home X` silently ignored the flag for the four
targets that place nothing on disk (langchain, crewai, openai-agents,
openclaw): install() returned before `home` was ever read. Same labelling rule
as the CLI's remote `--anchors` note (CLAUDE.md rule 6): a flag that does
nothing must say so in the output, or the operator has no way to notice it was
ignored."""

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
