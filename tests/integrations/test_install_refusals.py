"""install reports and stops — for every target that places a file.

Same stance as verify: an operator's local edit to a shim is a decision only
the operator can reverse, so install refuses and returns nonzero instead of
clobbering. tests/test_cli_install.py covers that for the hermes plugin;
the other two file-placing paths (hermes-gateway, and the stdin hook hosts)
each reach the refusal through their own branch, and both have a
follow-on success notice that must NOT be printed after a refusal — an
operator told "the gateway will discover it on next startup", or handed a
settings snippet, would wire up a shim this run did not write.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from waxseal.integrations._install import install


class TestHermesGatewayRefusal:
    def test_edited_handler_is_kept_and_the_discovery_notice_is_withheld(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert install("hermes-gateway", tmp_path, force=False) == 0
        handler = tmp_path / "hooks" / "waxseal-audit" / "handler.py"
        handler.write_text("# locally patched\n", encoding="utf-8")
        capsys.readouterr()

        assert install("hermes-gateway", tmp_path, force=False) == 1
        assert handler.read_text(encoding="utf-8") == "# locally patched\n"
        out = capsys.readouterr().out
        assert "--force" in out
        assert "next startup" not in out

    def test_force_completes_what_the_refusal_stopped(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        install("hermes-gateway", tmp_path, force=False)
        handler = tmp_path / "hooks" / "waxseal-audit" / "handler.py"
        handler.write_text("# locally patched\n", encoding="utf-8")
        capsys.readouterr()

        assert install("hermes-gateway", tmp_path, force=True) == 0
        assert "waxseal.integrations.hermes_gateway" in handler.read_text(encoding="utf-8")
        assert "next startup" in capsys.readouterr().out


class TestStdinHookShimRefusal:
    @pytest.mark.parametrize("target", ["claude-code", "codex", "cursor"])
    def test_edited_shim_is_kept_and_no_config_snippet_is_printed(
        self, target: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert install(target, tmp_path, force=False) == 0
        shim = tmp_path / "hooks" / "waxseal_hook.py"
        shim.write_text("# locally patched\n", encoding="utf-8")
        capsys.readouterr()

        assert install(target, tmp_path, force=False) == 1
        assert shim.read_text(encoding="utf-8") == "# locally patched\n"
        out = capsys.readouterr().out
        assert "--force" in out
        # The snippet names the shim path the host should run; printing it
        # after a refusal points the host at a file this run did not write.
        assert "add to" not in out
