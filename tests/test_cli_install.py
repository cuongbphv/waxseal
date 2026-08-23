"""`waxseal install <target>` — writes the host-side shim files so
`pip install waxseal` + one command replaces "checkout the repo and copy
hook files by hand".

The shims contain no logic: they import from waxseal.integrations.*, so a
`pip install -U waxseal` updates the hook behavior without re-running
install. The CLI contract is untouched: install never reads or writes any
audit log.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

from waxseal import AuditLog
from waxseal.cli import main
from waxseal.integrations.hermes import PLUGIN_MANIFEST
from waxseal.integrations.hermes_gateway import HOOK_MANIFEST


def load_by_path(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestHermesPlugin:
    def test_writes_manifest_and_shim(self, tmp_path: Path, capsys) -> None:
        assert main(["install", "hermes", "--home", str(tmp_path)]) == 0
        plugin_dir = tmp_path / "plugins" / "waxseal-audit"
        assert (plugin_dir / "plugin.yaml").read_text() == PLUGIN_MANIFEST
        shim = load_by_path(plugin_dir / "__init__.py", "hermes_shim_test")
        # The shim must delegate, not duplicate: pip upgrades the behavior.
        from waxseal.integrations import hermes

        assert shim.register is hermes.register
        # Standalone plugins are opt-in; forgetting enable = silent no-audit.
        assert "hermes plugins enable waxseal-audit" in capsys.readouterr().out

    def test_rerun_is_idempotent(self, tmp_path: Path) -> None:
        assert main(["install", "hermes", "--home", str(tmp_path)]) == 0
        assert main(["install", "hermes", "--home", str(tmp_path)]) == 0

    def test_refuses_to_overwrite_a_differing_file_without_force(
        self, tmp_path: Path, capsys
    ) -> None:
        # An operator's local edit must not be clobbered silently — install
        # reports and stops, exactly like verify reports and never repairs.
        main(["install", "hermes", "--home", str(tmp_path)])
        shim = tmp_path / "plugins" / "waxseal-audit" / "__init__.py"
        shim.write_text("# locally patched\n")
        assert main(["install", "hermes", "--home", str(tmp_path)]) == 1
        assert shim.read_text() == "# locally patched\n"
        assert "--force" in capsys.readouterr().out
        assert main(["install", "hermes", "--home", str(tmp_path), "--force"]) == 0
        assert "waxseal.integrations.hermes" in shim.read_text()


class TestHermesGateway:
    def test_writes_hook_manifest_and_shim(self, tmp_path: Path) -> None:
        assert main(["install", "hermes-gateway", "--home", str(tmp_path)]) == 0
        hook_dir = tmp_path / "hooks" / "waxseal-audit"
        assert (hook_dir / "HOOK.yaml").read_text() == HOOK_MANIFEST
        shim = load_by_path(hook_dir / "handler.py", "hermes_gateway_shim_test")
        from waxseal.integrations import hermes_gateway

        assert shim.handle is hermes_gateway.handle


class TestClaudeCodeHook:
    def test_writes_shim_and_prints_settings_snippet(self, tmp_path: Path, capsys) -> None:
        assert main(["install", "claude-code", "--home", str(tmp_path)]) == 0
        shim = tmp_path / "hooks" / "waxseal_hook.py"
        assert shim.exists()
        out = capsys.readouterr().out
        # The host only runs what settings.json names — the printed snippet
        # must reference the file actually written.
        assert "PreToolUse" in out
        assert str(shim) in out

    def test_shim_records_a_hook_event_end_to_end(self, tmp_path: Path) -> None:
        main(["install", "claude-code", "--home", str(tmp_path)])
        shim = tmp_path / "hooks" / "waxseal_hook.py"
        trail = tmp_path / "trail.jsonl"
        event = {"hook_event_name": "PreToolUse", "tool_name": "Bash",
                 "tool_input": {"command": "ls"}}
        proc = subprocess.run(
            [sys.executable, str(shim)], input=json.dumps(event).encode(),
            env={"WAXSEAL_TRAIL": str(trail), "PATH": "/usr/bin:/bin",
                 "PYTHONPATH": str(Path(__file__).parent.parent / "src")},
            capture_output=True,
        )
        # Exit 0 on every path: exit 2 would veto the user's tool call.
        assert proc.returncode == 0
        assert proc.stdout == b""  # stdout is parsed as decision JSON
        result = AuditLog.open(trail).verify(measure_drops=False)
        assert result.ok
        assert result.checked == 1


@pytest.mark.parametrize("target", ["codex", "cursor"])
def test_stdin_hook_targets_write_shim_and_print_config(
    target: str, tmp_path: Path, capsys
) -> None:
    assert main(["install", target, "--home", str(tmp_path)]) == 0
    assert (tmp_path / "hooks" / "waxseal_hook.py").exists()
    assert "hooks.json" in capsys.readouterr().out


@pytest.mark.parametrize("target", ["langchain", "crewai", "openai-agents"])
def test_library_targets_install_nothing_and_print_usage(
    target: str, tmp_path: Path, capsys
) -> None:
    # These attach in the user's own code; there is no host directory to
    # write into, so install is documentation, not file placement.
    assert main(["install", target, "--home", str(tmp_path)]) == 0
    assert list(tmp_path.iterdir()) == []
    assert "waxseal.integrations." in capsys.readouterr().out


def test_openclaw_installs_nothing_and_prints_the_schedule(tmp_path: Path, capsys) -> None:
    # The exporter runs on a timer, so there is no host file to place and
    # nothing on the agent's execution path to configure.
    assert main(["install", "openclaw", "--home", str(tmp_path)]) == 0
    assert list(tmp_path.iterdir()) == []
    out = capsys.readouterr().out
    assert "python -m waxseal.integrations.openclaw" in out
    assert "waxseal verify" in out


def test_unknown_target_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["install", "not-a-target", "--home", str(tmp_path)])
    assert exc.value.code == 2
