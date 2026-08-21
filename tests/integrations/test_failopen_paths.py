"""Fail-open branches shared by the hermes modules and the install helper.

Rule 6: a degraded guard must be recorded, never swallowed — so the
dropped-write and home-resolution fallbacks are behavior, not incidental
code, and each needs a test.
"""

from __future__ import annotations

import importlib
import sys
import types
from pathlib import Path

import pytest

from waxseal import AuditLog
from waxseal.integrations._install import _default_home


@pytest.fixture(params=["waxseal.integrations.hermes", "waxseal.integrations.hermes_gateway"])
def hermes_module(request):
    sys.modules.pop(request.param, None)
    module = importlib.import_module(request.param)
    yield module
    sys.modules.pop(request.param, None)


class TestHermesHomeResolution:
    def test_falls_back_to_dot_hermes_without_env_or_hermes_cli(
        self, hermes_module, monkeypatch, tmp_path: Path
    ) -> None:
        monkeypatch.delenv("HERMES_HOME", raising=False)
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        assert hermes_module._hermes_home() == tmp_path / ".hermes"

    def test_asks_hermes_cli_when_available(
        self, hermes_module, monkeypatch, tmp_path: Path
    ) -> None:
        # Inside a hermes process the CLI resolver is authoritative — a
        # hardcoded ~/.hermes would split the trail from the host's real home.
        monkeypatch.delenv("HERMES_HOME", raising=False)
        pkg = types.ModuleType("hermes_cli")
        config = types.ModuleType("hermes_cli.config")
        config.get_hermes_home = lambda: str(tmp_path / "custom-home")
        pkg.config = config
        monkeypatch.setitem(sys.modules, "hermes_cli", pkg)
        monkeypatch.setitem(sys.modules, "hermes_cli.config", config)
        assert hermes_module._hermes_home() == tmp_path / "custom-home"


class TestDroppedWritesAreLabelled:
    def test_hermes_plugin_labels_a_failed_append(
        self, monkeypatch, tmp_path: Path, capsys
    ) -> None:
        monkeypatch.setenv("HERMES_HOME", str(tmp_path))
        sys.modules.pop("waxseal.integrations.hermes", None)
        hermes = importlib.import_module("waxseal.integrations.hermes")
        monkeypatch.setattr(AuditLog, "try_append", lambda self, **kw: False)
        hermes.on_post_tool_call(tool_name="terminal", args={})
        assert "dropped" in capsys.readouterr().out
        sys.modules.pop("waxseal.integrations.hermes", None)

    def test_hermes_gateway_labels_a_failed_append(
        self, monkeypatch, tmp_path: Path, capsys
    ) -> None:
        monkeypatch.setenv("HERMES_HOME", str(tmp_path))
        sys.modules.pop("waxseal.integrations.hermes_gateway", None)
        gw = importlib.import_module("waxseal.integrations.hermes_gateway")
        monkeypatch.setattr(AuditLog, "try_append", lambda self, **kw: False)
        gw.handle("agent:step", {"iteration": 1})
        assert "dropped" in capsys.readouterr().out
        sys.modules.pop("waxseal.integrations.hermes_gateway", None)


class TestInstallDefaultHomes:
    def test_hermes_home_env_wins(self, monkeypatch, tmp_path: Path) -> None:
        monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hh"))
        assert _default_home("hermes") == tmp_path / "hh"
        assert _default_home("hermes-gateway") == tmp_path / "hh"

    def test_host_dot_directories(self, monkeypatch, tmp_path: Path) -> None:
        monkeypatch.delenv("HERMES_HOME", raising=False)
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        assert _default_home("hermes") == tmp_path / ".hermes"
        assert _default_home("claude-code") == tmp_path / ".claude"
        assert _default_home("codex") == tmp_path / ".codex"
        assert _default_home("cursor") == tmp_path / ".cursor"
