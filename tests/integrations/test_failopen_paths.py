"""Fail-open branches shared by the hermes modules and the install helper.

Rule 6: a degraded guard must be recorded, never swallowed — so the
dropped-write and home-resolution fallbacks are behavior, not incidental
code, and each needs a test.
"""

from __future__ import annotations

import importlib
import sys
import types
from collections.abc import Iterator
from pathlib import Path

import pytest

from waxseal import AuditLog
from waxseal.integrations._install import _default_home, install


@pytest.fixture(params=["waxseal.integrations.hermes", "waxseal.integrations.hermes_gateway"])
def hermes_module(request: pytest.FixtureRequest) -> Iterator[types.ModuleType]:
    sys.modules.pop(request.param, None)
    module = importlib.import_module(request.param)
    yield module
    sys.modules.pop(request.param, None)


class TestHermesHomeResolution:
    def test_falls_back_to_dot_hermes_without_env_or_hermes_cli(
        self, hermes_module: types.ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        # Path.home() is the LAST rung, reached only with no HOME at all —
        # the fallback still works, now stated against the corrected rule
        # (waxseal-fg4.3).
        monkeypatch.delenv("HERMES_HOME", raising=False)
        monkeypatch.delenv("HOME", raising=False)
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        assert hermes_module._hermes_home() == tmp_path / ".hermes"

    def test_home_env_is_preferred_over_path_home(
        self, hermes_module: types.ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        # The resolver goes through _trail.home_base(): on Windows
        # Path.home() reads USERPROFILE and ignores HOME, so a host that
        # sets HOME would otherwise seal the trail into the wrong profile
        # and `waxseal verify` would read a chain that looks truncated.
        monkeypatch.delenv("HERMES_HOME", raising=False)
        monkeypatch.setenv("HOME", str(tmp_path / "posix-home"))
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path / "windows"))
        assert hermes_module._hermes_home() == tmp_path / "posix-home" / ".hermes"

    def test_asks_hermes_cli_when_available(
        self, hermes_module: types.ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        # Inside a hermes process the CLI resolver is authoritative — a
        # hardcoded ~/.hermes would split the trail from the host's real home.
        monkeypatch.delenv("HERMES_HOME", raising=False)
        pkg = types.ModuleType("hermes_cli")
        config = types.ModuleType("hermes_cli.config")
        setattr(  # noqa: B010
            config, "get_hermes_home", lambda: str(tmp_path / "custom-home")
        )
        setattr(pkg, "config", config)  # noqa: B010
        monkeypatch.setitem(sys.modules, "hermes_cli", pkg)
        monkeypatch.setitem(sys.modules, "hermes_cli.config", config)
        assert hermes_module._hermes_home() == tmp_path / "custom-home"


class TestDroppedWritesAreLabelled:
    def test_hermes_plugin_labels_a_failed_append(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("HERMES_HOME", str(tmp_path))
        sys.modules.pop("waxseal.integrations.hermes", None)
        hermes = importlib.import_module("waxseal.integrations.hermes")
        monkeypatch.setattr(AuditLog, "try_append", lambda self, **kw: False)
        hermes.on_post_tool_call(tool_name="terminal", args={})
        assert "dropped" in capsys.readouterr().out
        sys.modules.pop("waxseal.integrations.hermes", None)

    def test_hermes_gateway_labels_a_failed_append(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("HERMES_HOME", str(tmp_path))
        sys.modules.pop("waxseal.integrations.hermes_gateway", None)
        gw = importlib.import_module("waxseal.integrations.hermes_gateway")
        monkeypatch.setattr(AuditLog, "try_append", lambda self, **kw: False)
        gw.handle("agent:step", {"iteration": 1})
        assert "dropped" in capsys.readouterr().out
        sys.modules.pop("waxseal.integrations.hermes_gateway", None)


class TestOpenFailureStillLeavesADropRecord:
    """M5: the pre-open failure branch (no AuditLog to route through yet)
    calls FileDropRecorder directly — every failure path still exits
    silently AND leaves a measurable drop record."""

    def test_hermes_plugin(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        monkeypatch.setenv("HERMES_HOME", str(tmp_path))
        # Realistic setup: the audit directory already exists from an
        # earlier successful run — THIS open() call fails for some other
        # reason (corrupt trail, transient permission issue), and unlike the
        # blocker-file scenario above, the sidecar write can still succeed.
        (tmp_path / "audit").mkdir()
        sys.modules.pop("waxseal.integrations.hermes", None)
        hermes = importlib.import_module("waxseal.integrations.hermes")
        monkeypatch.setattr(
            AuditLog,
            "open",
            staticmethod(lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("x"))),
        )
        hermes.on_post_tool_call(tool_name="terminal", args={})
        assert "dropped" in capsys.readouterr().out
        drops = tmp_path / "audit" / "trail.jsonl.drops"
        assert drops.exists()
        assert len(drops.read_text(encoding="utf-8").splitlines()) == 1
        sys.modules.pop("waxseal.integrations.hermes", None)

    def test_hermes_gateway(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        monkeypatch.setenv("HERMES_HOME", str(tmp_path))
        (tmp_path / "audit").mkdir()
        sys.modules.pop("waxseal.integrations.hermes_gateway", None)
        gw = importlib.import_module("waxseal.integrations.hermes_gateway")
        monkeypatch.setattr(
            AuditLog,
            "open",
            staticmethod(lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("x"))),
        )
        gw.handle("agent:step", {"iteration": 1})
        assert "dropped" in capsys.readouterr().out
        drops = tmp_path / "audit" / "trail.jsonl.drops"
        assert drops.exists()
        assert len(drops.read_text(encoding="utf-8").splitlines()) == 1
        sys.modules.pop("waxseal.integrations.hermes_gateway", None)


class TestInstallDefaultHomes:
    """`waxseal install` places shim files under the SAME home the trail
    resolvers use (waxseal-fg4.19). `_default_home` resolved its bottom rung
    with a bare `Path.home()`, which goes through ntpath on Windows and
    ignores HOME: `waxseal install hermes` on a host that sets HOME wrote the
    plugin into the USERPROFILE profile while the host launched with HOME
    looked in the other, so the plugin never loaded and there was no trail at
    all — zero evidence rather than the short chain fg4.3 produced.
    """

    def test_hermes_home_env_wins(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        # HERMES_HOME is the top rung and stays there: fg4.19 moved only the
        # rung below it, so a deployment that names the host home resolves
        # exactly as it did before.
        monkeypatch.setenv("HOME", str(tmp_path / "posix-home"))
        monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hh"))
        assert _default_home("hermes") == tmp_path / "hh"
        assert _default_home("hermes-gateway") == tmp_path / "hh"

    def test_home_env_is_preferred_over_path_home(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        # All five file-placing targets, because the split is per-host and
        # not per-target: whichever one an operator installs must land in the
        # profile the running host will look in.
        monkeypatch.delenv("HERMES_HOME", raising=False)
        monkeypatch.setenv("HOME", str(tmp_path / "posix-home"))
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path / "windows"))
        posix = tmp_path / "posix-home"
        assert _default_home("hermes") == posix / ".hermes"
        assert _default_home("hermes-gateway") == posix / ".hermes"
        assert _default_home("claude-code") == posix / ".claude"
        assert _default_home("codex") == posix / ".codex"
        assert _default_home("cursor") == posix / ".cursor"

    def test_host_dot_directories(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        # Path.home() is the LAST rung, reached only when there is no HOME at
        # all — the same coverage this monkeypatch used to carry, re-pointed
        # rather than deleted, now stated against the corrected rule.
        monkeypatch.delenv("HERMES_HOME", raising=False)
        monkeypatch.delenv("HOME", raising=False)
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        assert _default_home("hermes") == tmp_path / ".hermes"
        assert _default_home("hermes-gateway") == tmp_path / ".hermes"
        assert _default_home("claude-code") == tmp_path / ".claude"
        assert _default_home("codex") == tmp_path / ".codex"
        assert _default_home("cursor") == tmp_path / ".cursor"

    def test_layout_under_the_resolved_home_did_not_move(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # Regression: fg4.19 changed WHICH home is resolved and nothing about
        # the layout beneath it. The printed `wrote:` line names the full
        # path, which is how an operator whose shim relocated sees the move —
        # the shim left in the old profile is neither moved nor deleted.
        monkeypatch.delenv("HERMES_HOME", raising=False)
        monkeypatch.setenv("HOME", str(tmp_path / "posix-home"))
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path / "windows"))
        assert install("claude-code", None, False) == 0
        assert install("hermes", None, False) == 0
        posix = tmp_path / "posix-home"
        shim = posix / ".claude" / "hooks" / "waxseal_hook.py"
        plugin = posix / ".hermes" / "plugins" / "waxseal-audit" / "plugin.yaml"
        assert shim.exists()
        assert plugin.exists()
        assert not (tmp_path / "windows").exists()
        out = capsys.readouterr().out
        assert str(shim) in out
        assert str(plugin) in out

    def test_explicit_home_still_beats_the_environment(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # `--home` is above both rungs and untouched: an operator who names a
        # directory is not overridden by HOME.
        monkeypatch.setenv("HOME", str(tmp_path / "posix-home"))
        assert install("cursor", tmp_path / "explicit", False) == 0
        assert (tmp_path / "explicit" / "hooks" / "waxseal_hook.py").exists()
        assert not (tmp_path / "posix-home").exists()
        capsys.readouterr()
