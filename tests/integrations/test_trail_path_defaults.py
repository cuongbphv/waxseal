"""Where each stdin hook puts its trail when the host names no path.

The precedence is not cosmetic. `Path.home()` goes through ntpath on
Windows, which resolves "~" from USERPROFILE and IGNORES HOME — a host that
launches the hook with HOME set (git-bash, WSL-style wrappers, CI images)
would then write the trail into a different profile than the one the
operator later runs `waxseal verify` against, and the missing entries look
exactly like a truncated chain. HOME is therefore consulted first, and
Path.home() only when there is none.
"""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest

# host directory each hook nests its trail under
HOSTS = {
    "waxseal.integrations.claude_code": ".claude",
    "waxseal.integrations.codex": ".codex",
    "waxseal.integrations.cursor": ".cursor",
}


@pytest.fixture(params=sorted(HOSTS))
def hook(request, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("WAXSEAL_TRAIL", raising=False)
    monkeypatch.delenv("CODEX_HOME", raising=False)
    module = importlib.import_module(request.param)
    return module, HOSTS[request.param]


class TestDefaultTrailLocation:
    def test_waxseal_trail_env_overrides_every_default(
        self, hook, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        module, _ = hook
        monkeypatch.setenv("WAXSEAL_TRAIL", str(tmp_path / "explicit.jsonl"))
        monkeypatch.setenv("HOME", str(tmp_path / "posix-home"))
        assert module._trail_path() == tmp_path / "explicit.jsonl"

    def test_home_env_wins_over_path_home(
        self, hook, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        # The Windows split described above: both resolvers answer, and the
        # one the host actually set has to win.
        module, host_dir = hook
        monkeypatch.setenv("HOME", str(tmp_path / "posix-home"))
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path / "windows-profile"))
        assert module._trail_path() == (
            tmp_path / "posix-home" / host_dir / "waxseal" / "trail.jsonl"
        )

    def test_path_home_is_the_fallback_when_no_home_env(
        self, hook, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        module, host_dir = hook
        monkeypatch.delenv("HOME", raising=False)
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path / "profile"))
        assert module._trail_path() == (
            tmp_path / "profile" / host_dir / "waxseal" / "trail.jsonl"
        )


class TestCodexHome:
    """Codex relocates its whole state directory via CODEX_HOME; a trail
    left behind in ~/.codex would not follow the session it belongs to."""

    def test_codex_home_beats_the_home_fallbacks(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        codex = importlib.import_module("waxseal.integrations.codex")
        monkeypatch.delenv("WAXSEAL_TRAIL", raising=False)
        monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex-state"))
        monkeypatch.setenv("HOME", str(tmp_path / "posix-home"))
        assert codex._trail_path() == (
            tmp_path / "codex-state" / "waxseal" / "trail.jsonl"
        )

    def test_explicit_trail_still_beats_codex_home(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        codex = importlib.import_module("waxseal.integrations.codex")
        monkeypatch.setenv("WAXSEAL_TRAIL", str(tmp_path / "explicit.jsonl"))
        monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex-state"))
        assert codex._trail_path() == tmp_path / "explicit.jsonl"
