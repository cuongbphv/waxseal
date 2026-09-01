"""Where each stdin hook puts its trail when the host names no path.

The precedence is not cosmetic. `Path.home()` goes through ntpath on
Windows, which resolves "~" from USERPROFILE and IGNORES HOME — a host that
launches the hook with HOME set (git-bash, WSL-style wrappers, CI images)
would then write the trail into a different profile than the one the
operator later runs `waxseal verify` against, and the missing entries look
exactly like a truncated chain. HOME is therefore consulted first, and
Path.home() only when there is none.

0.1.5 changed only the BOTTOM rung: the stdin hooks route their default per
project (`_trail.routed_trail`), so the expected default now carries a
`trails/<slug>/trail.00000.jsonl` tail under the same host directory. The
precedence above it is untouched, and an event with no project key still
resolves to the pre-0.1.5 shared trail — asserted below so the fallback
cannot drift.
"""

from __future__ import annotations

import importlib
import types
from pathlib import Path

import pytest

from waxseal.domain.segments import project_slug

# host directory each hook nests its trail under
HOSTS = {
    "waxseal.integrations.claude_code": ".claude",
    "waxseal.integrations.codex": ".codex",
    "waxseal.integrations.cursor": ".cursor",
}


PROJECT = "/work/project"
EVENT = {"hook_event_name": "PreToolUse", "cwd": PROJECT}
NO_PROJECT_EVENT: dict[str, object] = {"hook_event_name": "PreToolUse"}

#: The routed default's tail under `<home>/<host dir>/waxseal`.
ROUTED_TAIL = Path("trails") / project_slug(PROJECT) / "trail.00000.jsonl"


@pytest.fixture(params=sorted(HOSTS))
def hook(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch
) -> tuple[types.ModuleType, str]:
    monkeypatch.delenv("WAXSEAL_TRAIL", raising=False)
    monkeypatch.delenv("CODEX_HOME", raising=False)
    module = importlib.import_module(request.param)
    return module, HOSTS[request.param]


class TestDefaultTrailLocation:
    def test_waxseal_trail_env_overrides_every_default(
        self, hook: tuple[types.ModuleType, str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        module, _ = hook
        monkeypatch.setenv("WAXSEAL_TRAIL", str(tmp_path / "explicit.jsonl"))
        monkeypatch.setenv("HOME", str(tmp_path / "posix-home"))
        assert module._trail_path(EVENT) == tmp_path / "explicit.jsonl"

    def test_home_env_wins_over_path_home(
        self, hook: tuple[types.ModuleType, str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        # The Windows split described above: both resolvers answer, and the
        # one the host actually set has to win.
        module, host_dir = hook
        monkeypatch.setenv("HOME", str(tmp_path / "posix-home"))
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path / "windows-profile"))
        assert module._trail_path(EVENT) == (
            tmp_path / "posix-home" / host_dir / "waxseal" / ROUTED_TAIL
        )

    def test_path_home_is_the_fallback_when_no_home_env(
        self, hook: tuple[types.ModuleType, str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        module, host_dir = hook
        monkeypatch.delenv("HOME", raising=False)
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path / "profile"))
        assert module._trail_path(EVENT) == (
            tmp_path / "profile" / host_dir / "waxseal" / ROUTED_TAIL
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
        assert codex._trail_path(EVENT) == (
            tmp_path / "codex-state" / "waxseal" / ROUTED_TAIL
        )

    def test_explicit_trail_still_beats_codex_home(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        codex = importlib.import_module("waxseal.integrations.codex")
        monkeypatch.setenv("WAXSEAL_TRAIL", str(tmp_path / "explicit.jsonl"))
        monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex-state"))
        assert codex._trail_path(EVENT) == tmp_path / "explicit.jsonl"


class TestTheSharedFallbackIsUnchanged:
    """An event with no project key still resolves to the pre-0.1.5 path.

    That trail is never migrated and never force-sealed: routed appends stop
    arriving, and it keeps verifying forever with plain `waxseal verify`.
    """

    def test_no_project_key_resolves_to_the_shared_trail(
        self, hook: tuple[types.ModuleType, str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        module, host_dir = hook
        monkeypatch.setenv("HOME", str(tmp_path / "posix-home"))
        assert module._trail_path(NO_PROJECT_EVENT) == (
            tmp_path / "posix-home" / host_dir / "waxseal" / "trail.jsonl"
        )
