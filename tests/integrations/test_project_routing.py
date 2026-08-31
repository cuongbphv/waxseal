"""Per-project trail routing and rotation in the three hook shims (B1/B2).

Every new behaviour here is ON BY DEFAULT — no feature flag, no new
environment variable (owner decision, 31/08/2026). The pre-existing
`WAXSEAL_TRAIL` still wins on LOCATION, and it is NOT a rotation off-switch:
a trail named through it rotates too, and on its first rotation it is adopted
as the base segment.

The hooks are exercised the way their hosts run them — a subprocess with one
JSON event on stdin — wherever the criterion is "it prints" (Condition R).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from waxseal import AuditLog
from waxseal.domain.segments import project_slug
from waxseal.sources.rotation import DEFAULT_MAX_SEGMENT_BYTES

REPO = Path(__file__).parent.parent.parent
SRC = str(REPO / "src")

HOOKS = {
    "claude_code": REPO / "src" / "waxseal" / "integrations" / "claude_code.py",
    "codex": REPO / "src" / "waxseal" / "integrations" / "codex.py",
    "cursor": REPO / "src" / "waxseal" / "integrations" / "cursor.py",
}
HOST_DIR = {"claude_code": ".claude", "codex": ".codex", "cursor": ".cursor"}

PROJECT = "/work/some project"


def event_for(hook: str, cwd: str | None = PROJECT) -> dict[str, object]:
    base: dict[str, object] = {
        "claude_code": {"hook_event_name": "PreToolUse", "tool_name": "Bash"},
        "codex": {"hook_event_name": "PreToolUse", "tool_name": "shell"},
        "cursor": {"hook_event_name": "beforeShellExecution", "command": "ls"},
    }[hook]
    if cwd is not None:
        base = {**base, "cwd": cwd}
    return base


def run(hook: str, event: dict[str, object] | str, home: Path, **env_extra: str):
    env = {k: v for k, v in os.environ.items() if k not in ("WAXSEAL_TRAIL", "CODEX_HOME")}
    env.update({"PYTHONPATH": SRC, "HOME": str(home)})
    env.update(env_extra)
    stdin = event if isinstance(event, str) else json.dumps(event)
    return subprocess.run(
        [sys.executable, str(HOOKS[hook])],
        input=stdin, capture_output=True, text=True, env=env, timeout=60,
    )


def routed_dir(hook: str, home: Path, cwd: str = PROJECT) -> Path:
    return home / HOST_DIR[hook] / "waxseal" / "trails" / project_slug(cwd)


HOOK_NAMES = sorted(HOOKS)


class TestRoutedByProject:
    @pytest.mark.parametrize("hook", HOOK_NAMES)
    def test_the_first_append_lands_in_the_projects_own_segment(
        self, hook: str, tmp_path: Path
    ) -> None:
        proc = run(hook, event_for(hook), tmp_path)
        assert proc.returncode == 0
        segment = routed_dir(hook, tmp_path) / "trail.00000.jsonl"
        assert segment.exists(), proc.stderr
        assert AuditLog.open(segment).verify(measure_drops=False).checked == 1

    @pytest.mark.parametrize("hook", HOOK_NAMES)
    def test_two_projects_never_share_a_directory(self, hook: str, tmp_path: Path) -> None:
        run(hook, event_for(hook, "/work/alpha"), tmp_path)
        run(hook, event_for(hook, "/work/beta"), tmp_path)
        trails = tmp_path / HOST_DIR[hook] / "waxseal" / "trails"
        assert len(sorted(trails.iterdir())) == 2

    @pytest.mark.parametrize("hook", HOOK_NAMES)
    def test_the_same_project_reuses_one_directory(self, hook: str, tmp_path: Path) -> None:
        run(hook, event_for(hook), tmp_path)
        run(hook, event_for(hook), tmp_path)
        trails = tmp_path / HOST_DIR[hook] / "waxseal" / "trails"
        assert len(sorted(trails.iterdir())) == 1
        segment = routed_dir(hook, tmp_path) / "trail.00000.jsonl"
        assert AuditLog.open(segment).verify(measure_drops=False).checked == 2

    @pytest.mark.parametrize("hook", HOOK_NAMES)
    def test_stdout_stays_empty_on_the_routed_path(self, hook: str, tmp_path: Path) -> None:
        # A hook's stdout is read by its host: Claude Code injects it into
        # model context, Cursor parses it as a permission decision.
        assert run(hook, event_for(hook), tmp_path).stdout == ""

    def test_codex_routing_follows_codex_home(self, tmp_path: Path) -> None:
        # CODEX_HOME relocates Codex's whole state directory; a trail left in
        # ~/.codex would not follow the session it belongs to.
        elsewhere = tmp_path / "relocated"
        run("codex", event_for("codex"), tmp_path, CODEX_HOME=str(elsewhere))
        assert (
            elsewhere / "waxseal" / "trails" / project_slug(PROJECT) / "trail.00000.jsonl"
        ).exists()

    def test_cursor_falls_back_to_workspace_roots(self, tmp_path: Path) -> None:
        event = {
            "hook_event_name": "beforeShellExecution",
            "command": "ls",
            "workspace_roots": [PROJECT, "/work/other"],
        }
        run("cursor", event, tmp_path)
        assert (routed_dir("cursor", tmp_path) / "trail.00000.jsonl").exists()


class TestTheRoutingNotice:
    @pytest.mark.parametrize("hook", HOOK_NAMES)
    def test_the_first_routed_append_names_where_writes_moved(
        self, hook: str, tmp_path: Path
    ) -> None:
        proc = run(hook, event_for(hook), tmp_path)
        assert "routed per project" in proc.stderr
        assert PROJECT in proc.stderr
        assert "trail.00000.jsonl" in proc.stderr
        assert "waxseal verify" in proc.stderr

    @pytest.mark.parametrize("hook", HOOK_NAMES)
    def test_the_notice_is_printed_once_not_on_every_append(
        self, hook: str, tmp_path: Path
    ) -> None:
        run(hook, event_for(hook), tmp_path)
        second = run(hook, event_for(hook), tmp_path)
        assert "routed per project" not in second.stderr

    @pytest.mark.parametrize("hook", HOOK_NAMES)
    def test_an_event_with_no_project_key_is_labelled_not_silent(
        self, hook: str, tmp_path: Path
    ) -> None:
        # Rule 6: routing degraded to the shared trail, and the degradation is
        # in the output rather than swallowed.
        proc = run(hook, event_for(hook, cwd=None), tmp_path)
        assert proc.returncode == 0
        assert "cannot route per project" in proc.stderr
        shared = tmp_path / HOST_DIR[hook] / "waxseal" / "trail.jsonl"
        assert shared.exists()

    @pytest.mark.parametrize("hook", HOOK_NAMES)
    def test_an_explicit_waxseal_trail_prints_no_routing_notice(
        self, hook: str, tmp_path: Path
    ) -> None:
        named = tmp_path / "named.jsonl"
        proc = run(hook, event_for(hook), tmp_path, WAXSEAL_TRAIL=str(named))
        assert named.exists()
        assert "routed per project" not in proc.stderr


class TestBackwardCompatibility:
    @pytest.mark.parametrize("hook", HOOK_NAMES)
    def test_a_legacy_trail_is_neither_migrated_nor_touched(
        self, hook: str, tmp_path: Path
    ) -> None:
        legacy = tmp_path / HOST_DIR[hook] / "waxseal" / "trail.jsonl"
        legacy.parent.mkdir(parents=True)
        log = AuditLog.open(legacy)
        for i in range(3):
            log.append(payload={"i": i}, payload_type="application/vnd.test.event+json")
        before = legacy.read_bytes()

        run(hook, event_for(hook), tmp_path)

        assert legacy.read_bytes() == before
        result = AuditLog.open(legacy).verify(measure_drops=False)
        assert result.ok and result.checked == 3

    @pytest.mark.parametrize("hook", HOOK_NAMES)
    def test_waxseal_trail_still_wins_on_location(self, hook: str, tmp_path: Path) -> None:
        named = tmp_path / "named.jsonl"
        run(hook, event_for(hook), tmp_path, WAXSEAL_TRAIL=str(named))
        assert named.exists()
        assert not (tmp_path / HOST_DIR[hook] / "waxseal" / "trails").exists()


class TestWaxsealTrailStillRotates:
    """`WAXSEAL_TRAIL` is a LOCATION, never a rotation off-switch."""

    @pytest.mark.parametrize("hook", HOOK_NAMES)
    def test_a_named_trail_past_the_threshold_rotates_and_is_adopted(
        self, hook: str, tmp_path: Path
    ) -> None:
        named = tmp_path / "named.jsonl"
        run(hook, event_for(hook), tmp_path, WAXSEAL_TRAIL=str(named))
        # Padded with blank lines so the stored tail stays readable; this is
        # what 16 MiB looks like to an O(1) tail read.
        named.write_bytes(b"\n" * DEFAULT_MAX_SEGMENT_BYTES + named.read_bytes())
        tail_hash = AuditLog.open(named).entry_hashes()[-1]

        proc = run(hook, event_for(hook), tmp_path, WAXSEAL_TRAIL=str(named))

        adopted = tmp_path / "named.00000.jsonl"
        assert adopted.exists(), proc.stderr
        entries = list(AuditLog.open(adopted).entries())
        assert entries[0].header.payload_type == (
            "application/vnd.waxseal.rotation-binding+json"
        )
        assert entries[0].payload is not None
        assert json.loads(entries[0].payload)["head_hash"] == tail_hash
        assert json.loads(entries[0].payload)["chain_id"].endswith("/named")

    @pytest.mark.parametrize("hook", HOOK_NAMES)
    def test_the_hook_uses_the_built_in_sixteen_mebibyte_constant(
        self, hook: str, tmp_path: Path
    ) -> None:
        # Condition R for B2's labelled threshold: the hook passes the
        # constant, and the notice says the number came from the built-in
        # default rather than from anything an operator configured.
        named = tmp_path / "named.jsonl"
        run(hook, event_for(hook), tmp_path, WAXSEAL_TRAIL=str(named))
        named.write_bytes(b"\n" * DEFAULT_MAX_SEGMENT_BYTES + named.read_bytes())
        proc = run(hook, event_for(hook), tmp_path, WAXSEAL_TRAIL=str(named))
        assert "rotated at 16777216 bytes (built-in default)" in proc.stderr

    @pytest.mark.parametrize("hook", HOOK_NAMES)
    def test_a_routed_trail_rotates_too(self, hook: str, tmp_path: Path) -> None:
        run(hook, event_for(hook), tmp_path)
        segment = routed_dir(hook, tmp_path) / "trail.00000.jsonl"
        segment.write_bytes(b"\n" * DEFAULT_MAX_SEGMENT_BYTES + segment.read_bytes())
        run(hook, event_for(hook), tmp_path)
        assert (routed_dir(hook, tmp_path) / "trail.00001.jsonl").exists()


class TestInProcessRouting:
    """The same routing driven through `main()` in-process.

    The subprocess tests above are the honest host-contract tests but are
    invisible to coverage (pytest-cov does not instrument them), and they
    cannot easily force a mid-rotation drop. These run the shipped `main()`
    directly, which is what Condition R asks for, and reach every routing
    branch.
    """

    @pytest.fixture(params=HOOK_NAMES)
    def hook_module(self, request: pytest.FixtureRequest):
        import importlib

        return importlib.import_module(f"waxseal.integrations.{request.param}"), request.param

    @staticmethod
    def drive(
        monkeypatch: pytest.MonkeyPatch, module, event: dict[str, object], home: Path
    ) -> int:
        import io

        monkeypatch.delenv("WAXSEAL_TRAIL", raising=False)
        monkeypatch.delenv("CODEX_HOME", raising=False)
        monkeypatch.setenv("HOME", str(home))
        monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(event)))
        return module.main()

    def test_the_routed_segment_is_written_and_the_move_is_announced(
        self,
        monkeypatch: pytest.MonkeyPatch,
        hook_module,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        module, name = hook_module
        assert self.drive(monkeypatch, module, event_for(name), tmp_path) == 0
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "routed per project" in captured.err
        segment = routed_dir(name, tmp_path) / "trail.00000.jsonl"
        assert AuditLog.open(segment).verify(measure_drops=False).checked == 1

    def test_a_second_append_announces_nothing(
        self,
        monkeypatch: pytest.MonkeyPatch,
        hook_module,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        module, name = hook_module
        self.drive(monkeypatch, module, event_for(name), tmp_path)
        capsys.readouterr()
        self.drive(monkeypatch, module, event_for(name), tmp_path)
        assert "routed per project" not in capsys.readouterr().err

    def test_an_event_with_no_cwd_is_labelled_every_time(
        self,
        monkeypatch: pytest.MonkeyPatch,
        hook_module,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        module, name = hook_module
        self.drive(monkeypatch, module, event_for(name, cwd=None), tmp_path)
        assert "cannot route per project" in capsys.readouterr().err
        # Not a one-off migration notice: a live degradation, every append.
        self.drive(monkeypatch, module, event_for(name, cwd=None), tmp_path)
        assert "cannot route per project" in capsys.readouterr().err

    def test_a_non_string_cwd_is_treated_as_absent(
        self,
        monkeypatch: pytest.MonkeyPatch,
        hook_module,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        module, name = hook_module
        event = {**event_for(name, cwd=None), "cwd": 17}
        assert self.drive(monkeypatch, module, event, tmp_path) == 0
        assert "cannot route per project" in capsys.readouterr().err

    def test_cursor_routes_on_the_first_workspace_root(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        # Cursor sends `cwd` on the shell events and `workspace_roots` on the
        # others; keying on `cwd` alone would leave a developer's file edits
        # and prompts braided into one shared trail.
        import importlib

        module = importlib.import_module("waxseal.integrations.cursor")
        event = {
            "hook_event_name": "beforeSubmitPrompt",
            "prompt": "hello",
            "workspace_roots": [PROJECT, "/work/other"],
        }
        assert self.drive(monkeypatch, module, event, tmp_path) == 0
        assert (routed_dir("cursor", tmp_path) / "trail.00000.jsonl").exists()
        assert not (
            routed_dir("cursor", tmp_path, "/work/other") / "trail.00000.jsonl"
        ).exists()

    def test_cursor_prefers_cwd_over_workspace_roots(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        import importlib

        module = importlib.import_module("waxseal.integrations.cursor")
        event = {
            "hook_event_name": "beforeShellExecution",
            "command": "ls",
            "cwd": PROJECT,
            "workspace_roots": ["/work/other"],
        }
        self.drive(monkeypatch, module, event, tmp_path)
        assert (routed_dir("cursor", tmp_path) / "trail.00000.jsonl").exists()

    @pytest.mark.parametrize(
        "roots", [[], [""], [17], "not-a-list"], ids=["empty", "blank", "nonstr", "notlist"]
    )
    def test_cursor_unusable_workspace_roots_fall_back_to_the_shared_trail(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
        roots: object,
    ) -> None:
        import importlib

        module = importlib.import_module("waxseal.integrations.cursor")
        event = {
            "hook_event_name": "beforeShellExecution",
            "command": "ls",
            "workspace_roots": roots,
        }
        assert self.drive(monkeypatch, module, event, tmp_path) == 0
        assert "cannot route per project" in capsys.readouterr().err

    def test_codex_home_relocates_the_routed_trail(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        import importlib
        import io

        module = importlib.import_module("waxseal.integrations.codex")
        monkeypatch.delenv("WAXSEAL_TRAIL", raising=False)
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("CODEX_HOME", str(tmp_path / "relocated"))
        monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(event_for("codex"))))
        assert module.main() == 0
        assert (
            tmp_path / "relocated" / "waxseal" / "trails"
            / project_slug(PROJECT) / "trail.00000.jsonl"
        ).exists()

    def test_an_unopenable_trail_records_its_drop_beside_the_active_segment(
        self,
        monkeypatch: pytest.MonkeyPatch,
        hook_module,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        module, name = hook_module
        # One append first, so there IS an active segment to record against.
        self.drive(monkeypatch, module, event_for(name), tmp_path)
        segment = routed_dir(name, tmp_path) / "trail.00000.jsonl"

        def boom(*a: object, **kw: object) -> None:
            raise RuntimeError("backend gone")

        monkeypatch.setattr(AuditLog, "open", staticmethod(boom))
        assert self.drive(monkeypatch, module, event_for(name), tmp_path) == 0
        assert capsys.readouterr().out == ""
        assert segment.with_name(segment.name + ".drops").exists()


class TestDropsDuringRotation:
    @pytest.fixture(params=HOOK_NAMES)
    def hook_module(self, request: pytest.FixtureRequest):
        import importlib

        return importlib.import_module(f"waxseal.integrations.{request.param}"), request.param

    def test_a_drop_during_rotation_lands_in_the_new_segments_sidecar(
        self,
        monkeypatch: pytest.MonkeyPatch,
        hook_module,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        # The event that TRIGGERS a rotation still has to be accounted for if
        # it is then lost: its `.drops` record belongs beside the NEW segment,
        # the one the writer was actually pointed at.
        import io

        module, name = hook_module
        monkeypatch.delenv("WAXSEAL_TRAIL", raising=False)
        monkeypatch.delenv("CODEX_HOME", raising=False)
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(event_for(name))))
        module.main()

        segment = routed_dir(name, tmp_path) / "trail.00000.jsonl"
        segment.write_bytes(b"\n" * DEFAULT_MAX_SEGMENT_BYTES + segment.read_bytes())

        real_append = AuditLog.append

        def append_unless_hook_event(self: AuditLog, *, payload: object, payload_type: str):
            # The genesis rotation binding must still get through; only the
            # hook's own event is lost, which is the case under test.
            if payload_type == module.PAYLOAD_TYPE:
                raise OSError("disk full")
            return real_append(self, payload=payload, payload_type=payload_type)

        monkeypatch.setattr(AuditLog, "append", append_unless_hook_event)
        monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(event_for(name))))
        assert module.main() == 0
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "dropped write" in captured.err

        new = routed_dir(name, tmp_path) / "trail.00001.jsonl"
        assert new.exists()
        assert new.with_name(new.name + ".drops").exists()
        assert not segment.with_name(segment.name + ".drops").exists()
