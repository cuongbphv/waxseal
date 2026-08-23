"""atomic_write_bytes — the single owner of os.replace in this codebase.

The failure it exists to prevent is a torn seal keyfile: half a key bricks
every future seal on that trail, and there is no recovery. So the two things
tested here are that the destination is never partially written, and that a
failure does not leave the temporary file behind — a directory slowly filling
with `.trail.jsonl.sealkey-*` files is how a disk-full outage starts.
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import pytest

from waxseal.adapters.atomic import atomic_write_bytes


class TestHappyPath:
    def test_writes_the_bytes(self, tmp_path: Path) -> None:
        target = tmp_path / "keyfile"
        atomic_write_bytes(target, b"secret")
        assert target.read_bytes() == b"secret"

    def test_replaces_an_existing_file_whole(self, tmp_path: Path) -> None:
        target = tmp_path / "keyfile"
        target.write_bytes(b"old value that is much longer")
        atomic_write_bytes(target, b"new")
        assert target.read_bytes() == b"new"

    def test_creates_missing_parent_directories(self, tmp_path: Path) -> None:
        target = tmp_path / "nested" / "deeper" / "keyfile"
        atomic_write_bytes(target, b"x")
        assert target.read_bytes() == b"x"

    def test_the_default_mode_is_owner_only(self, tmp_path: Path) -> None:
        if sys.platform == "win32":
            pytest.skip("POSIX permission bits")
        target = tmp_path / "keyfile"
        atomic_write_bytes(target, b"x")
        assert stat.S_IMODE(target.stat().st_mode) & 0o077 == 0

    def test_leaves_no_temporary_file_behind(self, tmp_path: Path) -> None:
        target = tmp_path / "keyfile"
        atomic_write_bytes(target, b"x")
        assert [p.name for p in tmp_path.iterdir()] == ["keyfile"]


class TestFailureCleanup:
    def failing_at(self, monkeypatch: pytest.MonkeyPatch, name: str) -> None:
        def explode(*args: object, **kwargs: object) -> object:
            raise OSError(f"{name} failed")

        monkeypatch.setattr(os, name, explode)

    @pytest.mark.parametrize("step", ["write", "chmod", "replace"])
    def test_a_failure_at_any_step_removes_the_temporary_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, step: str
    ) -> None:
        target = tmp_path / "keyfile"
        self.failing_at(monkeypatch, step)
        with pytest.raises(OSError, match=f"{step} failed"):
            atomic_write_bytes(target, b"x")
        assert list(tmp_path.iterdir()) == []

    def test_the_destination_is_untouched_when_the_write_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The whole point: a caller that crashes mid-write still finds the
        # previous key intact, not a truncated one.
        target = tmp_path / "keyfile"
        target.write_bytes(b"the good key")
        self.failing_at(monkeypatch, "replace")
        with pytest.raises(OSError):
            atomic_write_bytes(target, b"partial")
        assert target.read_bytes() == b"the good key"

    def test_cleanup_survives_a_temporary_file_that_is_already_gone(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The cleanup is best-effort by design: raising from the handler would
        # replace the real error with a bookkeeping one.
        target = tmp_path / "keyfile"
        real_unlink = os.unlink

        def unlink_twice(path: str | Path) -> None:
            real_unlink(path)
            real_unlink(path)  # second call raises FileNotFoundError

        monkeypatch.setattr(os, "replace", lambda *a, **k: (_ for _ in ()).throw(OSError("no")))
        monkeypatch.setattr(os, "unlink", unlink_twice)
        with pytest.raises(OSError, match="no"):
            atomic_write_bytes(target, b"x")
        assert list(tmp_path.iterdir()) == []

    def test_a_base_exception_also_cleans_up(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # `except BaseException`, not `except Exception`: a KeyboardInterrupt
        # or a timeout landing between mkstemp and replace must not leak the
        # temporary file either.
        target = tmp_path / "keyfile"

        def interrupt(*args: object, **kwargs: object) -> object:
            raise KeyboardInterrupt

        monkeypatch.setattr(os, "replace", interrupt)
        with pytest.raises(KeyboardInterrupt):
            atomic_write_bytes(target, b"x")
        assert list(tmp_path.iterdir()) == []
