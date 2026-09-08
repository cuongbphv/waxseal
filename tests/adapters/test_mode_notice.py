"""S1: labelled notice when a local trail or sealkey is group/world readable.

Rule 6: fail-open must be labelled. This build will not chmod the operator's
file, and it will not change an exit code. A 0o644 trail is still opened;
stderr says so. A 0o600 trail is silent. Windows has no POSIX mode bits that
mean the same thing, so the notice is skipped there the way filelock.py
skips flock.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from waxseal.adapters.attest import FileAttestor
from waxseal.log import AuditLog

PT = "application/vnd.test.event+json"

# Only the chmod-driven end-to-end tests skip on Windows: os.chmod cannot set
# POSIX group/other bits there. The mode -> notice logic itself is tested
# below on every platform, so the module's body stays covered on the
# windows-latest job too (the first Windows run of 0.1.6 failed the 100%
# floor on exactly these lines, with every test green).
posix_modes_only = pytest.mark.skipif(
    sys.platform == "win32",
    reason=(
        "UNMEASURED: POSIX file modes are not a Windows fact; the notice is "
        "skipped with a label on win32, matching adapters/filelock.py"
    ),
)


@posix_modes_only
def test_a_world_readable_trail_prints_a_notice_and_still_opens(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "trail.jsonl"
    log = AuditLog.open(path)
    log.append(payload={"i": 0}, payload_type=PT)
    os.chmod(path, 0o644)
    capsys.readouterr()

    opened = AuditLog.open(path)
    err = capsys.readouterr().err
    assert "notice:" in err
    assert str(path) in err
    assert opened.verify().ok


@posix_modes_only
def test_a_0600_trail_is_silent(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "trail.jsonl"
    log = AuditLog.open(path)
    log.append(payload={"i": 0}, payload_type=PT)
    os.chmod(path, 0o600)
    capsys.readouterr()

    AuditLog.open(path)
    assert capsys.readouterr().err == ""


@posix_modes_only
def test_a_world_readable_sealkey_prints_a_notice(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "trail.jsonl"
    attestor = FileAttestor(path, initial_key=b"\x01" * 32)
    attestor.attest(0, "a" * 64)
    key_path = path.with_name(path.name + ".sealkey")
    os.chmod(key_path, 0o644)
    capsys.readouterr()

    FileAttestor(path, initial_key=b"\x01" * 32)
    err = capsys.readouterr().err
    assert "notice:" in err
    assert str(key_path) in err


def _stat_with_mode(mode: int) -> os.stat_result:
    return os.stat_result((mode, 0, 0, 0, 0, 0, 0, 0, 0, 0))


class TestThePosixBodyOnEveryPlatform:
    """`_posix_mode_notice` is the stat + format step behind the win32 gate.

    Called directly, it runs on Windows too: a stat_result carries st_mode
    everywhere, only its meaning is POSIX. That is what keeps these lines
    inside the coverage floor on the windows-latest job.
    """

    def test_a_stat_error_is_silent(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from waxseal.adapters.mode_notice import _posix_mode_notice

        path = tmp_path / "missing.jsonl"
        real_stat = Path.stat

        def boom(self: Path, *, follow_symlinks: bool = True) -> os.stat_result:
            if self == path:
                raise OSError("UNMEASURED")
            return real_stat(self, follow_symlinks=follow_symlinks)

        monkeypatch.setattr(Path, "stat", boom)
        _posix_mode_notice(path)
        assert capsys.readouterr().err == ""

    def test_group_or_world_bits_print_the_mode(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from waxseal.adapters.mode_notice import _posix_mode_notice

        path = tmp_path / "trail.jsonl"
        monkeypatch.setattr(Path, "stat", lambda self, **_: _stat_with_mode(0o100644))
        _posix_mode_notice(path)
        err = capsys.readouterr().err
        assert "notice:" in err and str(path) in err and "0644" in err

    def test_owner_only_bits_are_silent(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from waxseal.adapters.mode_notice import _posix_mode_notice

        monkeypatch.setattr(Path, "stat", lambda self, **_: _stat_with_mode(0o100600))
        _posix_mode_notice(tmp_path / "trail.jsonl")
        assert capsys.readouterr().err == ""
