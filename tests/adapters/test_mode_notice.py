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

pytestmark = pytest.mark.skipif(
    sys.platform == "win32",
    reason=(
        "UNMEASURED: POSIX file modes are not a Windows fact; the notice is "
        "skipped with a label on win32, matching adapters/filelock.py"
    ),
)


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


def test_a_0600_trail_is_silent(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "trail.jsonl"
    log = AuditLog.open(path)
    log.append(payload={"i": 0}, payload_type=PT)
    os.chmod(path, 0o600)
    capsys.readouterr()

    AuditLog.open(path)
    assert capsys.readouterr().err == ""


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


def test_a_stat_error_is_silent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "missing.jsonl"
    real_stat = Path.stat

    def boom(self: Path, *args: object, **kwargs: object) -> object:
        if self == path:
            raise OSError("UNMEASURED")
        return real_stat(self, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", boom)
    from waxseal.adapters.mode_notice import notice_if_group_or_world_readable

    notice_if_group_or_world_readable(path)
