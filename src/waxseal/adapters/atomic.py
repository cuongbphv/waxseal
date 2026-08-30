"""Atomic file replacement: the single owner of os.replace in this codebase
(enforced by tests/architecture/test_invariants.py). A crash mid-write must
never leave a half-written file where a whole one is load-bearing (the seal
keyfile: a torn key would brick every future seal)."""

from __future__ import annotations

import contextlib
import os
import tempfile
from pathlib import Path


def atomic_write_bytes(path: Path, data: bytes, *, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}-")
    try:
        try:
            os.write(fd, data)
        finally:
            os.close(fd)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
