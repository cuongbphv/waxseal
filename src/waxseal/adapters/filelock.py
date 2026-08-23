"""Cross-platform advisory file lock.

Guards the read-tail + append critical section for file-based backends.
POSIX: fcntl.flock. Windows: msvcrt.locking on the first byte. The lock is a
separate ``<path>.lock`` file so readers never contend with the data file.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path


@contextmanager
def file_lock(target: Path) -> Iterator[None]:
    lock_path = target.with_name(target.name + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        if sys.platform == "win32":  # pragma: no cover - exercised on the windows-latest CI job
            import msvcrt

            msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
            try:
                yield
            finally:
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        else:  # pragma: no cover - exercised on the ubuntu-latest CI job
            import fcntl

            fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)
