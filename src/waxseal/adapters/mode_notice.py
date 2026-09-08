"""Label a local trail or sidecar whose POSIX mode is looser than 0o600.

Creating at 0o600 only covers files THIS build writes. A trail or sealkey
that already existed under a looser umask stays world-readable: this
library will not chmod the operator's file (it is theirs) and will not
change an exit code. Rule 6: fail-open must be labelled. Windows has no
POSIX group/other bits that mean the same thing, so this is skipped there
the way filelock.py skips flock.
"""

from __future__ import annotations

import sys
from pathlib import Path


def notice_if_group_or_world_readable(path: Path) -> None:
    if sys.platform == "win32":  # pragma: no cover - exercised on the windows-latest CI job
        return
    # Same two-platform pragma pair as adapters/filelock.py: each line names the
    # CI job that reaches it, so neither job can read the other's line as a gap.
    _posix_mode_notice(path)  # pragma: no cover - exercised on the ubuntu-latest CI job


def _posix_mode_notice(path: Path) -> None:
    """The stat + format step, kept apart from the platform gate on purpose.

    Behind the gate alone, these lines ran on no Windows job and the 100%
    floor failed there with every test green (first Windows run of 0.1.6). A
    stat_result carries st_mode on every platform; only its meaning is POSIX,
    so the tests call this directly and the gate above stays the one line
    that is platform-specific.
    """
    try:
        mode = path.stat().st_mode
    except OSError:
        return
    if mode & 0o077 == 0:
        return
    print(
        f"notice: {path} is group- or world-readable "
        f"(mode {mode & 0o777:04o}); this build did not change the mode",
        file=sys.stderr,
    )
