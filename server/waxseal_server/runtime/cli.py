"""Read surfaces run through the waxseal CLI, never through a re-implementation.

The plan splits the server in two: the write path uses waxseal as a library, and
every read/verify surface shells out to the CLI. The CLI's exit codes are a
documented, stable contract (0 intact / 1 broken / 2 unverifiable / 3 nothing
read), and a server that recomputed verdicts of its own would be a second
verifier for operators to reconcile.

The whole job of this module is to carry those four codes upward without
collapsing any of them, and to refuse to invent a fifth. Two ways that could go
wrong are handled explicitly rather than by luck:

* argparse *also* exits 2. A subcommand this build does not have, or a flag the
  server got wrong, would arrive looking exactly like "unverifiable" — a verdict
  nobody computed. Missing capability and usage error are their own states.
* exit 3 means nothing was read. Rendering it as "broken" would report a tamper
  against a file that does not exist.

`sys.executable`, never a bare `python3`: an interpreter found on PATH is not
necessarily the one that can import waxseal, and the release this server ships
in exists partly because that exact mistake dropped a whole trail on the
repository owner's machine (plan, Workstream D1).
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Final

from waxseal import Verdict
from waxseal_server.runtime.ledger import LEDGER_FLAGS

# Read-only by construction. `anchor` and `install` write, so they are not here
# and cannot be reached from an HTTP request even by name — CLAUDE.md rule 4
# ("verify reports, never repairs") applied to the server's own reach.
READ_ONLY_COMMANDS: Final[frozenset[str]] = frozenset(
    {
        "verify",
        "report",
        "inspect",
        "tail",
        "head",
        "checkpoint",
        "export-proof",
        "verify-proof",
        "consistency",
        "verify-handoff",
        "reconcile-tickets",
        "receipt",
        # Reads nothing at all — `cadence` takes only operator-supplied numbers
        # and opens no trail. It is here because "read-only" is the property this
        # set is about, and a command with no input to read is the strongest
        # case of it.
        "cadence",
        # Reads the chain's on-chain status. Read-only: `anchor` is what WRITES
        # to a ledger, and it is deliberately absent from this set.
        "ledger-status",
        # Planned but not in every build; `available()` decides at run time.
        "segments",
        "preflight",
    }
)

_CHOICES_RE: Final = re.compile(r"\{([a-z0-9,\-]+)\}")
_OUTCOME_CACHE_MAX: Final = 128
_CACHE_TTL_S: Final = 30.0
# Sidecars `verify`/`report` read next to a trail even when the path is not
# on argv. A stamp that only watched argv files would serve a stale "ok"
# after `.anchors` changed.
_TRAIL_SIDECAR_SUFFIXES: Final = (
    ".anchors",
    ".attest",
    ".drops",
    ".receipts",
    ".sealagg",
)
# Outcome depends on something the trail stamp cannot see. Caching a
# `live` reading after the writer went delinquent (or the RPC died) is
# the false-confidence collapse CLAUDE.md names.
_UNCACHED_COMMANDS: Final = frozenset({"ledger-status"})
# verify/report do not take these from the server today; if they ever
# do, a file stamp must not stand in for an RPC or witness reply. The set is
# the ledger module's own, so it cannot drift from what that module emits.
_NETWORK_FLAGS: Final = LEDGER_FLAGS

# Both spawns decode the child's output as UTF-8, so the child must write it:
# a child Python defaults to the platform locale (cp1252 on Windows), and the
# em dash in `waxseal --help` is a byte utf-8 decoding refuses - the parent
# would see None where it expected a verdict. Read by the child at startup,
# this wins over its locale on every platform.
_CHILD_ENV: Final = {**os.environ, "PYTHONIOENCODING": "utf-8"}

STATUS_BY_VERDICT: Final = {
    Verdict.OK: "ok",
    Verdict.BROKEN: "broken",
    Verdict.UNVERIFIABLE: "unverifiable",
}

_Stamp = tuple[str, int, int, int, int]
_OutcomeKey = tuple[str, tuple[str, ...], tuple[_Stamp, ...]]


def _stat_stamp(path: Path) -> _Stamp | None:
    try:
        st = path.stat()
    except OSError:
        return None
    # ctime+ino sit next to mtime+size because utime can restore
    # mtime after a same-size rewrite, and that rewrite is exactly
    # the writer verify must catch. The cache is a subprocess
    # budget, not a second verdict: anyone who can write the trail
    # is outside its threat model.
    return (
        str(path.resolve()),
        st.st_mtime_ns,
        st.st_size,
        st.st_ctime_ns,
        st.st_ino,
    )


def _directory_children(path: Path) -> list[Path]:
    try:
        children = list(path.iterdir())
    except OSError:
        return []
    out: list[Path] = []
    for child in children:
        try:
            if child.is_file() or child.is_dir():
                out.append(child)
        except OSError:
            continue
    return out


def _skips_outcome_cache(command: str, args: tuple[str, ...]) -> bool:
    if command in _UNCACHED_COMMANDS:
        return True
    # argparse takes `--rpc=URL` as well as `--rpc URL`; matching the bare
    # token alone let the joined form through to a file-stamped cache.
    return any(arg == flag or arg.startswith(flag + "=") for arg in args for flag in _NETWORK_FLAGS)


def _input_stamp(args: tuple[str, ...]) -> tuple[_Stamp, ...]:
    """Identity of every argv path that exists, plus trail sidecars.

    Missing paths are omitted: `verify` of an absent trail still runs the
    CLI (exit 3). Creating the file later is a different stamp, so a cached
    "absent" cannot mask a trail that now exists.
    """
    stamps: list[_Stamp] = []
    seen: set[str] = set()
    for arg in args:
        path = Path(arg)
        try:
            is_dir = path.is_dir()
            is_file = path.is_file()
        except OSError:
            continue
        if is_dir:
            # Directory mtime does not move when a child is edited (APFS,
            # ext4). `segments <dir>` would serve a stale ok if we only
            # stamped the directory inode.
            candidates = [path, *_directory_children(path)]
        elif is_file:
            candidates = [path]
            candidates.extend(
                path.with_name(path.name + suffix) for suffix in _TRAIL_SIDECAR_SUFFIXES
            )
        else:
            candidates = []
        for candidate in candidates:
            stamp = _stat_stamp(candidate)
            if stamp is None or stamp[0] in seen:
                continue
            stamps.append(stamp)
            seen.add(stamp[0])
    return tuple(stamps)


@dataclass(frozen=True, slots=True)
class CliOutcome:
    """One CLI invocation, reported without a verdict it did not produce.

    `verdict` is None whenever no verdict was computed: the trail was absent
    (exit 3), the subcommand is not in this build, or the invocation was a usage
    error. `status` names which of those it was, so the UI never has to guess
    from an exit code that means different things to different callers.
    """

    command: str
    argv: tuple[str, ...]
    exit_code: int | None
    verdict: Verdict | None
    status: str
    stdout: str
    stderr: str


class WaxsealCli:
    def __init__(
        self,
        *,
        python: str | None = None,
        timeout: float = 60.0,
        outcome_cache_size: int = _OUTCOME_CACHE_MAX,
        now_fn: Callable[[], float] | None = None,
    ) -> None:
        self._python = python or sys.executable
        self._timeout = timeout
        self._outcome_cache_size = outcome_cache_size
        self._now = now_fn or time.monotonic
        # Cached CliOutcome only. A miss still shells out — this is not a
        # second verifier (the CLI remains the sole verdict authority).
        # Value is (outcome, stored_at); TTL is a second layer over the
        # stamp so a forged mtime cannot keep an `ok` forever.
        self._outcomes: OrderedDict[_OutcomeKey, tuple[CliOutcome, float]] = OrderedDict()
        self._outcome_lock = threading.Lock()

    @lru_cache(maxsize=1)  # noqa: B019 - one instance per app; the CLI cannot change under it
    def available(self) -> frozenset[str]:
        """Subcommands this waxseal build actually offers.

        Parsed from `--help` rather than assumed, so a server running against an
        older or newer waxseal reports "unavailable" instead of mislabelling
        argparse's rejection as a verdict.
        """
        completed = subprocess.run(  # noqa: S603 - fixed argv, shell=False
            [self._python, "-m", "waxseal.cli", "--help"],
            capture_output=True,
            text=True,
            timeout=self._timeout,
            encoding="utf-8",
            env=_CHILD_ENV,
        )
        match = _CHOICES_RE.search(completed.stdout)
        if match is None:  # pragma: no cover - argparse always prints the metavar
            return frozenset()
        return frozenset(match.group(1).split(","))

    def run(self, command: str, *args: str) -> CliOutcome:
        if command not in READ_ONLY_COMMANDS:
            raise ValueError(
                f"{command!r} is not in the server's read-only command set; "
                "the server never invokes a waxseal command that writes"
            )
        argv = (self._python, "-m", "waxseal.cli", command, *args)
        if command not in self.available():
            return CliOutcome(
                command=command,
                argv=argv,
                exit_code=None,
                verdict=None,
                status="unavailable",
                stdout="",
                stderr=f"this waxseal build has no {command!r} subcommand",
            )
        key: _OutcomeKey | None = None
        if not _skips_outcome_cache(command, args):
            key = (command, args, _input_stamp(args))
            now = self._now()
            with self._outcome_lock:
                cached = self._outcomes.get(key)
                if cached is not None:
                    outcome, stored_at = cached
                    if now - stored_at <= _CACHE_TTL_S:
                        self._outcomes.move_to_end(key)
                        return outcome
                    del self._outcomes[key]
        completed = subprocess.run(  # noqa: S603 - list argv, shell=False, allowlisted command
            list(argv),
            capture_output=True,
            text=True,
            timeout=self._timeout,
            encoding="utf-8",
            env=_CHILD_ENV,
        )
        outcome = _classify(command, argv, completed.returncode, completed.stdout, completed.stderr)
        if key is not None:
            with self._outcome_lock:
                self._outcomes[key] = (outcome, self._now())
                self._outcomes.move_to_end(key)
                while len(self._outcomes) > self._outcome_cache_size:
                    self._outcomes.popitem(last=False)
        return outcome


def _classify(
    command: str, argv: tuple[str, ...], code: int, stdout: str, stderr: str
) -> CliOutcome:
    if code == 3:
        # "Nothing was read, nothing was created" — not a finding about content.
        return CliOutcome(command, argv, 3, None, "absent", stdout, stderr)
    if code == 2 and stderr.lstrip().startswith("usage:"):
        # argparse, not the verifier. A server bug must not wear a verdict.
        return CliOutcome(command, argv, 2, None, "usage_error", stdout, stderr)
    try:
        verdict = Verdict.from_exit_code(code)
    except ValueError:
        return CliOutcome(command, argv, code, None, "unexpected_exit", stdout, stderr)
    return CliOutcome(command, argv, code, verdict, STATUS_BY_VERDICT[verdict], stdout, stderr)
