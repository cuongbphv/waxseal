"""The single place `WAXSEAL_TRAIL` is read.

Until 0.1.5 only four of the nine integration modules honoured this variable
and each spelled the lookup out for itself. The other five ignored it, which
is the worst failure shape an audit tool has: the operator sets the variable,
restarts the host, runs `waxseal verify` on the path they named, and finds
nothing there. An absent trail and a truncated one look identical, and no
output says the writer was never pointed at that path in the first place.

The variable is the pre-existing one. Nothing here invents a second name, and
there is no config flag: an audit sink with two ways to be aimed has two ways
to be aimed at the wrong place. `routed_trail` below is the 0.1.5 per-project
DEFAULT that sits at the bottom of that precedence chain — routing changes
where the default points, never how the precedence works.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Callable
from pathlib import Path, PurePosixPath
from typing import Final

from waxseal.domain.segments import project_slug, segment_name

ENV_VAR: Final = "WAXSEAL_TRAIL"

#: Sub-directory of a host's waxseal home that holds the per-project trails.
#: The root above it is FIXED per host: there is no `WAXSEAL_TRAIL_ROOT` and
#: no new environment variable (owner decision, 31/08/2026).
TRAILS_DIRNAME: Final = "trails"

#: The pre-0.1.5 shared trail's file name, kept as the labelled fallback for
#: an event with no project key. It is never migrated and never force-sealed:
#: routed appends simply stop arriving, and it keeps verifying forever with
#: plain `waxseal verify`.
SHARED_TRAIL_NAME: Final = "trail.jsonl"


def env_trail() -> str | None:
    """The operator's `WAXSEAL_TRAIL`, or ``None`` when unset.

    An empty value (`WAXSEAL_TRAIL=` in a unit file, a compose file, a CI
    matrix that left a cell blank) is unset, not a request to write to
    ``Path("")`` — which resolves to the process's cwd and would strand the
    trail somewhere nobody named.

    Returned as ``str`` rather than ``Path`` because a value naming a chain
    SERVER has to keep its URL scheme intact: ``Path("http://host")``
    collapses the ``//`` and the target silently becomes a local file called
    ``http:``.

    RAW on purpose: this is the reader, not the policy. `resolve_trail` is
    where the value becomes a filesystem path and is therefore where a
    leading ``~`` is refused (waxseal-fg4.4); a caller that only asks whether
    the value names a chain SERVER — `claude_code._trail_target` — needs the
    string as the operator wrote it and must not be made to pay for, or print,
    a path-shaped refusal twice.
    """
    return os.environ.get(ENV_VAR) or None


def resolve_trail(
    explicit: Path | str | None = None,
    *,
    default: Callable[[], Path],
) -> Path:
    """Where an integration writes. Precedence, in order:

    1. ``explicit`` — an argument the caller passed in code. It always beats
       the environment: a caller who named a path has said something more
       specific than an inherited variable, and a deployment-wide
       `WAXSEAL_TRAIL` must not braid one component's dedicated trail into
       the shared one behind the caller's back.
    2. `WAXSEAL_TRAIL`.
    3. ``default()`` — the host's own location, called ONLY if the first two
       are absent (or the env value is refused, below), because those defaults
       reach into a host's config module or ``Path.home()`` and may raise or
       cost real work an operator had already overridden.

    The env value is taken verbatim while ``explicit`` gets ``expanduser()``.
    That asymmetry is deliberate, not an oversight: the four modules that
    already read this variable have always taken it verbatim, and widening
    who reads a variable must not change what a value already deployed
    means. (A shell expands ``~`` before the process is started, so an
    operator setting it from a shell sees no difference either way.)

    QUALIFIED, owner decision 01/09/2026 (waxseal-fg4.4). Verbatim is still
    the rule — nothing here expands anything — but a value whose path BEGINS
    with ``~`` is refused rather than used, because verbatim is exactly what
    makes it wrong: no shell runs between a systemd unit, a compose file or a
    config template and this process, so the tilde survives and the writer
    creates a directory literally named ``~`` under its cwd. The refusal
    falls back to ``default()`` and says so on stderr (rule 6: a degraded
    resolution is labelled, never silent). Falling back rather than raising is
    deliberate: a trail that stops writing is the failure this library exists
    to make visible, and the host default is a location `waxseal verify`
    already knows how to find, whereas a ``~`` directory is not. Expanding the
    env value instead was rejected: a deployment already running with a
    literal ``~`` directory would have its old trail stay put while new
    appends went elsewhere, which looks exactly like a truncated chain.
    """
    if explicit is not None:
        return Path(explicit).expanduser()
    env = env_trail()
    if env is not None:
        if env.startswith("~"):
            fallback = default()
            print(
                f"[waxseal-audit] {ENV_VAR}={env!r} is REFUSED: the value "
                "starts with '~' and is never expanded, so it would write to "
                "a directory literally named '~' under the current working "
                "directory instead of a home directory. Fix: set "
                f"{ENV_VAR} to an absolute path — there is no shell to expand "
                "a tilde in a systemd unit, a compose file or a config "
                f"template. Writing to the host default {fallback} instead; "
                "no existing trail was moved or migrated.",
                file=sys.stderr,
            )
            return fallback
        return Path(env)
    return default()


def home_base() -> Path:
    """The home directory an integration nests its default trail under.

    `HOME` before ``Path.home()``: on Windows ``Path.home()`` goes through
    ntpath, which resolves ``~`` from USERPROFILE and IGNORES HOME. A host
    that launches a hook with HOME set (git-bash, WSL-style wrappers, CI
    images) would otherwise write the trail into a different profile than
    the one the operator later runs `waxseal verify` against, and the
    missing entries look exactly like a truncated chain.
    """
    home = os.environ.get("HOME")
    return Path(home) if home else Path.home()


def hermes_home() -> Path:
    """Where hermes keeps its state: HERMES_HOME, else hermes_cli, else ~/.hermes.

    Re-exported as `_hermes_home` on both hermes host modules so the existing
    fail-open tests keep importing that name. The two copies used to drift.
    """
    env = os.environ.get("HERMES_HOME")
    if env:
        return Path(env)
    try:
        # Inside a hermes process this is the authoritative resolver.
        from hermes_cli.config import get_hermes_home

        return Path(get_hermes_home())
    except Exception:
        # home_base(), not Path.home(): the last rung has to honour HOME
        # first or a host that sets it writes into a different Windows
        # profile than `waxseal verify` reads (waxseal-fg4.3; the rule and
        # the ntpath split are documented on home_base itself).
        return home_base() / ".hermes"


def home_default(documented: str) -> Path:
    """A library integration's documented ``~/...`` default, under `home_base()`.

    waxseal-fg4.20. The three library-style integrations spelled this rung as
    ``Path(DEFAULT_TRAIL).expanduser()``. On Windows that runs
    ``ntpath.expanduser``, whose source consults USERPROFILE (then
    HOMEDRIVE/HOMEPATH) and never reads HOME at all — so a host launched with
    HOME set (git-bash, WSL-style wrappers, CI images) sealed the trail into
    one profile while `waxseal verify` read the other, and the absent entries
    are indistinguishable from a truncated chain. That is the split fg4.3
    fixed for hermes and fg4.19 for install; these three were the holdouts.

    ``documented`` is the module's own POSIX-spelled ``DEFAULT_TRAIL``, so it
    stays the single source of truth for the path the docstrings advertise,
    and is parsed as the POSIX string it is rather than through whatever
    separator the host happens to use.
    """
    return home_base() / PurePosixPath(documented).relative_to("~")


def routed_trail(root: Path, cwd: str | None) -> Path:
    """The per-project default: ``<root>/trails/<slug>/trail.00000.jsonl``.

    ``root`` is the host's own waxseal home (``~/.claude/waxseal``,
    ``$CODEX_HOME/waxseal``, ``~/.cursor/waxseal``) so each host keeps the
    directory its own docs and its own relocation variable already name.

    ``cwd`` is the project key, taken from the hook event. ``session_id`` was
    rejected: it changes every session, so it would spawn thousands of trails
    nobody ever verifies.

    Prints ONE labelled stderr line on the first routed append for a project,
    naming where writes moved. Keyed off the routed segment not existing yet,
    because a hook is a fresh process every time and nothing in memory can
    remember a "first". With no ``cwd`` at all it falls back to the shared
    trail and says so on EVERY append (rule 6: a degraded router is labelled,
    never silent — and unlike the routing notice, this one is a live
    degradation, not a one-off migration).
    """
    if not cwd:
        shared = root / SHARED_TRAIL_NAME
        print(
            "[waxseal-audit] hook event carries no cwd — cannot route per "
            f"project; writing to the shared trail {shared}",
            file=sys.stderr,
        )
        return shared
    path = root / TRAILS_DIRNAME / project_slug(cwd) / segment_name("trail", 0)
    if not path.exists():
        print(
            f"[waxseal-audit] trail routed per project: {cwd} -> {path} "
            f"(writes moved here from {root / SHARED_TRAIL_NAME}, which is "
            "not migrated and still verifies with `waxseal verify`)",
            file=sys.stderr,
        )
    return path
