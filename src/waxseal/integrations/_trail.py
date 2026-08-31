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
from pathlib import Path
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
       are absent, because those defaults reach into a host's config module
       or ``Path.home()`` and may raise or cost real work an operator had
       already overridden.

    The env value is taken verbatim while ``explicit`` gets ``expanduser()``.
    That asymmetry is deliberate, not an oversight: the four modules that
    already read this variable have always taken it verbatim, and widening
    who reads a variable must not change what a value already deployed
    means. (A shell expands ``~`` before the process is started, so an
    operator setting it from a shell sees no difference either way.)
    """
    if explicit is not None:
        return Path(explicit).expanduser()
    env = env_trail()
    if env is not None:
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
