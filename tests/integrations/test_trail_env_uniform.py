"""`WAXSEAL_TRAIL` means the same thing in every integration.

Before 0.1.5 only 4 of the 9 integration modules read `WAXSEAL_TRAIL`
(claude_code, codex, cursor, openclaw). The other five silently ignored it,
which is the worst possible shape for an audit tool: an operator who sets the
variable, restarts the host and then runs `waxseal verify` against the path
they named finds an empty or absent trail. That looks exactly like a
truncated chain, and nothing in the output says the writer was never pointed
there at all.

Precedence is fixed and non-negotiable:

    explicit argument  >  WAXSEAL_TRAIL  >  the host's default location

An explicit argument always beats the environment, because a caller who
passed a path in code has said something more specific than an inherited
env var, and a deployment-wide `WAXSEAL_TRAIL` must not silently braid one
component's dedicated trail into the shared one.

The three hook/plugin families differ in which rungs they can HAVE:

- library-style (langchain, crewai, openai_agents) take a trail argument, so
  all three rungs exist;
- hermes / hermes_gateway are loaded by their host with no path argument, so
  there is no explicit-argument rung; their chain is
  `WAXSEAL_TRAIL` > `HERMES_HOME` > home fallback;
- the stdin hooks (claude_code, codex, cursor) and the openclaw runner are
  covered here as a REGRESSION guard: extracting the shared resolver must
  not have moved any path they already resolved.
"""

from __future__ import annotations

import ast
import importlib
import sys
import types
from pathlib import Path

import pytest

from waxseal.integrations import _trail


@pytest.fixture(autouse=True)
def clean_env(monkeypatch: pytest.MonkeyPatch):
    for name in ("WAXSEAL_TRAIL", "HERMES_HOME", "CODEX_HOME", "OPENCLAW_HOME"):
        monkeypatch.delenv(name, raising=False)


class TestSharedResolver:
    """One resolver, so the variable cannot come to mean two things."""

    def test_env_var_name_is_the_pre_existing_one(self) -> None:
        # No new variable was invented for this: the whole point is that the
        # five modules that ignored WAXSEAL_TRAIL start honouring the one
        # the other four already did.
        assert _trail.ENV_VAR == "WAXSEAL_TRAIL"

    def test_explicit_argument_beats_the_environment(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setenv("WAXSEAL_TRAIL", str(tmp_path / "from-env.jsonl"))
        resolved = _trail.resolve_trail(
            tmp_path / "explicit.jsonl", default=lambda: tmp_path / "fallback.jsonl"
        )
        assert resolved == tmp_path / "explicit.jsonl"

    def test_environment_beats_the_host_default(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setenv("WAXSEAL_TRAIL", str(tmp_path / "from-env.jsonl"))
        resolved = _trail.resolve_trail(default=lambda: tmp_path / "fallback.jsonl")
        assert resolved == tmp_path / "from-env.jsonl"

    def test_host_default_is_used_when_nothing_is_named(self, tmp_path: Path) -> None:
        resolved = _trail.resolve_trail(default=lambda: tmp_path / "fallback.jsonl")
        assert resolved == tmp_path / "fallback.jsonl"

    def test_an_empty_env_var_is_not_a_path(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        # `WAXSEAL_TRAIL=` in a unit file or compose file is an unset
        # variable, not a request to write to Path(""), which would resolve
        # to the process's cwd and put the trail somewhere nobody named.
        monkeypatch.setenv("WAXSEAL_TRAIL", "")
        assert _trail.resolve_trail(default=lambda: tmp_path / "fallback.jsonl") == (
            tmp_path / "fallback.jsonl"
        )
        assert _trail.env_trail() is None

    def test_an_explicit_string_argument_expands_a_tilde(self, tmp_path: Path) -> None:
        # The library integrations document str defaults like
        # "~/.waxseal/langchain-trail.jsonl"; an unexpanded "~" would create
        # a directory literally named "~" under the cwd.
        resolved = _trail.resolve_trail("~/x.jsonl", default=lambda: tmp_path / "f.jsonl")
        assert resolved == Path.home() / "x.jsonl"

    def test_the_env_value_is_taken_verbatim(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        # Deliberately NOT expanded, because that is what the four modules
        # which already honoured this variable have always done, and this
        # release only widens who reads it — it does not change what a value
        # already in production means. (A shell expands "~" before the
        # process ever sees it, so the verbatim path is what an operator
        # setting it from a shell gets either way.)
        monkeypatch.setenv("WAXSEAL_TRAIL", "~/from-env.jsonl")
        assert _trail.resolve_trail(default=lambda: tmp_path / "f.jsonl") == Path(
            "~/from-env.jsonl"
        )

    def test_the_default_is_not_computed_when_it_is_not_needed(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        # The host defaults reach into hermes_cli / Path.home(); a resolver
        # that evaluated them eagerly would pay for (and could raise from) a
        # lookup the operator had already overridden.
        monkeypatch.setenv("WAXSEAL_TRAIL", str(tmp_path / "from-env.jsonl"))

        def explode() -> Path:
            raise AssertionError("the host default must stay unevaluated")

        assert _trail.resolve_trail(default=explode) == tmp_path / "from-env.jsonl"


# --------------------------------------------------------------------------
# library-style integrations: all three rungs
# --------------------------------------------------------------------------


@pytest.fixture()
def langchain(monkeypatch: pytest.MonkeyPatch):
    pkg = types.ModuleType("langchain_core")
    callbacks = types.ModuleType("langchain_core.callbacks")
    callbacks.BaseCallbackHandler = type("BaseCallbackHandler", (), {"raise_error": False})
    pkg.callbacks = callbacks
    monkeypatch.setitem(sys.modules, "langchain_core", pkg)
    monkeypatch.setitem(sys.modules, "langchain_core.callbacks", callbacks)
    name = "waxseal.integrations.langchain"
    sys.modules.pop(name, None)
    module = importlib.import_module(name)
    yield module.WaxsealCallbackHandler
    sys.modules.pop(name, None)


@pytest.fixture()
def crewai(monkeypatch: pytest.MonkeyPatch):
    class _Bus:
        def on(self, event_type: type):
            def decorator(fn):
                return fn

            return decorator

    bus = _Bus()

    class BaseEventListener:
        def __init__(self) -> None:
            self.setup_listeners(bus)

    events = types.ModuleType("crewai.events")
    events.BaseEventListener = BaseEventListener
    events.crewai_event_bus = bus
    for attr in (
        "ToolUsageStartedEvent", "ToolUsageFinishedEvent", "ToolUsageErrorEvent",
        "TaskStartedEvent", "TaskCompletedEvent", "TaskFailedEvent",
        "CrewKickoffStartedEvent", "CrewKickoffCompletedEvent", "CrewKickoffFailedEvent",
    ):
        setattr(events, attr, type(attr, (), {}))
    pkg = types.ModuleType("crewai")
    pkg.events = events
    monkeypatch.setitem(sys.modules, "crewai", pkg)
    monkeypatch.setitem(sys.modules, "crewai.events", events)
    name = "waxseal.integrations.crewai"
    sys.modules.pop(name, None)
    module = importlib.import_module(name)
    yield module.WaxsealEventListener
    sys.modules.pop(name, None)


@pytest.fixture()
def openai_agents(monkeypatch: pytest.MonkeyPatch):
    stub = types.ModuleType("agents")
    stub.RunHooks = type("RunHooks", (), {})
    monkeypatch.setitem(sys.modules, "agents", stub)
    name = "waxseal.integrations.openai_agents"
    sys.modules.pop(name, None)
    module = importlib.import_module(name)
    yield module.WaxsealRunHooks
    sys.modules.pop(name, None)


#: (fixture name, the documented default path each class falls back to)
LIBRARY_DEFAULTS = {
    "langchain": "~/.waxseal/langchain-trail.jsonl",
    "crewai": "~/.waxseal/crewai-trail.jsonl",
    "openai_agents": "~/.waxseal/openai-agents-trail.jsonl",
}


@pytest.fixture(params=sorted(LIBRARY_DEFAULTS))
def library_integration(request):
    cls = request.getfixturevalue(request.param)
    return cls, LIBRARY_DEFAULTS[request.param]


class TestLibraryIntegrationPrecedence:
    def test_explicit_trail_argument_beats_the_env_var(
        self, library_integration, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        cls, _ = library_integration
        monkeypatch.setenv("WAXSEAL_TRAIL", str(tmp_path / "from-env.jsonl"))
        assert cls(tmp_path / "explicit.jsonl")._trail == tmp_path / "explicit.jsonl"

    def test_env_var_is_honoured_when_no_argument_is_passed(
        self, library_integration, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        cls, _ = library_integration
        monkeypatch.setenv("WAXSEAL_TRAIL", str(tmp_path / "from-env.jsonl"))
        assert cls()._trail == tmp_path / "from-env.jsonl"

    def test_documented_default_survives_with_no_argument_and_no_env(
        self, library_integration
    ) -> None:
        cls, default = library_integration
        assert cls()._trail == Path(default).expanduser()

    def test_the_default_did_not_change_shape(self, library_integration) -> None:
        # The pre-0.1.5 signature carried the default as the parameter's own
        # value; it is now a None sentinel so that "caller passed nothing"
        # is distinguishable from "caller passed the default path" — the
        # only way an env rung can sit between them. The resolved path for a
        # caller who passes nothing must be unchanged.
        cls, default = library_integration
        assert cls()._trail == Path(default).expanduser()

    def test_a_string_argument_is_still_accepted_and_expanded(
        self, library_integration
    ) -> None:
        cls, _ = library_integration
        assert cls("~/given-as-str.jsonl")._trail == Path.home() / "given-as-str.jsonl"


# --------------------------------------------------------------------------
# hermes / hermes_gateway: no explicit-argument rung, so env > HERMES_HOME > home
# --------------------------------------------------------------------------


@pytest.fixture(params=["hermes", "hermes_gateway"])
def hermes_module(request):
    module = importlib.import_module(f"waxseal.integrations.{request.param}")
    module._logs.clear()
    return module


class TestHermesPrecedence:
    def test_env_var_beats_hermes_home(
        self, hermes_module, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hermes-home"))
        monkeypatch.setenv("WAXSEAL_TRAIL", str(tmp_path / "from-env.jsonl"))
        assert hermes_module._trail_path() == tmp_path / "from-env.jsonl"

    def test_hermes_home_beats_the_home_fallback(
        self, hermes_module, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hermes-home"))
        assert hermes_module._trail_path() == (
            tmp_path / "hermes-home" / "audit" / "trail.jsonl"
        )

    def test_home_env_beats_path_home_in_the_fallback(
        self, hermes_module, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        # waxseal-fg4.3. Both hermes modules resolved the bottom rung with a
        # bare Path.home(), which goes through ntpath on Windows and IGNORES
        # HOME: a plugin launched with HOME set (git-bash, WSL-style
        # wrappers, CI images) wrote the trail into one profile while
        # `waxseal verify` read the other, and the missing entries look
        # exactly like a truncated chain. The other integrations already
        # went through _trail.home_base(); these two did not.
        monkeypatch.setenv("HOME", str(tmp_path / "posix-home"))
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path / "windows"))
        assert hermes_module._trail_path() == (
            tmp_path / "posix-home" / ".hermes" / "audit" / "trail.jsonl"
        )

    def test_path_home_is_the_fallback_when_no_home_env(
        self, hermes_module, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        # Same coverage the Path.home monkeypatch used to carry, now stated
        # against the corrected rule: Path.home() is consulted only when
        # there is no HOME at all.
        monkeypatch.delenv("HOME", raising=False)
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path / "profile"))
        assert hermes_module._trail_path() == (
            tmp_path / "profile" / ".hermes" / "audit" / "trail.jsonl"
        )

    def test_the_env_var_actually_moves_the_written_trail(
        self, hermes_module, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        # Resolving the path is not the claim; writing there is. Without
        # this the module could honour the variable in _trail_path() and
        # still open a log somewhere else.
        trail = tmp_path / "moved" / "trail.jsonl"
        monkeypatch.setenv("WAXSEAL_TRAIL", str(trail))
        monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hermes-home"))
        if hasattr(hermes_module, "handle"):
            hermes_module.handle("session:start", {"session_id": "s-1"})
        else:
            hermes_module.on_pre_tool_call(tool_name="shell", args={"cmd": "ls"})
        assert trail.exists()
        assert not (tmp_path / "hermes-home").exists()

    def test_a_drop_is_recorded_beside_the_env_named_trail_not_the_default(
        self, hermes_module, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        # Fail-open must stay labelled AT THE PATH THE OPERATOR NAMED. A
        # drop filed next to the host default would be invisible to anyone
        # looking where they pointed the writer (rule 6).
        blocked = tmp_path / "blocked"
        blocked.write_text("a file where the trail directory should be")
        monkeypatch.setenv("WAXSEAL_TRAIL", str(blocked / "trail.jsonl"))
        monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hermes-home"))
        if hasattr(hermes_module, "handle"):
            hermes_module.handle("session:start", {"session_id": "s-1"})
        else:
            hermes_module.on_pre_tool_call(tool_name="shell", args={"cmd": "ls"})
        assert not (tmp_path / "hermes-home").exists()


# --------------------------------------------------------------------------
# regression: the four modules that already honoured the variable
# --------------------------------------------------------------------------


#: module -> (host directory, sub-directory, routes-per-project?)
#: 0.1.5 routes the three stdin hooks' DEFAULT per project, so their expected
#: tail gains `trails/<slug>/trail.00000.jsonl`. Every rung ABOVE the default
#: is what this class guards, and none of them moved.
ALREADY_HONOURING = {
    "waxseal.integrations.claude_code": (".claude", "waxseal", True),
    "waxseal.integrations.codex": (".codex", "waxseal", True),
    "waxseal.integrations.cursor": (".cursor", "waxseal", True),
    "waxseal.integrations.openclaw": (".openclaw", "audit", False),
}

_ROUTING_EVENT = {"hook_event_name": "PreToolUse", "cwd": "/work/project"}


@pytest.fixture(params=sorted(ALREADY_HONOURING))
def already_honouring(request):
    from waxseal.domain.segments import project_slug

    module = importlib.import_module(request.param)
    host_dir, sub, routed = ALREADY_HONOURING[request.param]
    raw = getattr(module, "_trail_path", None) or module.resolve_trail
    if not routed:
        return raw, (host_dir, sub), Path("trail.jsonl")
    tail = Path("trails") / project_slug("/work/project") / "trail.00000.jsonl"
    return (lambda: raw(_ROUTING_EVENT)), (host_dir, sub), tail


class TestNoRegressionForTheOriginalFour:
    def test_env_var_still_wins(
        self, already_honouring, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        resolve, _, _tail = already_honouring
        monkeypatch.setenv("WAXSEAL_TRAIL", str(tmp_path / "from-env.jsonl"))
        monkeypatch.setenv("HOME", str(tmp_path / "posix-home"))
        assert resolve() == tmp_path / "from-env.jsonl"

    def test_default_location_is_unchanged(
        self, already_honouring, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        resolve, (host_dir, sub), tail = already_honouring
        monkeypatch.setenv("HOME", str(tmp_path / "posix-home"))
        assert resolve() == tmp_path / "posix-home" / host_dir / sub / tail

    def test_home_env_still_beats_path_home(
        self, already_honouring, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        # The Windows ntpath split test_trail_path_defaults.py documents:
        # extracting a shared resolver must not have moved this rung.
        resolve, (host_dir, sub), tail = already_honouring
        monkeypatch.setenv("HOME", str(tmp_path / "posix-home"))
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path / "windows"))
        assert resolve() == tmp_path / "posix-home" / host_dir / sub / tail


class TestEveryIntegrationHonoursTheVariable:
    """The census this bead closes: 4 of 9 became 9 of 9."""

    MODULES = (
        "waxseal.integrations.claude_code",
        "waxseal.integrations.codex",
        "waxseal.integrations.crewai",
        "waxseal.integrations.cursor",
        "waxseal.integrations.hermes",
        "waxseal.integrations.hermes_gateway",
        "waxseal.integrations.langchain",
        "waxseal.integrations.openai_agents",
        "waxseal.integrations.openclaw",
    )

    def test_no_integration_reads_the_variable_for_itself(self) -> None:
        # A module holding its own os.environ lookup could re-introduce a
        # private precedence order; _trail is the only reader, so there is
        # exactly one answer to "where does this integration write". Matched
        # on the quoted NAME, so prose mentioning the variable is fine and a
        # real lookup is not.
        src = Path(_trail.__file__).parent
        offenders = [
            path.name
            for path in sorted(src.glob("*.py"))
            if path.name != "_trail.py" and '"WAXSEAL_TRAIL"' in path.read_text()
        ]
        assert offenders == []

    def test_no_integration_resolves_home_for_itself(self) -> None:
        # waxseal-fg4.3: home_base() landed in _trail.py during D3 and 7 of
        # the 9 modules were wired to it, while both hermes modules kept a
        # bare Path.home(). That is the Windows/ntpath profile split — the
        # writer seals into one profile, `waxseal verify` reads another, and
        # the absent entries are indistinguishable from a truncated chain.
        # Matched on the parsed CALL, not the source text, so prose naming
        # the rule stays legal and a real lookup does not; the divergence is
        # DETECTED next time rather than merely unlikely.
        #
        # waxseal-fg4.19 widened this to the private modules too. _install.py
        # was excluded on the grounds that it places shim files rather than
        # trails; that ground is gone, because a shim placed in the profile
        # the host does not read never loads and produces no trail at all.
        # _trail.py stays out because it IS the owner: home_base() is the one
        # place Path.home() is allowed to be called.
        src = Path(_trail.__file__).parent
        offenders = []
        for path in sorted(src.glob("*.py")):
            if path.name == "_trail.py":
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "home"
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "Path"
                ):
                    offenders.append(path.name)
                    break
        assert offenders == []

    def test_both_hermes_modules_resolve_the_same_home(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        # The two modules carry byte-identical resolvers; a fix applied to
        # one and not the other is how fg4.3 happened in the first place.
        monkeypatch.setenv("HOME", str(tmp_path / "posix-home"))
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path / "windows"))
        plugin = importlib.import_module("waxseal.integrations.hermes")
        gateway = importlib.import_module("waxseal.integrations.hermes_gateway")
        assert plugin._trail_path() == gateway._trail_path()

    def test_the_census_is_complete(self) -> None:
        src = Path(_trail.__file__).parent
        modules = {
            f"waxseal.integrations.{p.stem}"
            for p in src.glob("*.py")
            if not p.stem.startswith("_")
        }
        assert modules == set(self.MODULES)
