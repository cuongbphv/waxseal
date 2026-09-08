"""Value shapes every integration's _sanitize must survive.

_sanitize is the last gate a host value passes before it is hashed, and the
shapes it does NOT special-case are exactly where a leak or a crash would
come from: a secret nested one level down in a list, or an object with no
JSON form whose repr() carries the key it was constructed with
(redact-before-hash has to hold on the repr path too, not only on the plain
string one).

Rule 5 also lives here: None must come back as None. A sanitizer that
folded it to 0 or "" would turn "the host did not send this field" into a
measured value on the chain.

crewai / langchain_core / agents are NOT test dependencies — the modules
under test need only the base-class NAMES at import time, so stubs are
injected the way the sibling test files do it.
"""

from __future__ import annotations

import importlib
import sys
import types
from collections.abc import Iterator

import pytest

from waxseal.adapters.redactors import REDACTED

SECRET = "sk-abcdef1234567890abcdef"

# Every integration that clips and redacts; they share one _sanitize body,
# so a shape that escapes one escapes all of them. Owner ruling 08/09/2026:
# AGT joins this list (both mappings already passed).
REDACTING_MODULES = [
    "waxseal.integrations.agt",
    "waxseal.integrations.claude_code",
    "waxseal.integrations.codex",
    "waxseal.integrations.crewai",
    "waxseal.integrations.cursor",
    "waxseal.integrations.hermes",
    "waxseal.integrations.langchain",
    "waxseal.integrations.openai_agents",
]

_CREWAI_EVENT_NAMES = (
    "CrewKickoffCompletedEvent",
    "CrewKickoffFailedEvent",
    "CrewKickoffStartedEvent",
    "TaskCompletedEvent",
    "TaskFailedEvent",
    "TaskStartedEvent",
    "ToolUsageErrorEvent",
    "ToolUsageFinishedEvent",
    "ToolUsageStartedEvent",
)


class _ClientWithKeyInRepr:
    """A host object whose repr leaks the key it was built with — the reason
    the catch-all branch redacts instead of writing str() straight out."""

    def __repr__(self) -> str:
        return f"<ApiClient key={SECRET}>"


def _stub_host_frameworks(monkeypatch: pytest.MonkeyPatch) -> None:
    # setattr(), not `events.BaseEventListener = ...`: types.ModuleType has no
    # declared attributes of its own, so a plain dot-assignment is exactly
    # the attr-defined error mypy exists to catch -- setattr is the same
    # runtime effect without pretending the fake module is statically typed.
    events = types.ModuleType("crewai.events")
    setattr(events, "BaseEventListener", type("BaseEventListener", (), {}))  # noqa: B010
    for name in _CREWAI_EVENT_NAMES:
        setattr(events, name, type(name, (), {}))
    crewai = types.ModuleType("crewai")
    setattr(crewai, "events", events)  # noqa: B010
    monkeypatch.setitem(sys.modules, "crewai", crewai)
    monkeypatch.setitem(sys.modules, "crewai.events", events)

    callbacks = types.ModuleType("langchain_core.callbacks")
    setattr(callbacks, "BaseCallbackHandler", type("BaseCallbackHandler", (), {}))  # noqa: B010
    langchain_core = types.ModuleType("langchain_core")
    setattr(langchain_core, "callbacks", callbacks)  # noqa: B010
    monkeypatch.setitem(sys.modules, "langchain_core", langchain_core)
    monkeypatch.setitem(sys.modules, "langchain_core.callbacks", callbacks)

    agents = types.ModuleType("agents")
    setattr(agents, "RunHooks", type("RunHooks", (), {}))  # noqa: B010
    monkeypatch.setitem(sys.modules, "agents", agents)


@pytest.fixture(params=REDACTING_MODULES)
def integration(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch
) -> Iterator[types.ModuleType]:
    _stub_host_frameworks(monkeypatch)
    sys.modules.pop(request.param, None)
    module = importlib.import_module(request.param)
    yield module
    sys.modules.pop(request.param, None)


def test_redacting_hosts_reexport_the_shared_sanitize(
    integration: types.ModuleType,
) -> None:
    from waxseal.integrations._sanitize import sanitize

    assert integration._sanitize is sanitize


class TestScalarsKeepTheirIdentity:
    def test_none_is_not_folded_to_zero_or_empty_string(
        self,
        integration: types.ModuleType,
    ) -> None:
        # Rule 5: None ≠ 0. "the host sent no value" and "the host sent 0"
        # must stay two different things once they are on the chain.
        assert integration._sanitize(None) is None
        assert integration._sanitize(0) == 0
        assert integration._sanitize(0) is not None

    def test_booleans_are_not_flattened_into_numbers(self, integration: types.ModuleType) -> None:
        # from_cache=False and from_cache=0 read the same to a careless
        # sanitizer and differently to anyone auditing the trail.
        assert integration._sanitize(False) is False
        assert integration._sanitize(True) is True

    def test_numbers_pass_through_unchanged(self, integration: types.ModuleType) -> None:
        assert integration._sanitize(12) == 12
        assert integration._sanitize(3.5) == 3.5


class TestSequencesAreWalkedNotStringified:
    def test_secret_nested_in_a_list_is_redacted(self, integration: types.ModuleType) -> None:
        # Redact-before-hash applies at every depth: an argv list is the
        # most ordinary place an agent puts an exported key.
        out = integration._sanitize(["bash", "-c", f"export OPENAI_API_KEY={SECRET}"])
        assert isinstance(out, list)
        assert SECRET not in str(out)
        assert REDACTED in out[2]

    def test_tuple_contents_are_walked_and_land_as_a_json_array(
        self,
        integration: types.ModuleType,
    ) -> None:
        # Without the sequence branch a tuple falls to the repr catch-all and
        # the whole argv becomes one opaque string in the payload.
        out = integration._sanitize(("bash", f"--token={SECRET}"))
        assert isinstance(out, list)
        assert out[0] == "bash"
        assert SECRET not in out[1]

    def test_nested_containers_are_walked_to_the_bottom(
        self,
        integration: types.ModuleType,
    ) -> None:
        out = integration._sanitize(
            {"steps": [{"cmd": f"curl -H 'Authorization: Bearer {SECRET}'"}]}
        )
        assert SECRET not in str(out)


class TestObjectsWithNoJsonForm:
    def test_repr_fallback_is_redacted_before_it_can_land(
        self,
        integration: types.ModuleType,
    ) -> None:
        out = integration._sanitize(_ClientWithKeyInRepr())
        assert SECRET not in out
        assert REDACTED in out

    def test_an_arbitrary_object_never_raises(self, integration: types.ModuleType) -> None:
        # The observer runs inside the host's call path; a TypeError here
        # would surface to the user as the host failing, not the trail.
        assert isinstance(integration._sanitize(object()), str)

    def test_oversized_repr_is_clipped_with_a_visible_marker(
        self, integration: types.ModuleType
    ) -> None:
        limit: int = integration.MAX_FIELD_CHARS

        class _Huge:
            def __repr__(self) -> str:
                return "z" * (limit + 500)

        # Silent truncation would read back as "that was the whole object".
        assert "truncated" in integration._sanitize(_Huge())


class TestHermesGatewaySanitize:
    """The gateway keeps a leaner _sanitize (no clip, no value redaction —
    AuditLog's own redactor covers it there), but the same shape rules apply."""

    def test_context_lists_are_walked_into_json_arrays(self) -> None:
        gw = importlib.import_module("waxseal.integrations.hermes_gateway")
        out = gw._sanitize(["step-1", ("step-2", object())])
        assert isinstance(out, list)
        assert out[0] == "step-1"
        # A tuple must be walked, not repr'd: the live object inside it is
        # what has no JSON form, not the sequence around it.
        assert isinstance(out[1], list)
        assert isinstance(out[1][1], str)

    def test_none_survives_as_none(self) -> None:
        gw = importlib.import_module("waxseal.integrations.hermes_gateway")
        assert gw._sanitize({"iteration": None}) == {"iteration": None}
