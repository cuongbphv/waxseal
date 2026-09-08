from __future__ import annotations

import json
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import Any, cast

import pytest
from fastapi.testclient import TestClient
from waxseal_server.runtime.cli import READ_ONLY_COMMANDS, WaxsealCli

from waxseal import AuditLog

# The library's OWN backend-conformance suite is the strongest statement this
# server can make: "a real waxseal client cannot tell this apart from the
# backends it ships with." Reaching it needs the repository root importable as
# the `tests` package, which is also why this directory deliberately has no
# `__init__.py` — two packages both named `tests` would shadow each other.
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

PAYLOAD_TYPE = "application/vnd.waxseal-server-test.event+json"


def build_envelopes(tmp_path: Path, count: int) -> list[dict[str, Any]]:
    """Real client-side envelopes, produced by the library the server serves.

    Hand-rolling envelopes in the test would let the server agree with the test
    and disagree with every actual waxseal client — the one failure a wire
    contract exists to prevent.
    """
    trail = tmp_path / "fixture.jsonl"
    log = AuditLog.open(trail)
    for i in range(count):
        log.append(payload={"i": i}, payload_type=PAYLOAD_TYPE)
    return [
        json.loads(line) for line in trail.read_text(encoding="utf-8").splitlines() if line.strip()
    ]


@pytest.fixture
def envelopes(tmp_path: Path) -> list[dict[str, Any]]:
    return build_envelopes(tmp_path / "fixtures", 5)


#: Said out loud rather than passed quietly. A build that ships every read this
#: server offers leaves the real-planned-command shape with no live instance;
#: the property is still held by the withholding form below, which runs
#: unconditionally. A silent green tick here would claim a check nobody
#: performed, which is the one thing this project must not print (rule 5).
NO_ABSENT_COMMAND = (
    "this waxseal build ships every read-only command the server offers, so no "
    "REAL planned-but-absent command exists to exercise. Skipped with a label, "
    "never silently passed; the build-independent form of the same property "
    "runs regardless (waxseal-fg4.36)."
)


def planned_but_absent(
    cli: WaxsealCli, offered: Iterable[str] = READ_ONLY_COMMANDS
) -> frozenset[str]:
    """Reads this server offers that the wheel behind it does not have.

    DERIVED from the build, never a name. Naming a planned command as the
    example of an absent one expired four tests the day Workstream B shipped
    `segments` (waxseal-fg4.16) and five more when Workstream E shipped
    `preflight` one batch later (waxseal-fg4.36). Every command still planned
    belongs to a workstream inside this same release, so the next hardcoded name
    would expire on the same schedule.
    """
    return frozenset(offered) - cli.available()


def withhold(monkeypatch: pytest.MonkeyPatch, cli: WaxsealCli, command: str) -> None:
    """Make this runner's build lack `command`, whatever it really ships.

    The condition under test is "a name absent from `available()`", not any one
    command, and a server pointed at an older wheel than its portal is exactly
    how that arises in production. Stating it this way cannot expire, because no
    release can make it true or false.
    """
    shipped = cli.available()
    assert command in shipped, f"{command!r} must really ship, or this proves nothing"
    monkeypatch.setattr(cli, "available", lambda: shipped - {command})


def cli_of(client: TestClient) -> WaxsealCli:
    return cast(WaxsealCli, client.app.state.services.cli)  # type: ignore[attr-defined]
