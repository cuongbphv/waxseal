"""The Claude Code hook writing to a chain SERVER instead of a local file.

`WAXSEAL_TRAIL` has always chosen where a hook writes. This makes an
`http(s)://` value mean what it already means everywhere else in the library —
a remote chain over REMOTE.md — so a developer's hook can append to a
self-hosted server without a second configuration mechanism.

Three things change for a URL target and each has a reason:

- the value stays a `str`. `Path("http://host")` collapses the `//` and drops
  the scheme, and `AuditLog.open` dispatches on the string, so passing a Path
  would silently route a remote target to a local file named `http:`;
- `record_drops` is off. A drop record is a sidecar file NEXT TO the trail, and
  a URL has no next-to. `AuditLog.open` rejects the combination outright;
- the chain gets an id, because one server holds many projects' trails.

The observer contract is unchanged and is what the last class here pins: an
unreachable server must cost the developer nothing but a labelled notice.
"""

from __future__ import annotations

import http.server
import json
import os
import subprocess
import sys
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from tests.adapters.fake_chain_server import FakeChainServer
from tests.adapters.test_remote import _quiet_handler_for

HOOK_PATH = (
    Path(__file__).parent.parent.parent / "src" / "waxseal" / "integrations" / "claude_code.py"
)
SRC = str(Path(__file__).parent.parent.parent / "src")


class LiveFakeServer:
    """`FakeChainServer` over a real socket, because the hook is a subprocess."""

    def __init__(self) -> None:
        self.server = FakeChainServer()
        self._httpd = http.server.ThreadingHTTPServer(
            ("127.0.0.1", 0), _quiet_handler_for(self.server)
        )
        self.port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def entries(self, chain_id: str = "default") -> list[dict[str, Any]]:
        return list(self.server._chains.get(chain_id, []))

    def __enter__(self) -> LiveFakeServer:
        self._thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()


@pytest.fixture
def live() -> Iterator[LiveFakeServer]:
    with LiveFakeServer() as server:
        yield server


def run_hook(
    event: dict[str, Any], trail: str, **env_overrides: str
) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "PYTHONPATH": SRC, "WAXSEAL_TRAIL": trail, **env_overrides}
    return subprocess.run(
        [sys.executable, str(HOOK_PATH)],
        input=json.dumps(event),
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )


def event(**overrides: Any) -> dict[str, Any]:
    base = {
        "session_id": "sess-1",
        "cwd": "/Users/dev/Projects/waxseal",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "pytest -q"},
        "tool_use_id": "toolu_01",
    }
    base.update(overrides)
    return base


class TestRemoteTarget:
    def test_a_url_trail_appends_to_the_server(self, live: LiveFakeServer) -> None:
        result = run_hook(event(), live.url, WAXSEAL_CHAIN_ID="waxseal")
        assert result.returncode == 0
        assert len(live.entries("waxseal")) == 1

    def test_the_entry_carries_the_hook_payload(self, live: LiveFakeServer) -> None:
        import base64

        run_hook(event(), live.url, WAXSEAL_CHAIN_ID="waxseal")
        [stored] = live.entries("waxseal")
        payload = json.loads(base64.b64decode(stored["payload_b64"]))
        assert payload["event"] == "PreToolUse"
        assert payload["tool_name"] == "Bash"

    def test_two_events_chain_on_the_server(self, live: LiveFakeServer) -> None:
        run_hook(event(), live.url, WAXSEAL_CHAIN_ID="waxseal")
        run_hook(event(tool_use_id="toolu_02"), live.url, WAXSEAL_CHAIN_ID="waxseal")
        stored = live.entries("waxseal")
        assert [e["header"]["seq"] for e in stored] == [0, 1]
        assert stored[1]["header"]["prev_hash"] == stored[0]["entry_hash"]

    def test_it_writes_nothing_to_stdout(self, live: LiveFakeServer) -> None:
        # UserPromptSubmit stdout is injected into model context.
        result = run_hook(
            event(hook_event_name="UserPromptSubmit", prompt="hello"),
            live.url,
            WAXSEAL_CHAIN_ID="waxseal",
        )
        assert result.stdout == ""

    def test_a_secret_is_redacted_before_it_leaves_the_machine(
        self, live: LiveFakeServer
    ) -> None:
        # Redaction runs before hashing, so it also runs before the POST. A
        # remote target must not be the one path where a key escapes.
        import base64

        secret = "sk-ant-api03-" + "S3CRETVALUE" * 4
        run_hook(
            event(tool_input={"command": f"curl -H 'x: {secret}'"}),
            live.url,
            WAXSEAL_CHAIN_ID="waxseal",
        )
        [stored] = live.entries("waxseal")
        payload = base64.b64decode(stored["payload_b64"]).decode()
        assert "S3CRETVALUE" not in payload
        assert "REDACTED" in payload


class TestChainId:
    def test_an_explicit_chain_id_is_used(self, live: LiveFakeServer) -> None:
        run_hook(event(), live.url, WAXSEAL_CHAIN_ID="my-project")
        assert len(live.entries("my-project")) == 1

    def test_without_one_the_chain_is_named_after_the_project_directory(
        self, live: LiveFakeServer
    ) -> None:
        # One server holds many projects' trails, so a hook that always wrote to
        # "default" would braid every project into one chain.
        run_hook(event(cwd="/Users/dev/Projects/waxseal"), live.url)
        assert len(live.entries("waxseal")) == 1

    def test_a_directory_name_is_sanitised_into_a_safe_chain_id(
        self, live: LiveFakeServer
    ) -> None:
        run_hook(event(cwd="/Users/dev/My Project (v2)"), live.url)
        assert len(live.entries("my-project-v2")) == 1

    def test_an_event_with_no_cwd_falls_back_to_default(
        self, live: LiveFakeServer
    ) -> None:
        no_cwd = event()
        del no_cwd["cwd"]
        run_hook(no_cwd, live.url)
        assert len(live.entries("default")) == 1

    def test_the_chain_id_does_not_affect_a_local_trail(self, tmp_path: Path) -> None:
        # A local trail is one file at one path; the id is a remote concept and
        # must not silently move the file somebody configured.
        trail = tmp_path / "trail.jsonl"
        run_hook(event(), str(trail), WAXSEAL_CHAIN_ID="ignored-here")
        assert trail.exists()


class TestStillNeverBlocks:
    def test_an_unreachable_server_exits_zero_with_a_labelled_notice(
        self, tmp_path: Path
    ) -> None:
        # The observer contract: a broken audit path must never veto the
        # developer's tool call. Port 1 is reserved and refuses immediately.
        result = run_hook(event(), "http://127.0.0.1:1", WAXSEAL_CHAIN_ID="waxseal")
        assert result.returncode == 0
        assert result.stdout == ""
        assert "waxseal-audit" in result.stderr

    def test_a_url_target_does_not_crash_on_the_drops_sidecar(
        self, tmp_path: Path
    ) -> None:
        # `record_drops=True` with a URL raises ValueError in AuditLog.open —
        # a remote trail has no next-to for a sidecar. The hook must not ask.
        result = run_hook(event(), "http://127.0.0.1:1", WAXSEAL_CHAIN_ID="waxseal")
        assert "record_drops" not in result.stderr

    def test_a_server_returning_500_still_exits_zero(self, live: LiveFakeServer) -> None:
        live.server.enforce_precondition = True
        result = run_hook(event(), f"{live.url}/nowhere", WAXSEAL_CHAIN_ID="waxseal")
        assert result.returncode == 0
        assert result.stdout == ""
