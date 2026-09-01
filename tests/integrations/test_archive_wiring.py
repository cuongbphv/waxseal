"""The hooks actually reach J3's archive — waxseal-fg4.24.

J3 shipped `sources/rotation.py::open_segmented(archive=...)`, the two
destinations, and the three-state report; every hook called `open_segmented`
WITHOUT `archive=`, so a hook-driven rotation could only ever print
`archive_not_attempted`. Everything was built, everything was tested, and
nothing an operator could configure reached any of it.

So the criterion this file holds is REACHABILITY, and it is deliberately not
the criterion `tests/adapters/test_segment_archive.py` and
`tests/test_sources_rotation.py` already meet: nothing here constructs a
destination and hands it to `open_segmented`. Every test drives the shipped
`main()` with one JSON event on stdin and one environment variable, which is
the only way a real operator has, and then watches the segment arrive at the
other end.

The three states stay three (rule 5). Unset means nothing is sent and the line
says so; an unusable value means nothing is sent and the line says WHY, which
is a different fact from "nobody configured one"; and a destination that
refuses or is unreachable is `archive_failed` with the rotation intact
underneath it (rule 6).

FALSIFIABILITY RECEIPT — measured 01/09/2026, baseline **54 tests, 0
failures** in this file — 15 hook cases x 3 hooks, plus the production-
threshold case and the seam's own 8
(`uv run --extra dev pytest tests/integrations/test_archive_wiring.py -q -p
no:randomly`, counts read out of the junit XML). Each wiring backed out one at
a time, the same 54 re-run, then restored:

    1. `archive=archive_destination()` deleted from all three hooks — i.e.
       the code exactly as it shipped in 8d87bad..da252bd
         -> exit 1, tests=54 failures=37, across 13 case names:
            test_a_configured_server_receives_the_sealed_segment
            test_the_import_credential_is_its_own_authority
            test_no_import_credential_sends_no_authorization_header
            test_a_server_that_refuses_is_failed_and_the_rotation_stands
            test_an_unreachable_destination_is_failed_not_an_exception
            test_an_s3_url_reaches_the_bucket_through_the_hook
            test_a_prefix_without_a_slash_still_stores_under_the_folder
            test_a_bucket_with_no_prefix_stores_at_the_root
            test_a_missing_s3_extra_is_not_attempted_through_the_hook_too
            test_an_unsupported_scheme_is_not_attempted_and_names_the_scheme
            test_an_s3_url_with_no_bucket_is_not_attempted_and_says_why
            test_an_unusable_value_is_not_the_same_line_as_no_value
            test_the_archive_engages_at_the_built_in_threshold
         The other 17 still PASS — the unconfigured cases and the seam's own
         unit tests. That asymmetry is the finding: from the
         `archive_not_attempted` line alone the shipped code looked healthy.
    2. `archive_destination` returning `None` for an unusable value (instead
       of a NOT_ATTEMPTED destination that names the cause)
         -> exit 1, tests=54 failures=9, across 3 case names:
            test_an_unsupported_scheme_is_not_attempted_and_names_the_scheme
            test_an_s3_url_with_no_bucket_is_not_attempted_and_says_why
            test_an_unusable_value_is_not_the_same_line_as_no_value
    3. `_key_prefix`'s separator normalization removed (`return prefix`)
         -> exit 1, tests=54 failures=4, across 2 case names:
            test_a_prefix_without_a_slash_still_stores_under_the_folder
            test_the_key_prefix_is_separator_terminated
    4. the import credential read from `WAXSEAL_API_KEY` instead of
       `WAXSEAL_ARCHIVE_API_KEY` — the tempting reuse this bead exists to
       refuse
         -> exit 1, tests=54 failures=6, across 2 case names:
            test_the_import_credential_is_its_own_authority
            test_no_import_credential_sends_no_authorization_header
"""

from __future__ import annotations

import http.server
import io
import json
import sys
import threading
import types
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from tests.adapters.test_segment_archive import FakeLockS3Client
from tests.integrations.test_project_routing import HOOK_NAMES, event_for
from waxseal import AuditLog
from waxseal.adapters.remote import RemoteRequest
from waxseal.adapters.segment_archive import _MULTIPART_BOUNDARY
from waxseal.domain.archive import ArchiveState
from waxseal.integrations._archive import (
    ENV_ARCHIVE,
    ENV_ARCHIVE_API_KEY,
    archive_destination,
)
from waxseal.sources.rotation import DEFAULT_MAX_SEGMENT_BYTES

# Well above one stored hook entry (~460 bytes) so the fixture, not the
# threshold, decides when a rotation happens — test_sources_rotation.py's
# number and reasoning, unchanged. The production 16 MiB constant is exercised
# unpatched by TestTheProductionThreshold below.
TINY = 5000

CHAIN_KEY = "chain-write-token-must-not-travel"
WITNESS_KEY = "witness-token-must-not-travel"
ARCHIVE_KEY = "import-write-token"


class LiveImportServer:
    """The server's `POST /v1/imports` endpoint over a real socket.

    A real socket rather than an injected `Transport`, because the hook builds
    its own destination from the environment and there is nowhere to inject
    one — which is exactly the property under test. It also means the bytes
    travel through the shipped `urllib_transport` and the shipped multipart
    encoder.
    """

    def __init__(self, *, status: int = 201) -> None:
        self.status = status
        self.files: dict[str, bytes] = {}
        self.headers: list[dict[str, str]] = []
        self.paths: list[str] = []
        server = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length)
                server.paths.append(self.path)
                server.headers.append(dict(self.headers))
                if server.status == 201:
                    name, content = _parse_multipart(dict(self.headers), body)
                    server.files[name] = content
                    payload = b'{"import_id": "imp-0001"}'
                else:
                    payload = b'{"error":"denied"}'
                self.send_response(server.status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args: object) -> None:
                pass  # keep test output quiet

        self._httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port: int = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def __enter__(self) -> LiveImportServer:
        self._thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join(timeout=5)


def _parse_multipart(headers: dict[str, str], body: bytes) -> tuple[str, bytes]:
    """The `file` part, parsed the way `FakeImportServer` does it.

    Parsed rather than trusted: an encoder that mis-framed the body would
    store the wrong bytes here, and this file's central claim is that the
    segment arrives byte-for-byte.
    """
    request = RemoteRequest(
        method="POST",
        url="/v1/imports",
        headers={"Content-Type": headers["Content-Type"]},
        body=body,
    )
    from tests.adapters.test_segment_archive import FakeImportServer

    return FakeImportServer.parse(request)


@pytest.fixture
def live() -> Iterator[LiveImportServer]:
    with LiveImportServer() as server:
        yield server


@pytest.fixture(params=HOOK_NAMES)
def hook(request: pytest.FixtureRequest) -> tuple[Any, str]:
    import importlib

    return importlib.import_module(f"waxseal.integrations.{request.param}"), request.param


def base_env(monkeypatch: pytest.MonkeyPatch, trail: Path) -> None:
    monkeypatch.setenv("WAXSEAL_TRAIL", str(trail))
    monkeypatch.delenv(ENV_ARCHIVE, raising=False)
    monkeypatch.delenv(ENV_ARCHIVE_API_KEY, raising=False)
    # Present, and must stay out of every archive request: the whole point of
    # a third credential is that these two never travel to the import route.
    monkeypatch.setenv("WAXSEAL_API_KEY", CHAIN_KEY)
    monkeypatch.setenv("WAXSEAL_WITNESS_API_KEY", WITNESS_KEY)


def drive(
    monkeypatch: pytest.MonkeyPatch, module: Any, name: str, trail: Path, *, tiny: bool = True
) -> int:
    if tiny:
        # Orthogonal to the wiring under test: it only decides WHEN the
        # rotation fires, so the suite does not write 16 MiB per case. One
        # test below leaves it alone.
        monkeypatch.setattr(module, "DEFAULT_MAX_SEGMENT_BYTES", TINY)
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(event_for(name))))
    return module.main()


def rotate(
    monkeypatch: pytest.MonkeyPatch,
    module: Any,
    name: str,
    trail: Path,
    *,
    tiny: bool = True,
) -> tuple[int, bytes]:
    """One append, pad the trail past the threshold, append again.

    Returns the second run's exit code and the SEALED segment's bytes as they
    stood when the archive read them. Padding at the FRONT keeps the last line
    intact, which is what the O(1) tail read needs to seal the segment.
    """
    threshold = TINY if tiny else DEFAULT_MAX_SEGMENT_BYTES
    drive(monkeypatch, module, name, trail, tiny=tiny)
    trail.write_bytes(b"\n" * threshold + trail.read_bytes())
    code = drive(monkeypatch, module, name, trail, tiny=tiny)
    return code, trail.read_bytes()


def archive_lines(err: str) -> list[str]:
    return [line for line in err.splitlines() if "archive_" in line]


class TestNothingConfigured:
    """Opt-in stays opt-in: wiring the seam must not start sending anything."""

    def test_an_unset_variable_is_still_not_attempted(
        self,
        monkeypatch: pytest.MonkeyPatch,
        hook: tuple[Any, str],
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        module, name = hook
        trail = tmp_path / "named.jsonl"
        base_env(monkeypatch, trail)
        code, _ = rotate(monkeypatch, module, name, trail)
        err = capsys.readouterr().err
        assert code == 0
        assert (tmp_path / "named.00000.jsonl").exists()
        [line] = archive_lines(err)
        assert line.startswith(f"[waxseal-audit] {ArchiveState.NOT_ATTEMPTED.value}:")
        assert "no archive destination configured" in line

    def test_no_rotation_archives_nothing(
        self,
        monkeypatch: pytest.MonkeyPatch,
        hook: tuple[Any, str],
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
        live: LiveImportServer,
    ) -> None:
        module, name = hook
        trail = tmp_path / "named.jsonl"
        base_env(monkeypatch, trail)
        monkeypatch.setenv(ENV_ARCHIVE, live.url)
        drive(monkeypatch, module, name, trail)
        assert archive_lines(capsys.readouterr().err) == []
        assert live.files == {}


class TestTheServerImportDestination:
    def test_a_configured_server_receives_the_sealed_segment(
        self,
        monkeypatch: pytest.MonkeyPatch,
        hook: tuple[Any, str],
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
        live: LiveImportServer,
    ) -> None:
        # THE reachability test: one environment variable, the shipped
        # main(), a real socket. Nothing in this test knows what an
        # ArchiveDestination is.
        module, name = hook
        trail = tmp_path / "named.jsonl"
        base_env(monkeypatch, trail)
        monkeypatch.setenv(ENV_ARCHIVE, live.url)
        monkeypatch.setenv(ENV_ARCHIVE_API_KEY, ARCHIVE_KEY)

        code, sealed = rotate(monkeypatch, module, name, trail)

        assert code == 0
        assert live.paths == ["/v1/imports"]
        assert live.files == {"named.jsonl": sealed}
        [line] = archive_lines(capsys.readouterr().err)
        assert line.startswith(f"[waxseal-audit] {ArchiveState.STORED.value}:")
        assert "import_id=imp-0001" in line
        # The rotation itself is untouched: new segment, binding, and the
        # event that triggered it all landed.
        assert AuditLog.open(tmp_path / "named.00000.jsonl").verify(measure_drops=False).ok

    def test_the_import_credential_is_its_own_authority(
        self,
        monkeypatch: pytest.MonkeyPatch,
        hook: tuple[Any, str],
        tmp_path: Path,
        live: LiveImportServer,
    ) -> None:
        # The bead's standing question, answered in a test rather than in
        # prose: the archive write is a THIRD authority. The chain-write token
        # can extend live history and the witness token belongs to a different
        # administrative authority entirely, so neither may travel here.
        module, name = hook
        trail = tmp_path / "named.jsonl"
        base_env(monkeypatch, trail)
        monkeypatch.setenv(ENV_ARCHIVE, live.url)
        monkeypatch.setenv(ENV_ARCHIVE_API_KEY, ARCHIVE_KEY)

        rotate(monkeypatch, module, name, trail)

        [headers] = live.headers
        assert headers["Authorization"] == f"Bearer {ARCHIVE_KEY}"
        sent = json.dumps(headers)
        assert CHAIN_KEY not in sent
        assert WITNESS_KEY not in sent

    def test_no_import_credential_sends_no_authorization_header(
        self,
        monkeypatch: pytest.MonkeyPatch,
        hook: tuple[Any, str],
        tmp_path: Path,
        live: LiveImportServer,
    ) -> None:
        # Unset means unset here too: it must not silently fall back to the
        # chain-write token that IS set in this environment.
        module, name = hook
        trail = tmp_path / "named.jsonl"
        base_env(monkeypatch, trail)
        monkeypatch.setenv(ENV_ARCHIVE, live.url)

        rotate(monkeypatch, module, name, trail)

        [headers] = live.headers
        assert "Authorization" not in headers
        assert CHAIN_KEY not in json.dumps(headers)


class TestFailureNeverBlocksTheRotation:
    """Rule 6, through the hook: a labelled degradation, never a lost append."""

    def test_a_server_that_refuses_is_failed_and_the_rotation_stands(
        self,
        monkeypatch: pytest.MonkeyPatch,
        hook: tuple[Any, str],
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        module, name = hook
        trail = tmp_path / "named.jsonl"
        base_env(monkeypatch, trail)
        with LiveImportServer(status=403) as server:
            monkeypatch.setenv(ENV_ARCHIVE, server.url)
            code, _ = rotate(monkeypatch, module, name, trail)
        err = capsys.readouterr().err
        assert code == 0  # a nonzero exit would veto the developer's tool call
        [line] = archive_lines(err)
        assert line.startswith(f"[waxseal-audit] {ArchiveState.FAILED.value}:")
        assert "HTTP 403" in line
        new_segment = tmp_path / "named.00000.jsonl"
        assert AuditLog.open(new_segment).verify(measure_drops=False).ok
        assert AuditLog.open(new_segment).verify(measure_drops=False).checked == 2

    def test_an_unreachable_destination_is_failed_not_an_exception(
        self,
        monkeypatch: pytest.MonkeyPatch,
        hook: tuple[Any, str],
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        # A destination whose transport RAISES (connection refused): the
        # rotation is already durable when the archive runs, so this may only
        # ever become a labelled line.
        module, name = hook
        trail = tmp_path / "named.jsonl"
        base_env(monkeypatch, trail)
        with LiveImportServer() as server:
            dead = server.url  # bound, then closed: nothing is listening
        monkeypatch.setenv(ENV_ARCHIVE, dead)

        code, _ = rotate(monkeypatch, module, name, trail)

        assert code == 0
        [line] = archive_lines(capsys.readouterr().err)
        assert line.startswith(f"[waxseal-audit] {ArchiveState.FAILED.value}:")
        assert AuditLog.open(tmp_path / "named.00000.jsonl").verify(measure_drops=False).ok


class TestTheS3Destination:
    @staticmethod
    def fake_boto3(monkeypatch: pytest.MonkeyPatch) -> FakeLockS3Client:
        """The `s3` extra, faked at its single import site.

        `adapters/s3.py::_resolve_client` is the only place waxseal imports
        boto3 at all (rule 1), and it imports it inside the function — so a
        module in `sys.modules` is the whole injection.
        """
        client = FakeLockS3Client()
        monkeypatch.setitem(
            sys.modules, "boto3", types.SimpleNamespace(client=lambda _service: client)
        )
        return client

    def test_an_s3_url_reaches_the_bucket_through_the_hook(
        self,
        monkeypatch: pytest.MonkeyPatch,
        hook: tuple[Any, str],
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        module, name = hook
        trail = tmp_path / "named.jsonl"
        base_env(monkeypatch, trail)
        client = self.fake_boto3(monkeypatch)
        monkeypatch.setenv(ENV_ARCHIVE, "s3://audit/segments/")

        code, sealed = rotate(monkeypatch, module, name, trail)

        assert code == 0
        assert client.stored("audit", "segments/named.jsonl") == sealed
        [line] = archive_lines(capsys.readouterr().err)
        assert line.startswith(f"[waxseal-audit] {ArchiveState.STORED.value}:")
        assert "s3://audit/segments/named.jsonl" in line

    def test_a_prefix_without_a_slash_still_stores_under_the_folder(
        self,
        monkeypatch: pytest.MonkeyPatch,
        hook: tuple[Any, str],
        tmp_path: Path,
    ) -> None:
        # `s3://audit/segments` names a folder, not a rename: without the
        # normalization the object lands as `segmentsnamed.jsonl`.
        module, name = hook
        trail = tmp_path / "named.jsonl"
        base_env(monkeypatch, trail)
        client = self.fake_boto3(monkeypatch)
        monkeypatch.setenv(ENV_ARCHIVE, "s3://audit/segments")

        _, sealed = rotate(monkeypatch, module, name, trail)

        assert client.stored("audit", "segments/named.jsonl") == sealed

    def test_a_bucket_with_no_prefix_stores_at_the_root(
        self,
        monkeypatch: pytest.MonkeyPatch,
        hook: tuple[Any, str],
        tmp_path: Path,
    ) -> None:
        module, name = hook
        trail = tmp_path / "named.jsonl"
        base_env(monkeypatch, trail)
        client = self.fake_boto3(monkeypatch)
        monkeypatch.setenv(ENV_ARCHIVE, "s3://audit")

        _, sealed = rotate(monkeypatch, module, name, trail)

        assert client.stored("audit", "named.jsonl") == sealed

    def test_a_missing_s3_extra_is_not_attempted_through_the_hook_too(
        self,
        monkeypatch: pytest.MonkeyPatch,
        hook: tuple[Any, str],
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        # Reached the destination, asked nothing of it: J1's own
        # not-attempted, which must stay distinguishable from "nobody
        # configured a destination" — the operator DID configure one.
        module, name = hook
        trail = tmp_path / "named.jsonl"
        base_env(monkeypatch, trail)
        monkeypatch.setitem(sys.modules, "boto3", None)
        monkeypatch.setenv(ENV_ARCHIVE, "s3://audit/segments/")

        code, _ = rotate(monkeypatch, module, name, trail)

        assert code == 0
        [line] = archive_lines(capsys.readouterr().err)
        assert line.startswith(f"[waxseal-audit] {ArchiveState.NOT_ATTEMPTED.value}:")
        assert "s3://audit/segments/named.jsonl" in line
        assert "no archive destination configured" not in line


class TestAnUnusableValueSaysSo:
    def test_an_unsupported_scheme_is_not_attempted_and_names_the_scheme(
        self,
        monkeypatch: pytest.MonkeyPatch,
        hook: tuple[Any, str],
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        module, name = hook
        trail = tmp_path / "named.jsonl"
        base_env(monkeypatch, trail)
        # `file://` specifically: the scheme that would turn an "upload" into
        # a local copy if anything ever honoured it.
        monkeypatch.setenv(ENV_ARCHIVE, "file:///tmp/secret-place/archive")

        code, _ = rotate(monkeypatch, module, name, trail)

        assert code == 0
        [line] = archive_lines(capsys.readouterr().err)
        assert line.startswith(f"[waxseal-audit] {ArchiveState.NOT_ATTEMPTED.value}:")
        assert "'file'" in line
        # The value itself never reaches stderr: an archive URL can carry
        # userinfo, and a hook notice is not a place to spill a credential.
        assert "secret-place" not in line

    def test_an_s3_url_with_no_bucket_is_not_attempted_and_says_why(
        self,
        monkeypatch: pytest.MonkeyPatch,
        hook: tuple[Any, str],
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        module, name = hook
        trail = tmp_path / "named.jsonl"
        base_env(monkeypatch, trail)
        monkeypatch.setenv(ENV_ARCHIVE, "s3:///no-bucket-here/")

        code, _ = rotate(monkeypatch, module, name, trail)

        assert code == 0
        [line] = archive_lines(capsys.readouterr().err)
        assert line.startswith(f"[waxseal-audit] {ArchiveState.NOT_ATTEMPTED.value}:")
        assert "names no bucket" in line

    def test_an_unusable_value_is_not_the_same_line_as_no_value(
        self,
        monkeypatch: pytest.MonkeyPatch,
        hook: tuple[Any, str],
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        # Both are NOT_ATTEMPTED and both are correct. Collapsing them would
        # tell an operator who set the variable that they never set it.
        module, name = hook
        unset_trail = tmp_path / "unset.jsonl"
        base_env(monkeypatch, unset_trail)
        rotate(monkeypatch, module, name, unset_trail)
        [unset_line] = archive_lines(capsys.readouterr().err)

        bad_trail = tmp_path / "bad.jsonl"
        monkeypatch.setenv("WAXSEAL_TRAIL", str(bad_trail))
        monkeypatch.setenv(ENV_ARCHIVE, "ftp://archive.example/segments")
        rotate(monkeypatch, module, name, bad_trail)
        [bad_line] = archive_lines(capsys.readouterr().err)

        assert unset_line != bad_line
        assert "no archive destination configured" in unset_line
        assert "'ftp'" in bad_line

    def test_a_whitespace_only_value_is_treated_as_unset(
        self,
        monkeypatch: pytest.MonkeyPatch,
        hook: tuple[Any, str],
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        module, name = hook
        trail = tmp_path / "named.jsonl"
        base_env(monkeypatch, trail)
        monkeypatch.setenv(ENV_ARCHIVE, "   ")

        rotate(monkeypatch, module, name, trail)

        [line] = archive_lines(capsys.readouterr().err)
        assert "no archive destination configured" in line


class TestTheProductionThreshold:
    """Once, at 16 MiB, with nothing patched: the wiring is not an artifact of
    the tiny threshold the rest of this file uses."""

    def test_the_archive_engages_at_the_built_in_threshold(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
        live: LiveImportServer,
    ) -> None:
        import waxseal.integrations.claude_code as module

        trail = tmp_path / "named.jsonl"
        base_env(monkeypatch, trail)
        monkeypatch.setenv(ENV_ARCHIVE, live.url)

        code, sealed = rotate(monkeypatch, module, "claude_code", trail, tiny=False)

        assert code == 0
        assert len(sealed) > DEFAULT_MAX_SEGMENT_BYTES
        assert live.files == {"named.jsonl": sealed}
        err = capsys.readouterr().err
        assert "rotated at 16777216 bytes (built-in default)" in err
        assert f"{ArchiveState.STORED.value}:" in err


class TestTheSeamItself:
    """Unit-level cover for the branches the hook tests reach only indirectly."""

    def test_an_unset_variable_builds_no_destination(self) -> None:
        assert archive_destination({}) is None

    def test_https_is_accepted_as_well_as_http(self) -> None:
        destination = archive_destination({ENV_ARCHIVE: "https://audit.example"})
        assert destination is not None
        # Unreachable host, so the outcome is FAILED — what matters is that a
        # destination was built at all for the https scheme.
        assert destination("x.jsonl", b"{}").state is ArchiveState.FAILED

    @pytest.mark.parametrize(
        ("url", "expected"),
        [
            ("s3://audit", "audit/named.jsonl"),
            ("s3://audit/", "audit/named.jsonl"),
            ("s3://audit/segments", "audit/segments/named.jsonl"),
            ("s3://audit/segments/", "audit/segments/named.jsonl"),
            ("s3://audit/a/b/", "audit/a/b/named.jsonl"),
        ],
    )
    def test_the_key_prefix_is_separator_terminated(
        self, monkeypatch: pytest.MonkeyPatch, url: str, expected: str
    ) -> None:
        client = FakeLockS3Client()
        monkeypatch.setitem(
            sys.modules, "boto3", types.SimpleNamespace(client=lambda _service: client)
        )
        destination = archive_destination({ENV_ARCHIVE: url})
        assert destination is not None
        report = destination("named.jsonl", b"{}\n")
        assert report.state is ArchiveState.STORED
        assert report.destination == f"s3://{expected}"

    def test_a_segment_carrying_the_multipart_boundary_is_still_only_a_line(
        self, live: LiveImportServer
    ) -> None:
        # The destination raises out of its own encoder here. The seam adds no
        # new way for that to escape: it is a report, like every other outcome.
        destination = archive_destination(
            {ENV_ARCHIVE: live.url, ENV_ARCHIVE_API_KEY: ARCHIVE_KEY}
        )
        assert destination is not None
        report = destination("x.jsonl", f"--{_MULTIPART_BOUNDARY}\n".encode())
        assert report.state is ArchiveState.FAILED
        assert live.files == {}
