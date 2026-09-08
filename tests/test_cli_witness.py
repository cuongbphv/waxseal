"""`waxseal anchor --witness` / `verify --witness` against a real socket.

These run over an actual localhost HTTP server rather than an injected
transport: the witness path is the one place where the security claim depends
on the observation genuinely leaving the process, and a test that never opens
a socket cannot tell that story.

The exit-code rules encoded here:

- a witness that disagrees is a break (exit 1). It is evidence of a rewrite or
  a split view, and there is no benign reading of it.
- a witness that cannot be reached is unverifiable coverage (exit 2), always
  printed with its label. Escalating "I could not ask" to "broken" would
  conflate the two things this project refuses to conflate; reporting it as a
  pass (exit 0) would let a verifier claim a check it never performed.
"""

from __future__ import annotations

import http.server
import json
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest

from waxseal import AuditLog
from waxseal.cli import main

PT = "application/vnd.test.event+json"


class WitnessService:
    """A minimal witness: POST appends a checkpoint, GET lists them."""

    def __init__(self) -> None:
        self.records: list[dict[str, object]] = []
        self.status_override: int | None = None
        self.body_override: bytes | None = None
        # One entry per request, None when no Authorization header arrived —
        # the credential-separation tests need to see what actually crossed
        # the wire, not what the client believes it sent.
        self.auth: list[str | None] = []

    def handle(self, method: str, body: bytes | None) -> tuple[int, bytes]:
        if self.status_override is not None:
            return self.status_override, self.body_override or b""
        if method == "POST":
            assert body is not None
            self.records.append(json.loads(body))
            return 201, json.dumps({"receipt": f"r-{len(self.records)}"}).encode()
        if not self.records:
            return 404, b""
        return 200, json.dumps({"checkpoints": self.records}).encode()


def start_witness(
    service: WitnessService,
) -> tuple[http.server.HTTPServer, threading.Thread, str]:
    class Handler(http.server.BaseHTTPRequestHandler):
        def _dispatch(self, method: str) -> None:
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length) if length else None
            service.auth.append(self.headers.get("Authorization"))
            status, resp = service.handle(method, body)
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)

        def do_GET(self) -> None:  # noqa: N802
            self._dispatch("GET")

        def do_POST(self) -> None:  # noqa: N802
            self._dispatch("POST")

        def log_message(self, *args: object) -> None:
            pass

    httpd = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, thread, f"http://127.0.0.1:{httpd.server_address[1]}/witness"


def make_trail(path: Path, n: int = 3, *, start: int = 0) -> None:
    log = AuditLog.open(path)
    for i in range(start, start + n):
        log.append(payload={"i": i}, payload_type=PT)


@pytest.fixture
def witness() -> Iterator[tuple[WitnessService, str]]:
    service = WitnessService()
    httpd, thread, url = start_witness(service)
    try:
        yield service, url
    finally:
        httpd.shutdown()
        thread.join(timeout=5)
        httpd.server_close()


class TestAnchorPublishes:
    def test_checkpoint_reaches_the_witness(
        self,
        tmp_path: Path,
        witness: tuple[WitnessService, str],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        service, url = witness
        trail = tmp_path / "trail.jsonl"
        make_trail(trail, 3)

        assert main(["anchor", str(trail), "--witness", url]) == 0
        assert service.records[0]["seq"] == 2
        assert "published to" in capsys.readouterr().out

    def test_local_sidecar_is_still_written(
        self,
        tmp_path: Path,
        witness: tuple[WitnessService, str],
    ) -> None:
        # The witness is an addition, not a replacement: the local queue is
        # what `verify --anchors` reads when no witness is configured.
        _, url = witness
        trail = tmp_path / "trail.jsonl"
        make_trail(trail)
        main(["anchor", str(trail), "--witness", url])
        assert Path(str(trail) + ".anchors").exists()

    def test_a_failing_witness_publish_exits_1(
        self,
        tmp_path: Path,
        witness: tuple[WitnessService, str],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        service, url = witness
        service.status_override = 503
        trail = tmp_path / "trail.jsonl"
        make_trail(trail)

        assert main(["anchor", str(trail), "--witness", url]) == 1
        assert "WITNESS PUBLISH FAILED" in capsys.readouterr().out

    def test_publishes_to_every_witness(self, tmp_path: Path) -> None:
        first, second = WitnessService(), WitnessService()
        h1, t1, u1 = start_witness(first)
        h2, t2, u2 = start_witness(second)
        try:
            trail = tmp_path / "trail.jsonl"
            make_trail(trail)
            assert main(["anchor", str(trail), "--witness", u1, "--witness", u2]) == 0
            assert len(first.records) == len(second.records) == 1
        finally:
            for httpd, thread in ((h1, t1), (h2, t2)):
                httpd.shutdown()
                thread.join(timeout=5)
                httpd.server_close()


class TestVerifyCrossChecks:
    def test_consistent_witness_passes(
        self,
        tmp_path: Path,
        witness: tuple[WitnessService, str],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        _, url = witness
        trail = tmp_path / "trail.jsonl"
        make_trail(trail, 3)
        main(["anchor", str(trail), "--witness", url])
        capsys.readouterr()

        assert main(["verify", str(trail), "--witness", url]) == 0
        assert "consistent" in capsys.readouterr().out

    def test_trail_that_grew_since_the_witness_saw_it_is_consistent(
        self, tmp_path: Path, witness: tuple[WitnessService, str]
    ) -> None:
        _, url = witness
        trail = tmp_path / "trail.jsonl"
        make_trail(trail, 2)
        main(["anchor", str(trail), "--witness", url])
        make_trail(trail, 2, start=2)
        assert main(["verify", str(trail), "--witness", url]) == 0

    def test_rewritten_history_is_a_break(
        self,
        tmp_path: Path,
        witness: tuple[WitnessService, str],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        _, url = witness
        trail = tmp_path / "trail.jsonl"
        make_trail(trail, 3)
        main(["anchor", str(trail), "--witness", url])
        capsys.readouterr()

        trail.unlink()
        make_trail(trail, 3)  # a different, perfectly self-consistent history

        # Falsifiability receipt: nothing local objects to this.
        assert main(["verify", str(trail)]) == 0
        capsys.readouterr()

        assert main(["verify", str(trail), "--witness", url]) == 1
        out = capsys.readouterr().out
        assert "INCONSISTENT" in out
        assert "split-view" in out

    def test_truncation_below_the_witnessed_head_is_a_break(
        self,
        tmp_path: Path,
        witness: tuple[WitnessService, str],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        _, url = witness
        trail = tmp_path / "trail.jsonl"
        make_trail(trail, 4)
        main(["anchor", str(trail), "--witness", url])
        capsys.readouterr()
        trail.write_text(
            "\n".join(trail.read_text(encoding="utf-8").splitlines()[:2]) + "\n", encoding="utf-8"
        )

        assert main(["verify", str(trail), "--witness", url]) == 1
        assert "anchor_beyond_head" in capsys.readouterr().out

    def test_an_unreachable_witness_is_labelled_and_not_a_pass(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        service = WitnessService()
        httpd, thread, url = start_witness(service)
        httpd.shutdown()
        thread.join(timeout=5)
        httpd.server_close()

        trail = tmp_path / "trail.jsonl"
        make_trail(trail)
        # "Could not ask" is coverage the run does not have: exit 2
        # (unverifiable), never 0 (a pass) and never 1 (tampering) —
        # SPEC.md section 14.
        assert main(["verify", str(trail), "--witness", url]) == 2
        out = capsys.readouterr().out
        assert "unreachable" in out
        assert "NOT checked" in out

    def test_an_inconsistent_witness_beats_an_unreachable_one(
        self, tmp_path: Path, witness: tuple[WitnessService, str]
    ) -> None:
        # _combine's ordering: 1 is the stronger finding. A run that found a
        # split view must never soften to "unverifiable" because another
        # witness happened to be down.
        forked, url = witness
        down = WitnessService()
        httpd, thread, down_url = start_witness(down)
        httpd.shutdown()
        thread.join(timeout=5)
        httpd.server_close()

        trail = tmp_path / "trail.jsonl"
        make_trail(trail, 3)
        forked.records.append({"seq": 2, "entry_hash": "f" * 64, "root": "e" * 64})

        assert main(["verify", str(trail), "--witness", url, "--witness", down_url]) == 1

    def test_a_witness_holding_nothing_reports_no_coverage(
        self,
        tmp_path: Path,
        witness: tuple[WitnessService, str],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        _, url = witness
        trail = tmp_path / "trail.jsonl"
        make_trail(trail)
        assert main(["verify", str(trail), "--witness", url]) == 0
        assert "no_checkpoints_witnessed" in capsys.readouterr().out

    def test_one_disagreeing_witness_outweighs_the_agreeing_ones(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        honest, forked = WitnessService(), WitnessService()
        h1, t1, u1 = start_witness(honest)
        h2, t2, u2 = start_witness(forked)
        try:
            trail = tmp_path / "trail.jsonl"
            make_trail(trail, 3)
            main(["anchor", str(trail), "--witness", u1])
            # The second witness holds a checkpoint from a history this trail
            # does not extend — the split-view signature.
            forked.records.append({"seq": 2, "entry_hash": "f" * 64, "root": "e" * 64})
            capsys.readouterr()

            assert main(["verify", str(trail), "--witness", u1, "--witness", u2]) == 1
            out = capsys.readouterr().out
            assert "consistent" in out
            assert "INCONSISTENT" in out
        finally:
            for httpd, thread in ((h1, t1), (h2, t2)):
                httpd.shutdown()
                thread.join(timeout=5)
                httpd.server_close()

    def test_unreadable_witness_records_are_reported_as_uncovered(
        self,
        tmp_path: Path,
        witness: tuple[WitnessService, str],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        service, url = witness
        trail = tmp_path / "trail.jsonl"
        make_trail(trail, 3)
        main(["anchor", str(trail), "--witness", url])
        service.records.append({"from_the_future": True})
        capsys.readouterr()

        assert main(["verify", str(trail), "--witness", url]) == 0
        assert "1 record(s) this build could not read" in capsys.readouterr().out

    def test_an_unusable_witness_response_is_unreachable_not_consistent(
        self,
        tmp_path: Path,
        witness: tuple[WitnessService, str],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        # A proxy error page answering 200 must never read as "no
        # disagreement found" — it is coverage the run did not get (exit 2).
        service, url = witness
        service.status_override = 200
        service.body_override = b"<html>captive portal</html>"
        trail = tmp_path / "trail.jsonl"
        make_trail(trail)

        assert main(["verify", str(trail), "--witness", url]) == 2
        assert "unreachable" in capsys.readouterr().out


class TestWitnessCredentialSeparation:
    """REMOTE.md section 8: a witness sits under a DIFFERENT administrative
    authority than the chain server. WAXSEAL_API_KEY is the chain server's
    WRITE credential — a witness that received it could append forged entries
    to the very chain it is supposed to check. Witness requests therefore use
    WAXSEAL_WITNESS_API_KEY and nothing else."""

    def test_the_chain_server_key_never_reaches_a_witness(
        self, tmp_path: Path, witness: tuple[WitnessService, str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        service, url = witness
        monkeypatch.setenv("WAXSEAL_API_KEY", "chain-write-credential")
        monkeypatch.delenv("WAXSEAL_WITNESS_API_KEY", raising=False)
        trail = tmp_path / "trail.jsonl"
        make_trail(trail)

        main(["anchor", str(trail), "--witness", url])
        main(["verify", str(trail), "--witness", url])
        # Both the publish (POST) and the read-back (GET) crossed the wire
        # bare: the chain key must not appear in either direction.
        assert service.auth == [None, None]

    def test_the_witness_key_is_sent_as_a_bearer(
        self, tmp_path: Path, witness: tuple[WitnessService, str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        service, url = witness
        monkeypatch.delenv("WAXSEAL_API_KEY", raising=False)
        monkeypatch.setenv("WAXSEAL_WITNESS_API_KEY", "witness-token")
        trail = tmp_path / "trail.jsonl"
        make_trail(trail)

        main(["anchor", str(trail), "--witness", url])
        main(["verify", str(trail), "--witness", url])
        assert service.auth == ["Bearer witness-token"] * 2


class TestRemoteTrailWithWitness:
    def test_witness_works_for_a_url_target(
        self,
        tmp_path: Path,
        witness: tuple[WitnessService, str],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        # The combination the whole feature exists for: an untrusted chain
        # server, checked against a witness under a different authority.
        from tests.test_cli_pin import TestRemoteTarget

        service, wurl = witness
        server, httpd, thread = TestRemoteTarget()._start_server()
        try:
            url = f"http://127.0.0.1:{httpd.server_address[1]}"
            log = AuditLog.open(url)
            for i in range(3):
                log.append(payload={"i": i}, payload_type=PT)
            service.records.append(
                {
                    "seq": 2,
                    "entry_hash": log.entry_hashes()[-1],
                    "root": __import__("waxseal.domain.checkpoint", fromlist=["checkpoint_for"])
                    .checkpoint_for(log.entry_hashes())
                    .root,
                }
            )
            capsys.readouterr()

            assert main(["verify", url, "--witness", wurl]) == 0
            assert "consistent" in capsys.readouterr().out
        finally:
            httpd.shutdown()
            thread.join(timeout=5)
            httpd.server_close()


class TestReportSurface:
    def test_report_json_lists_each_witness(
        self,
        tmp_path: Path,
        witness: tuple[WitnessService, str],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        _, url = witness
        trail = tmp_path / "trail.jsonl"
        make_trail(trail, 3)
        main(["anchor", str(trail), "--witness", url])
        capsys.readouterr()

        assert main(["report", str(trail), "--json", "--witness", url]) == 0
        witnesses = json.loads(capsys.readouterr().out)["witnesses"]
        assert len(witnesses) == 1
        assert witnesses[0]["status"] == "consistent"

    def test_no_witness_configured_is_not_checked(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        trail = tmp_path / "trail.jsonl"
        make_trail(trail)
        assert main(["report", str(trail), "--json"]) == 0
        assert json.loads(capsys.readouterr().out)["witnesses"] is None

    def test_markdown_names_unreachable_witnesses(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        service = WitnessService()
        httpd, thread, url = start_witness(service)
        httpd.shutdown()
        thread.join(timeout=5)
        httpd.server_close()

        trail = tmp_path / "trail.jsonl"
        make_trail(trail)
        # report carries the same exit-code table as verify: unreachable is
        # unverifiable coverage (2) on both surfaces or the two would disagree.
        assert main(["report", str(trail), "--witness", url]) == 2
        out = capsys.readouterr().out
        assert "unreachable" in out
        assert "not a pass" in out


class TestReadOnly:
    def test_witness_verification_does_not_touch_the_trail(
        self, tmp_path: Path, witness: tuple[WitnessService, str]
    ) -> None:
        _, url = witness
        trail = tmp_path / "trail.jsonl"
        make_trail(trail)
        main(["anchor", str(trail), "--witness", url])
        before = trail.read_bytes()
        main(["verify", str(trail), "--witness", url])
        assert trail.read_bytes() == before
