"""`waxseal verify --pin` — trust-on-first-use against a rewritten history.

The scenario these tests exist for is the one plain verification is blind to:
an attacker (or a Byzantine chain server) rewrites the WHOLE trail, re-hashing
every row so the links hold perfectly. `verify` says ok, correctly, because
every question it asks has a true answer. The pin asks a question `verify`
cannot: is this the same history I confirmed last time?

Two behaviors here are security properties rather than conveniences, and each
has a test that fails if it regresses:

- a failing run never advances the pin. If it did, the first tampered read
  would overwrite the evidence and every read after it would pass.
- a pin file that cannot be read is a break, not a silent return to first-use.
  Scribbling over the pin is otherwise a complete bypass.
"""

from __future__ import annotations

import http.server
import json
import threading
from datetime import UTC, datetime
from pathlib import Path

import pytest

from waxseal import AuditLog
from waxseal.cli import main

PT = "application/vnd.test.event+json"


def make_trail(path: Path, n: int = 3, *, start: int = 0) -> None:
    log = AuditLog.open(path)
    for i in range(start, start + n):
        log.append(payload={"i": i}, payload_type=PT)


def rewrite_whole_trail(path: Path, n: int = 3) -> None:
    """A consistently re-hashed history: every link holds, nothing is the
    same. This is the attack `verify` alone cannot see."""
    path.unlink()
    log = AuditLog.open(path)
    for i in range(n):
        log.append(payload={"forged": i}, payload_type=PT)


class TestFirstUse:
    def test_creates_the_pin_and_labels_the_assumption(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        trail = tmp_path / "trail.jsonl"
        pin = tmp_path / "pin.json"
        make_trail(trail)

        assert main(["verify", str(trail), "--pin", str(pin)]) == 0
        out = capsys.readouterr().out
        assert "trust-on-first-use" in out
        # Never silent: the operator must be able to tell an assumption from
        # a check (CLAUDE.md rule 6).
        assert "does not verify" in out
        assert pin.exists()

    def test_pin_records_the_current_head(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        pin = tmp_path / "pin.json"
        make_trail(trail, 4)
        main(["verify", str(trail), "--pin", str(pin)])
        assert json.loads(pin.read_text())["seq"] == 3

    def test_empty_trail_is_labelled_not_pinned(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        trail = tmp_path / "trail.jsonl"
        trail.write_text("")
        pin = tmp_path / "pin.json"
        assert main(["verify", str(trail), "--pin", str(pin)]) == 0
        assert "nothing to pin" in capsys.readouterr().out
        assert not pin.exists()


class TestSteadyState:
    def test_unchanged_trail_passes(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        trail = tmp_path / "trail.jsonl"
        pin = tmp_path / "pin.json"
        make_trail(trail)
        main(["verify", str(trail), "--pin", str(pin)])
        capsys.readouterr()

        assert main(["verify", str(trail), "--pin", str(pin)]) == 0
        assert "pin ok" in capsys.readouterr().out

    def test_appended_trail_passes_and_advances_the_pin(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        pin = tmp_path / "pin.json"
        make_trail(trail, 2)
        main(["verify", str(trail), "--pin", str(pin)])
        make_trail(trail, 2, start=2)

        assert main(["verify", str(trail), "--pin", str(pin)]) == 0
        assert json.loads(pin.read_text())["seq"] == 3


class TestRewrittenHistory:
    def test_whole_trail_rewrite_is_caught(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        trail = tmp_path / "trail.jsonl"
        pin = tmp_path / "pin.json"
        make_trail(trail)
        main(["verify", str(trail), "--pin", str(pin)])
        capsys.readouterr()
        rewrite_whole_trail(trail)

        # Falsifiability receipt for the pin's whole reason to exist: without
        # --pin this same trail verifies clean.
        assert main(["verify", str(trail)]) == 0
        assert main(["verify", str(trail), "--pin", str(pin)]) == 1
        out = capsys.readouterr().out
        assert "PIN BROKEN" in out
        assert "pin_mismatch" in out

    def test_truncation_is_reported_as_rollback(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        trail = tmp_path / "trail.jsonl"
        pin = tmp_path / "pin.json"
        make_trail(trail, 4)
        main(["verify", str(trail), "--pin", str(pin)])
        capsys.readouterr()
        lines = trail.read_text().splitlines()
        trail.write_text("\n".join(lines[:2]) + "\n")

        assert main(["verify", str(trail), "--pin", str(pin)]) == 1
        assert "pin_beyond_head" in capsys.readouterr().out

    def test_a_failing_run_never_advances_the_pin(self, tmp_path: Path) -> None:
        # The property that makes the pin worth anything: one tampered read
        # must not overwrite the memory that detected it.
        trail = tmp_path / "trail.jsonl"
        pin = tmp_path / "pin.json"
        make_trail(trail)
        main(["verify", str(trail), "--pin", str(pin)])
        before = pin.read_bytes()

        rewrite_whole_trail(trail)
        assert main(["verify", str(trail), "--pin", str(pin)]) == 1
        assert pin.read_bytes() == before
        # Still detected on the next run, and the one after that.
        assert main(["verify", str(trail), "--pin", str(pin)]) == 1

    def test_a_broken_chain_does_not_advance_the_pin(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        pin = tmp_path / "pin.json"
        make_trail(trail, 3)
        main(["verify", str(trail), "--pin", str(pin)])
        before = pin.read_bytes()

        make_trail(trail, 1, start=3)
        lines = trail.read_text().splitlines()
        obj = json.loads(lines[3])
        obj["header"]["ts"] = "2027-01-01T00:00:00+00:00"
        lines[3] = json.dumps(obj)
        trail.write_text("\n".join(lines) + "\n")

        assert main(["verify", str(trail), "--pin", str(pin)]) == 1
        assert pin.read_bytes() == before


class TestUnreadablePinState:
    def test_malformed_pin_is_a_break_not_a_re_pin(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        trail = tmp_path / "trail.jsonl"
        pin = tmp_path / "pin.json"
        make_trail(trail)
        pin.write_text("{ garbage", encoding="utf-8")

        assert main(["verify", str(trail), "--pin", str(pin)]) == 1
        assert "malformed_pin" in capsys.readouterr().out
        # The re-pin attack: an attacker who corrupts the pin must not get a
        # fresh trust-on-first-use over the trail they just rewrote.
        assert pin.read_text() == "{ garbage"

    def test_unknown_version_is_unverifiable_not_tampered(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        trail = tmp_path / "trail.jsonl"
        pin = tmp_path / "pin.json"
        make_trail(trail)
        pin.write_text(
            json.dumps(
                {
                    "v": 99,
                    "target": str(trail.resolve()),
                    "chain_id": None,
                    "seq": 0,
                    "entry_hash": "a" * 64,
                    "root": "b" * 64,
                    "pinned_ts": "t",
                }
            ),
            encoding="utf-8",
        )

        assert main(["verify", str(trail), "--pin", str(pin)]) == 2
        out = capsys.readouterr().out
        assert "pin_version_unknown" in out
        assert "NOT evidence of tampering" in out

    def test_unknown_version_is_not_overwritten(self, tmp_path: Path) -> None:
        # A newer waxseal's state file belongs to that build; this one has no
        # business replacing what it could not read.
        trail = tmp_path / "trail.jsonl"
        pin = tmp_path / "pin.json"
        make_trail(trail)
        payload = json.dumps(
            {
                "v": 99,
                "target": str(trail.resolve()),
                "chain_id": None,
                "seq": 0,
                "entry_hash": "a" * 64,
                "root": "b" * 64,
                "pinned_ts": "t",
            }
        )
        pin.write_text(payload, encoding="utf-8")
        main(["verify", str(trail), "--pin", str(pin)])
        assert pin.read_text() == payload


class TestTargetMismatch:
    def test_pin_for_another_trail_is_refused(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        first = tmp_path / "first.jsonl"
        second = tmp_path / "second.jsonl"
        pin = tmp_path / "pin.json"
        make_trail(first)
        make_trail(second)
        main(["verify", str(first), "--pin", str(pin)])
        capsys.readouterr()

        assert main(["verify", str(second), "--pin", str(pin)]) == 1
        assert "pin_target_mismatch" in capsys.readouterr().out

    def test_refusal_does_not_overwrite_the_other_trails_pin(self, tmp_path: Path) -> None:
        first = tmp_path / "first.jsonl"
        second = tmp_path / "second.jsonl"
        pin = tmp_path / "pin.json"
        make_trail(first)
        make_trail(second)
        main(["verify", str(first), "--pin", str(pin)])
        before = pin.read_bytes()

        main(["verify", str(second), "--pin", str(pin)])
        assert pin.read_bytes() == before

    def test_relative_and_absolute_paths_are_the_same_target(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        trail = tmp_path / "trail.jsonl"
        pin = tmp_path / "pin.json"
        make_trail(trail)
        main(["verify", str(trail), "--pin", str(pin)])
        capsys.readouterr()

        monkeypatch.chdir(tmp_path)
        assert main(["verify", "trail.jsonl", "--pin", str(pin)]) == 0
        assert "pin ok" in capsys.readouterr().out


class TestCompositionWithOtherDimensions:
    def test_unverifiable_rows_still_exit_2_with_a_passing_pin(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from waxseal.domain.hashing import compute_entry_hash
        from waxseal.domain.header import EntryHeader

        trail = tmp_path / "trail.jsonl"
        pin = tmp_path / "pin.json"
        make_trail(trail, 2)
        lines = trail.read_text().splitlines()
        obj = json.loads(lines[1])
        obj["header"]["hash_version"] = "e" * 64
        obj["entry_hash"] = compute_entry_hash(EntryHeader(**obj["header"]))
        lines[1] = json.dumps(obj)
        trail.write_text("\n".join(lines) + "\n")

        assert main(["verify", str(trail), "--pin", str(pin)]) == 2
        out = capsys.readouterr().out
        assert "unverifiable" in out
        assert "trust-on-first-use" in out

    def test_a_broken_anchor_still_wins_over_a_passing_pin(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        trail = tmp_path / "trail.jsonl"
        pin = tmp_path / "pin.json"
        make_trail(trail, 3)
        main(["anchor", str(trail)])
        main(["verify", str(trail), "--pin", str(pin)])
        capsys.readouterr()

        anchors = Path(str(trail) + ".anchors")
        record = json.loads(anchors.read_text().strip())
        record["root"] = "c" * 64
        anchors.write_text(json.dumps(record) + "\n")

        assert main(["verify", str(trail), "--pin", str(pin), "--anchors"]) == 1
        out = capsys.readouterr().out
        assert "ANCHOR BROKEN" in out
        assert "pin ok" in out

    def test_pin_is_not_advanced_when_an_anchor_check_fails(self, tmp_path: Path) -> None:
        # Only an overall exit 1 (broken) freezes the pin, whichever dimension
        # found the break: advancing past it would record the tampered state
        # as confirmed. An overall exit 2 still advances (SPEC.md section 13)
        # — unverifiable is not tampered.
        trail = tmp_path / "trail.jsonl"
        pin = tmp_path / "pin.json"
        make_trail(trail, 2)
        main(["verify", str(trail), "--pin", str(pin)])
        before = json.loads(pin.read_text())["seq"]

        main(["anchor", str(trail)])
        anchors = Path(str(trail) + ".anchors")
        record = json.loads(anchors.read_text().strip())
        record["root"] = "c" * 64
        anchors.write_text(json.dumps(record) + "\n")
        make_trail(trail, 2, start=2)

        assert main(["verify", str(trail), "--pin", str(pin), "--anchors"]) == 1
        assert json.loads(pin.read_text())["seq"] == before


class TestInjectableClock:
    def test_an_injected_now_fn_stamps_the_pin(self, tmp_path: Path) -> None:
        # CLAUDE.md rule 8: timestamps are injectable. The pin's write path
        # must accept a now_fn so this test asserts an exact pinned_ts rather
        # than monkeypatching a module global or trusting the wall clock.
        from datetime import UTC, datetime

        from waxseal.cli import _verify

        trail = tmp_path / "trail.jsonl"
        pin = tmp_path / "pin.json"
        make_trail(trail)
        fixed = datetime(2026, 8, 23, 12, 0, 0, tzinfo=UTC)

        code = _verify(
            AuditLog.open(trail),
            trail,
            pin_path=pin,
            target=str(trail.resolve()),
            now_fn=lambda: fixed,
        )
        assert code == 0
        assert json.loads(pin.read_text())["pinned_ts"] == fixed.isoformat()


class TestReportSurface:
    def test_report_renders_the_pin_check(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        trail = tmp_path / "trail.jsonl"
        pin = tmp_path / "pin.json"
        make_trail(trail)
        main(["report", str(trail), "--pin", str(pin)])
        capsys.readouterr()

        assert main(["report", str(trail), "--json", "--pin", str(pin)]) == 0
        obj = json.loads(capsys.readouterr().out)
        assert obj["pin"]["ok"] is True

    def test_report_without_pin_says_not_checked(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # Absence of a check is never a pass (CLAUDE.md rule 5).
        trail = tmp_path / "trail.jsonl"
        make_trail(trail)
        assert main(["report", str(trail), "--json"]) == 0
        assert json.loads(capsys.readouterr().out)["pin"] is None

    def test_report_markdown_names_the_pin(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        trail = tmp_path / "trail.jsonl"
        make_trail(trail)
        main(["report", str(trail)])
        assert "Pin:" in capsys.readouterr().out


class TestReadOnly:
    def test_pinned_verify_does_not_touch_the_trail(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        pin = tmp_path / "pin.json"
        make_trail(trail)
        before = trail.read_bytes()
        main(["verify", str(trail), "--pin", str(pin)])
        main(["verify", str(trail), "--pin", str(pin)])
        assert trail.read_bytes() == before


class TestRemoteTarget:
    """The Byzantine chain server, reduced to the part a client CAN detect.

    REMOTE.md's first normative fact is that the server is a trusted writer,
    not a Byzantine-fault-tolerant peer. A pin narrows what that trust has to
    cover: a server that serves one history and later a different,
    perfectly self-consistent one is caught, because the client remembers.
    (What a pin still cannot catch is split-view — two clients served two
    histories, neither able to see the other's. That needs a witness.)
    """

    def _start_server(self):  # type: ignore[no-untyped-def]
        import http.server
        import threading

        from tests.adapters.fake_chain_server import FakeChainServer

        server = FakeChainServer()

        class Handler(http.server.BaseHTTPRequestHandler):
            def _dispatch(self, method: str) -> None:
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length) if length else None
                status, resp_body = server.handle(method, self.path, dict(self.headers), body)
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(resp_body)

            def do_GET(self) -> None:  # noqa: N802
                self._dispatch("GET")

            def do_POST(self) -> None:  # noqa: N802
                self._dispatch("POST")

            def log_message(self, *args: object) -> None:
                pass

        httpd = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        return server, httpd, thread

    def test_a_server_that_rewrites_history_is_caught(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        server, httpd, thread = self._start_server()
        try:
            url = f"http://127.0.0.1:{httpd.server_address[1]}"
            pin = tmp_path / "pin.json"
            log = AuditLog.open(url)
            for i in range(3):
                log.append(payload={"i": i}, payload_type=PT)

            assert main(["verify", url, "--pin", str(pin)]) == 0
            capsys.readouterr()

            # The server discards what it served and builds a different
            # history that is internally flawless.
            server._chains.clear()
            forged = AuditLog.open(url)
            for i in range(3):
                forged.append(payload={"forged": i}, payload_type=PT)

            # Falsifiability receipt: plain verification is happy with it.
            assert main(["verify", url]) == 0
            capsys.readouterr()

            assert main(["verify", url, "--pin", str(pin)]) == 1
            assert "pin_mismatch" in capsys.readouterr().out
        finally:
            httpd.shutdown()
            thread.join(timeout=5)
            httpd.server_close()

    def test_the_url_is_the_pin_target(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        server, httpd, thread = self._start_server()
        try:
            url = f"http://127.0.0.1:{httpd.server_address[1]}"
            pin = tmp_path / "pin.json"
            log = AuditLog.open(url)
            log.append(payload={"i": 0}, payload_type=PT)
            main(["verify", url, "--pin", str(pin)])
            capsys.readouterr()
            assert json.loads(pin.read_text())["target"] == url
            assert json.loads(pin.read_text())["chain_id"] == "default"
        finally:
            httpd.shutdown()
            thread.join(timeout=5)
            httpd.server_close()


class _WitnessService:
    """A minimal witness: POST appends a checkpoint, GET lists them.

    Same shape as test_cli_witness.py's fixture, kept local rather than
    imported — pytest fixtures do not cross files cleanly, and this file's
    own `_start_server` above already sets the precedent of a small
    self-contained localhost server per test module.
    """

    def __init__(self) -> None:
        self.records: list[dict[str, object]] = []

    def handle(self, method: str, body: bytes | None) -> tuple[int, bytes]:
        if method == "POST":
            assert body is not None
            self.records.append(json.loads(body))
            return 201, json.dumps({"receipt": f"r-{len(self.records)}"}).encode()
        if not self.records:
            return 404, b""
        return 200, json.dumps({"checkpoints": self.records}).encode()


def _start_witness(service: _WitnessService):  # type: ignore[no-untyped-def]
    class Handler(http.server.BaseHTTPRequestHandler):
        def _dispatch(self, method: str) -> None:
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length) if length else None
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


def _duplicate_anchor_record(trail: Path, *, sink: str) -> None:
    """Append one more `.anchors` sidecar record for the SAME checkpoint the
    latest real record already carries, under a different ``sink`` name.

    A cheap way to manufacture a second (or third) "distinct external sink"
    for these tests without standing up a real RFC 3161 responder: the
    separation-shortfall comparison only counts distinct sink identities in
    the sidecar, it does not care whether two different sinks happen to
    agree on the same checkpoint.
    """
    anchors = Path(str(trail) + ".anchors")
    lines = anchors.read_text().splitlines()
    record = json.loads(lines[-1])
    record["sink"] = sink
    anchors.write_text(anchors.read_text() + json.dumps(record) + "\n")


def _add_declared_topology(
    pin: Path,
    *,
    seal_escrow: bool = True,
    anchor_sinks: int,
    witness: bool,
    pin_separate: bool = True,
) -> None:
    """Hand-edit a pin file to add a `declared_topology` directly, bypassing
    `--declare-topology` (waxseal-ekd) — useful here for setting up
    fixtures with values `--declare-topology`'s own spec grammar need not
    exercise (e.g. arbitrary `seal_escrow`/`pin_separate` combinations),
    and for tests of the comparison logic itself in isolation from the
    CLI writer."""
    state = json.loads(pin.read_text())
    state["declared_topology"] = {
        "seal_escrow": seal_escrow,
        "anchor_sinks": anchor_sinks,
        "witness": witness,
        "pin_separate": pin_separate,
    }
    pin.write_text(json.dumps(state))


class TestDeclaredTopologyShortfall:
    """`declared_topology` vs. what a run actually observes
    (waxseal-7tk.3.2).

    A shortfall is a separate, exit-2 finding — "this run corroborated less
    independence than the operator declared" — never exit 1: the trail
    itself still verifies, and CLAUDE.md's collapse theorem forbids
    rendering "under-corroborated" the same as "tampered".
    """

    def test_shortfall_is_exit_2_with_the_reason_named(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        trail = tmp_path / "trail.jsonl"
        pin = tmp_path / "pin.json"
        make_trail(trail, 3)
        main(["anchor", str(trail)])  # one "file" sink record (excluded)
        main(["verify", str(trail), "--pin", str(pin), "--anchors"])
        capsys.readouterr()

        # Declares 2 anchor sinks + a witness; this run will observe only 1
        # external sink and no reachable witness.
        _add_declared_topology(pin, anchor_sinks=2, witness=True)
        _duplicate_anchor_record(trail, sink="rfc3161")

        unreachable = "http://127.0.0.1:1/witness"
        code = main(
            ["verify", str(trail), "--pin", str(pin), "--anchors", "--witness", unreachable]
        )
        out = capsys.readouterr().out
        assert code == 2
        assert "separation_shortfall" in out
        assert "pin ok" in out  # the trail itself still verifies

    def test_shortfall_does_not_fire_when_observed_meets_or_exceeds_declared(
        self, tmp_path: Path, witness_service, capsys: pytest.CaptureFixture[str]
    ) -> None:
        service, url = witness_service
        trail = tmp_path / "trail.jsonl"
        pin = tmp_path / "pin.json"
        make_trail(trail, 3)
        main(["verify", str(trail), "--pin", str(pin)])
        capsys.readouterr()

        _add_declared_topology(pin, anchor_sinks=2, witness=True)
        main(["anchor", str(trail), "--witness", url])  # consistent witness + "file" record
        _duplicate_anchor_record(trail, sink="rfc3161")
        _duplicate_anchor_record(trail, sink="ots")

        code = main(["verify", str(trail), "--pin", str(pin), "--anchors", "--witness", url])
        out = capsys.readouterr().out
        assert code == 0
        assert "separation_shortfall" not in out

    def test_shortfall_check_does_not_fire_when_not_measured_this_run(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # A topology IS declared, but this run passes neither --anchors nor
        # --witness: nothing was measured, so the comparison must not run at
        # all — "not measured" stays distinct from "measured and found
        # short" (rule 5).
        trail = tmp_path / "trail.jsonl"
        pin = tmp_path / "pin.json"
        make_trail(trail, 3)
        main(["verify", str(trail), "--pin", str(pin)])
        capsys.readouterr()

        _add_declared_topology(pin, anchor_sinks=99, witness=True)

        code = main(["verify", str(trail), "--pin", str(pin)])
        out = capsys.readouterr().out
        assert code == 0
        assert "separation_shortfall" not in out
        assert "pin ok" in out

    def test_no_declared_topology_at_all_is_unaffected_even_with_a_thin_setup(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # The overwhelmingly common case today: no pin file has this field.
        # Even with a run that would fail a declared topology (1 sink, no
        # reachable witness), nothing about this bead may change behavior
        # when nothing was ever declared.
        trail = tmp_path / "trail.jsonl"
        pin = tmp_path / "pin.json"
        make_trail(trail, 3)
        main(["anchor", str(trail)])
        assert main(["verify", str(trail), "--pin", str(pin), "--anchors"]) == 0
        capsys.readouterr()

        unreachable = "http://127.0.0.1:1/witness"
        code = main(
            ["verify", str(trail), "--pin", str(pin), "--anchors", "--witness", unreachable]
        )
        out = capsys.readouterr().out
        # Exit 2 here comes only from the unreachable witness, never from a
        # separation check that has nothing to compare against.
        assert code == 2
        assert "separation_shortfall" not in out
        assert "unreachable" in out

    def test_pre_existing_pin_without_the_key_parses_and_behaves_as_before(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # A pin file written by hand in the exact shape a pre-bead build
        # would have written — no declared_topology key anywhere in the
        # JSON — must parse and verify exactly as it always did.
        from waxseal.domain.checkpoint import checkpoint_for

        trail = tmp_path / "trail.jsonl"
        pin = tmp_path / "pin.json"
        make_trail(trail, 3)
        log = AuditLog.open(trail)
        head = checkpoint_for(log.entry_hashes())
        pin.write_text(
            json.dumps(
                {
                    "v": 1,
                    "target": str(trail.resolve()),
                    "chain_id": None,
                    "seq": head.seq,
                    "entry_hash": head.entry_hash,
                    "root": head.root,
                    "pinned_ts": "2026-08-23T09:00:00+00:00",
                }
            )
        )

        assert main(["verify", str(trail), "--pin", str(pin)]) == 0
        out = capsys.readouterr().out
        assert "pin ok" in out
        assert "separation_shortfall" not in out

    def test_declared_topology_survives_a_pin_advance(self, tmp_path: Path) -> None:
        # A shortfall (exit 2) still advances the pin (SPEC.md section 13:
        # unverifiable is not tampered) — and the new pin state must carry
        # the declaration forward, or the check would silently stop working
        # after the very first advance.
        trail = tmp_path / "trail.jsonl"
        pin = tmp_path / "pin.json"
        make_trail(trail, 2)
        main(["verify", str(trail), "--pin", str(pin)])
        _add_declared_topology(pin, anchor_sinks=1, witness=False)

        make_trail(trail, 1, start=2)
        main(["verify", str(trail), "--pin", str(pin)])

        assert json.loads(pin.read_text())["declared_topology"] == {
            "seal_escrow": True,
            "anchor_sinks": 1,
            "witness": False,
            "pin_separate": True,
        }

    def test_no_declared_topology_reports_tau_not_declared(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # Điều kiện R: `verify` with no `--pin` at all must still print τ
        # as "not declared" — a silent absence would be exactly the false
        # confidence rule 5 forbids.
        trail = tmp_path / "trail.jsonl"
        make_trail(trail, 2)
        assert main(["verify", str(trail)]) == 0
        out = capsys.readouterr().out
        line = next(line for line in out.splitlines() if "separation degree" in line)
        assert "not declared" in line
        assert "0" not in line and "1" not in line

    def test_pin_without_declared_topology_still_reports_tau_not_declared(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        trail = tmp_path / "trail.jsonl"
        pin = tmp_path / "pin.json"
        make_trail(trail, 2)
        main(["verify", str(trail), "--pin", str(pin)])  # trust-on-first-use
        capsys.readouterr()

        assert main(["verify", str(trail), "--pin", str(pin)]) == 0
        out = capsys.readouterr().out
        line = next(line for line in out.splitlines() if "separation degree" in line)
        assert "not declared" in line

    def test_declared_topology_reports_the_number_and_the_enumeration(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        trail = tmp_path / "trail.jsonl"
        pin = tmp_path / "pin.json"
        make_trail(trail, 2)
        main(["verify", str(trail), "--pin", str(pin)])  # trust-on-first-use
        _add_declared_topology(pin, anchor_sinks=2, witness=True)
        capsys.readouterr()

        assert main(["verify", str(trail), "--pin", str(pin)]) == 0
        out = capsys.readouterr().out
        line = next(line for line in out.splitlines() if "separation degree" in line)
        # writer(1) + seal_escrow(1) + anchor_sinks(2) + witness(1) + pin_separate(1)
        assert "6" in line
        assert "writer(1)" in line and "anchor_sinks(2)" in line and "witness(1)" in line


def _add_max_anchor_age(pin: Path, *, max_anchor_age_s: int) -> None:
    """Hand-edit a pin file to add `max_anchor_age_s`, standing in for the
    not-yet-built CLI flag to declare one (out of this bead's scope — only
    `domain/pinning.py` parse/render and the `cli.py` comparison are wired
    here)."""
    state = json.loads(pin.read_text())
    state["max_anchor_age_s"] = max_anchor_age_s
    pin.write_text(json.dumps(state))


def _set_last_anchor_ts(trail: Path, ts: str) -> None:
    """Hand-edit the last `.anchors` record's `ts` field, keeping its
    checkpoint (seq/entry_hash/root) untouched so `verify --anchors` still
    finds it consistent — only the anchor_staleness input changes."""
    anchors = Path(str(trail) + ".anchors")
    lines = anchors.read_text().splitlines()
    record = json.loads(lines[-1])
    record["ts"] = ts
    lines[-1] = json.dumps(record)
    anchors.write_text("\n".join(lines) + "\n")


def _add_expect_anchor_binding(pin: Path, *, expect_anchor_binding: bool = True) -> None:
    """Hand-edit a pin file to add `expect_anchor_binding` directly,
    bypassing `--expect-anchor-binding` (waxseal-ekd) — kept for tests of
    the comparison logic itself in isolation from the CLI writer."""
    state = json.loads(pin.read_text())
    state["expect_anchor_binding"] = expect_anchor_binding
    pin.write_text(json.dumps(state))


def _append_anchor_record(
    trail: Path,
    *,
    seq: int,
    agg_commit: str | None = None,
    agg_epoch: int | None = None,
    sink: str = "test",
    v: int | None = None,
    ts: str = "2026-08-29T12:00:00+00:00",
) -> None:
    """Append one hand-built `.anchors` sidecar record for checkpoint ``seq``
    of the CURRENT trail. ``entry_hash``/``root`` are computed from the
    trail's own entry hashes so `verify --anchors` still finds the
    chain-shape claim consistent (exit 1 is not what these tests are
    about) — only the aggregate-binding fields and format version are the
    test's to control, matching ``_duplicate_anchor_record``'s precedent of
    hand-editing the sidecar directly rather than standing up a real
    aggregate-sealing sink."""
    from waxseal.domain.checkpoint import checkpoint_for

    log = AuditLog.open(trail)
    hashes = log.entry_hashes()
    cp = checkpoint_for(hashes[: seq + 1])
    record: dict[str, object] = {
        "seq": cp.seq,
        "entry_hash": cp.entry_hash,
        "root": cp.root,
        "sink": sink,
        "receipt": None,
        "ts": ts,
        "v": v if v is not None else (2 if agg_commit is not None else 1),
    }
    if agg_commit is not None:
        record["agg_commit"] = agg_commit
        record["agg_epoch"] = agg_epoch
    anchors = Path(str(trail) + ".anchors")
    with open(anchors, "a") as f:
        f.write(json.dumps(record) + "\n")


def _append_unreadable_anchor_record(trail: Path, *, v: str = "99") -> None:
    """Append a sidecar record stamped with a format version this build does
    not know. ``read_anchor_records`` reports an unknown version as
    unreadable-by-name without even inspecting the rest of the record (see
    its own source), so no seq/entry_hash/root is needed here."""
    anchors = Path(str(trail) + ".anchors")
    with open(anchors, "a") as f:
        f.write(json.dumps({"v": v}) + "\n")


class TestAnchorStaleness:
    """`max_anchor_age_s` on a declared pin vs. what `.anchors` actually
    shows this run (waxseal-7tk.4.1, W4/C3).

    Silence past the deadline is itself the finding — exit 2, never exit 1:
    the trail itself still verifies, only corroborating evidence has gone
    quiet. `now_fn` is injected throughout (rule 8: tests never sleep, and
    must not depend on the wall clock to pass or fail deterministically).
    """

    FIXED = datetime(2026, 8, 29, 12, 0, 0, tzinfo=UTC)

    def _verify_at(
        self, trail: Path, *, pin: Path, check_anchors: bool = True
    ) -> int:
        from waxseal.cli import _verify

        return _verify(
            AuditLog.open(trail),
            trail,
            check_anchors=check_anchors,
            pin_path=pin,
            target=str(trail.resolve()),
            now_fn=lambda: self.FIXED,
        )

    def test_fresh_anchor_is_exit_0(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        trail = tmp_path / "trail.jsonl"
        pin = tmp_path / "pin.json"
        make_trail(trail, 3)
        main(["verify", str(trail), "--pin", str(pin)])
        capsys.readouterr()

        _add_max_anchor_age(pin, max_anchor_age_s=3600)
        main(["anchor", str(trail)])
        _set_last_anchor_ts(trail, "2026-08-29T11:59:00+00:00")  # 1 min old

        code = self._verify_at(trail, pin=pin)
        out = capsys.readouterr().out
        assert code == 0
        assert "anchor_stale" not in out

    def test_stale_anchor_is_exit_2_with_the_reason_named(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        trail = tmp_path / "trail.jsonl"
        pin = tmp_path / "pin.json"
        make_trail(trail, 3)
        main(["verify", str(trail), "--pin", str(pin)])
        capsys.readouterr()

        _add_max_anchor_age(pin, max_anchor_age_s=3600)
        main(["anchor", str(trail)])
        _set_last_anchor_ts(trail, "2026-08-29T10:00:00+00:00")  # 2h old, Δ=1h

        code = self._verify_at(trail, pin=pin)
        out = capsys.readouterr().out
        assert code == 2
        assert "anchor_stale" in out
        assert "pin ok" in out  # the trail itself still verifies

    def test_zero_anchor_records_is_exit_2_not_exit_1(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # No `anchor` command ever run: the `.anchors` sidecar does not
        # exist, so this run measures zero records. Absence of anchoring
        # evidence is itself staleness ("vắng anchor = vắng bằng chứng"),
        # never rendered as a broken (exit 1) trail.
        trail = tmp_path / "trail.jsonl"
        pin = tmp_path / "pin.json"
        make_trail(trail, 3)
        main(["verify", str(trail), "--pin", str(pin)])
        capsys.readouterr()

        _add_max_anchor_age(pin, max_anchor_age_s=3600)

        code = self._verify_at(trail, pin=pin)
        out = capsys.readouterr().out
        assert code == 2
        assert "anchor_stale" in out

    def test_no_delta_declared_no_check_even_with_an_ancient_anchor(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # max_anchor_age_s is never declared on this pin. Even a deliberately
        # ancient anchor record must not produce a staleness finding.
        trail = tmp_path / "trail.jsonl"
        pin = tmp_path / "pin.json"
        make_trail(trail, 3)
        main(["verify", str(trail), "--pin", str(pin)])
        capsys.readouterr()

        main(["anchor", str(trail)])
        _set_last_anchor_ts(trail, "2000-01-01T00:00:00+00:00")

        code = self._verify_at(trail, pin=pin)
        out = capsys.readouterr().out
        assert code == 0
        assert "anchor_stale" not in out

    def test_delta_declared_but_anchors_not_checked_this_run(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # A deadline IS declared, but this run passes no --anchors: nothing
        # was measured, so the comparison must not run at all — the exit
        # code must match what it would be with no Δ declared at all (rule
        # 5: "not measured" stays distinct from "measured and found short").
        trail = tmp_path / "trail.jsonl"
        pin = tmp_path / "pin.json"
        make_trail(trail, 3)
        main(["verify", str(trail), "--pin", str(pin)])
        capsys.readouterr()

        _add_max_anchor_age(pin, max_anchor_age_s=1)  # an impossibly tight Δ
        main(["anchor", str(trail)])
        _set_last_anchor_ts(trail, "2000-01-01T00:00:00+00:00")

        code = self._verify_at(trail, pin=pin, check_anchors=False)
        out = capsys.readouterr().out
        assert code == 0
        assert "anchor_stale" not in out

    def test_unparseable_timestamp_is_unverifiable_not_broken(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        trail = tmp_path / "trail.jsonl"
        pin = tmp_path / "pin.json"
        make_trail(trail, 3)
        main(["verify", str(trail), "--pin", str(pin)])
        capsys.readouterr()

        _add_max_anchor_age(pin, max_anchor_age_s=3600)
        main(["anchor", str(trail)])
        _set_last_anchor_ts(trail, "not-a-timestamp")

        code = self._verify_at(trail, pin=pin)
        out = capsys.readouterr().out
        assert code == 2
        assert "anchor_timestamp_unparseable" in out
        assert "anchor_stale" not in out

    def test_old_pin_file_without_the_key_behaves_as_before(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # A pin file written by hand in the exact shape a pre-bead build
        # would have written — no max_anchor_age_s key anywhere in the
        # JSON — must parse and verify exactly as it always did, even with
        # an ancient anchor record sitting right next to it.
        from waxseal.domain.checkpoint import checkpoint_for

        trail = tmp_path / "trail.jsonl"
        pin = tmp_path / "pin.json"
        make_trail(trail, 3)
        log = AuditLog.open(trail)
        head = checkpoint_for(log.entry_hashes())
        pin.write_text(
            json.dumps(
                {
                    "v": 1,
                    "target": str(trail.resolve()),
                    "chain_id": None,
                    "seq": head.seq,
                    "entry_hash": head.entry_hash,
                    "root": head.root,
                    "pinned_ts": "2026-08-23T09:00:00+00:00",
                }
            )
        )
        main(["anchor", str(trail)])
        _set_last_anchor_ts(trail, "2000-01-01T00:00:00+00:00")

        code = self._verify_at(trail, pin=pin)
        out = capsys.readouterr().out
        assert code == 0
        assert "pin ok" in out
        assert "anchor_stale" not in out
        assert "max_anchor_age_s" not in json.loads(pin.read_text())

    def test_max_anchor_age_survives_a_pin_advance(self, tmp_path: Path) -> None:
        # Exit 2 still advances the pin (SPEC.md section 13: unverifiable is
        # not tampered) — and the new pin state must carry the declaration
        # forward, or the check would silently stop working after the very
        # first advance (the declared_topology bead's own lesson, repeated
        # here for this field).
        trail = tmp_path / "trail.jsonl"
        pin = tmp_path / "pin.json"
        make_trail(trail, 2)
        main(["verify", str(trail), "--pin", str(pin)])
        _add_max_anchor_age(pin, max_anchor_age_s=3600)

        make_trail(trail, 1, start=2)
        main(["verify", str(trail), "--pin", str(pin)])

        assert json.loads(pin.read_text())["max_anchor_age_s"] == 3600

    def test_staleness_is_checked_before_separation_shortfall(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # Both conditions can be true in the same run; _pin_check's
        # documented ordering says anchor_staleness wins the single `reason`
        # slot when that happens.
        trail = tmp_path / "trail.jsonl"
        pin = tmp_path / "pin.json"
        make_trail(trail, 3)
        main(["anchor", str(trail)])
        main(["verify", str(trail), "--pin", str(pin), "--anchors"])
        capsys.readouterr()

        pin_obj = json.loads(pin.read_text())
        pin_obj["max_anchor_age_s"] = 3600
        pin_obj["declared_topology"] = {
            "seal_escrow": True,
            "anchor_sinks": 2,
            "witness": True,
            "pin_separate": True,
        }
        pin.write_text(json.dumps(pin_obj))
        _set_last_anchor_ts(trail, "2000-01-01T00:00:00+00:00")

        code = self._verify_at(trail, pin=pin)
        out = capsys.readouterr().out
        assert code == 2
        assert "anchor_stale" in out
        assert "separation_shortfall" not in out


class TestAnchorPolicyDowngrade:
    """`expect_anchor_binding` vs. what `.anchors` actually shows this run
    (waxseal-7tk.5.1, W5/F2).

    A v1 checkpoint frame is byte-identical whether or not an aggregate
    binding exists, so an attacker who controls the `.anchors` sidecar can
    silently present only v1-shaped records and strip SPEC §15's
    replay-plus-truncate protection. This class is the PoC that turns that
    finding from [Inference] into [Verified]: exit 2, never exit 1 — the
    trail itself still verifies, only the declared policy goes
    uncorroborated.
    """

    def _verify_at(
        self, trail: Path, *, pin: Path, check_anchors: bool = True
    ) -> int:
        from waxseal.cli import _verify

        return _verify(
            AuditLog.open(trail),
            trail,
            check_anchors=check_anchors,
            pin_path=pin,
            target=str(trail.resolve()),
        )

    def test_only_v1_shaped_records_is_exit_2(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # Case 1 — the bead's own stated goal: PoC turning F2 from
        # [Inference] to [Verified]. Airtight: a flag-on pin, a sidecar
        # holding only ordinary v1 records, no binding anywhere.
        trail = tmp_path / "trail.jsonl"
        pin = tmp_path / "pin.json"
        make_trail(trail, 3)
        main(["verify", str(trail), "--pin", str(pin)])
        capsys.readouterr()

        _add_expect_anchor_binding(pin)
        main(["anchor", str(trail)])  # ordinary v1 record, no binding

        code = self._verify_at(trail, pin=pin)
        out = capsys.readouterr().out
        assert code == 2
        assert "anchor_policy_downgrade" in out
        assert "pin ok" in out  # the trail itself still verifies

    def test_binding_at_or_after_pinned_seq_is_exit_0(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # Case 2.
        trail = tmp_path / "trail.jsonl"
        pin = tmp_path / "pin.json"
        make_trail(trail, 3)
        main(["verify", str(trail), "--pin", str(pin)])
        capsys.readouterr()

        _add_expect_anchor_binding(pin)
        pinned_seq = json.loads(pin.read_text())["seq"]
        _append_anchor_record(trail, seq=pinned_seq, agg_commit="commit-1", agg_epoch=1)

        code = self._verify_at(trail, pin=pin)
        out = capsys.readouterr().out
        assert code == 0
        assert "anchor_policy_downgrade" not in out
        assert "anchor_binding_unreadable" not in out

    def test_binding_strictly_before_pinned_seq_is_exit_2(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # Case 3: a binding exists, but only before the pinned seq — it does
        # not corroborate the declared policy going forward.
        trail = tmp_path / "trail.jsonl"
        pin = tmp_path / "pin.json"
        make_trail(trail, 5)
        _append_anchor_record(trail, seq=1, agg_commit="commit-1", agg_epoch=1)
        main(["verify", str(trail), "--pin", str(pin)])  # pins at seq=4
        capsys.readouterr()

        _add_expect_anchor_binding(pin)
        assert json.loads(pin.read_text())["seq"] == 4

        code = self._verify_at(trail, pin=pin)
        out = capsys.readouterr().out
        assert code == 2
        assert "anchor_policy_downgrade" in out

    def test_unreadable_record_is_exit_2_with_unreadable_reason_not_downgrade(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # Case 4: an unreadable-format record means "no binding found among
        # the readable ones" is NOT evidence there is truly no binding.
        trail = tmp_path / "trail.jsonl"
        pin = tmp_path / "pin.json"
        make_trail(trail, 3)
        main(["verify", str(trail), "--pin", str(pin)])
        capsys.readouterr()

        _add_expect_anchor_binding(pin)
        _append_unreadable_anchor_record(trail)

        code = self._verify_at(trail, pin=pin)
        out = capsys.readouterr().out
        assert code == 2
        assert "anchor_binding_unreadable" in out
        assert "anchor_policy_downgrade" not in out

    def test_flag_off_no_check_even_with_only_v1_records(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # expect_anchor_binding is never declared (stays at its False
        # default) — the exact sidecar contents that trip case 1 above must
        # produce no finding at all when the operator never asked.
        trail = tmp_path / "trail.jsonl"
        pin = tmp_path / "pin.json"
        make_trail(trail, 3)
        main(["verify", str(trail), "--pin", str(pin)])
        capsys.readouterr()

        main(["anchor", str(trail)])  # v1 only, ancient by construction age

        code = self._verify_at(trail, pin=pin)
        out = capsys.readouterr().out
        assert code == 0
        assert "anchor_policy_downgrade" not in out
        assert "anchor_binding_unreadable" not in out

    def test_flag_on_but_anchors_not_checked_this_run(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # A binding IS expected, but this run passes no --anchors: nothing
        # was measured, so the comparison must not run at all (rule 5).
        trail = tmp_path / "trail.jsonl"
        pin = tmp_path / "pin.json"
        make_trail(trail, 3)
        main(["verify", str(trail), "--pin", str(pin)])
        capsys.readouterr()

        _add_expect_anchor_binding(pin)
        main(["anchor", str(trail)])  # v1 only — would downgrade if checked

        code = self._verify_at(trail, pin=pin, check_anchors=False)
        out = capsys.readouterr().out
        assert code == 0
        assert "anchor_policy_downgrade" not in out
        assert "pin ok" in out

    def test_old_pin_file_without_the_key_behaves_as_before(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # A pin file written by hand in the exact shape a pre-bead build
        # would have written — no expect_anchor_binding key anywhere in the
        # JSON — must parse and verify exactly as it always did, even with
        # a sidecar full of nothing but v1 records.
        from waxseal.domain.checkpoint import checkpoint_for

        trail = tmp_path / "trail.jsonl"
        pin = tmp_path / "pin.json"
        make_trail(trail, 3)
        log = AuditLog.open(trail)
        head = checkpoint_for(log.entry_hashes())
        pin.write_text(
            json.dumps(
                {
                    "v": 1,
                    "target": str(trail.resolve()),
                    "chain_id": None,
                    "seq": head.seq,
                    "entry_hash": head.entry_hash,
                    "root": head.root,
                    "pinned_ts": "2026-08-23T09:00:00+00:00",
                }
            )
        )
        main(["anchor", str(trail)])

        code = self._verify_at(trail, pin=pin)
        out = capsys.readouterr().out
        assert code == 0
        assert "pin ok" in out
        assert "anchor_policy_downgrade" not in out
        # expect_anchor_binding is always rendered explicitly (unlike
        # declared_topology/max_anchor_age_s's omit-when-absent
        # convention) — an old pin file with the key missing entirely
        # still advances to an explicit False, never an error.
        assert json.loads(pin.read_text())["expect_anchor_binding"] is False

    def test_downgrade_survives_a_pin_advance(self, tmp_path: Path) -> None:
        # Exit 2 still advances the pin (SPEC.md section 13: unverifiable is
        # not tampered) — and the new pin state must carry the declaration
        # forward, or the check would silently stop working after the very
        # first advance (the same lesson declared_topology/max_anchor_age_s
        # already had to learn).
        trail = tmp_path / "trail.jsonl"
        pin = tmp_path / "pin.json"
        make_trail(trail, 2)
        main(["verify", str(trail), "--pin", str(pin)])
        _add_expect_anchor_binding(pin)
        main(["anchor", str(trail)])  # v1 only

        make_trail(trail, 1, start=2)
        self._verify_at(trail, pin=pin)

        assert json.loads(pin.read_text())["expect_anchor_binding"] is True

    def test_downgrade_is_checked_before_anchor_staleness(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # Both conditions can be true in the same run; _pin_check's
        # documented ordering says anchor_policy_downgrade wins the single
        # `reason` slot when that happens — it is the direct F2 finding.
        trail = tmp_path / "trail.jsonl"
        pin = tmp_path / "pin.json"
        make_trail(trail, 3)
        main(["anchor", str(trail)])  # v1 only, no binding
        main(["verify", str(trail), "--pin", str(pin), "--anchors"])
        capsys.readouterr()

        pin_obj = json.loads(pin.read_text())
        pin_obj["expect_anchor_binding"] = True
        pin_obj["max_anchor_age_s"] = 3600
        pin.write_text(json.dumps(pin_obj))
        _set_last_anchor_ts(trail, "2000-01-01T00:00:00+00:00")  # ancient -> stale too

        code = self._verify_at(trail, pin=pin)
        out = capsys.readouterr().out
        assert code == 2
        assert "anchor_policy_downgrade" in out
        assert "anchor_stale" not in out


class TestDeclaredTopologySpecParsing:
    """`_parse_declared_topology_spec` — the `--declare-topology` grammar
    itself, exercised directly rather than only through a full CLI run, so
    every malformed-input branch gets its own case instead of leaning on
    argparse's own error path for all of them.
    """

    def test_a_trailing_comma_is_tolerated(self) -> None:
        from waxseal.cli import _parse_declared_topology_spec

        topology = _parse_declared_topology_spec(
            "seal_escrow=true,anchor_sinks=2,witness=true,pin_separate=true,"
        )
        assert topology.anchor_sinks == 2

    def test_a_token_without_equals_is_rejected(self) -> None:
        from waxseal.cli import _parse_declared_topology_spec

        with pytest.raises(ValueError, match="expected key=value"):
            _parse_declared_topology_spec("seal_escrow")

    def test_a_duplicated_key_is_rejected(self) -> None:
        from waxseal.cli import _parse_declared_topology_spec

        with pytest.raises(ValueError, match="given more than once"):
            _parse_declared_topology_spec(
                "seal_escrow=true,seal_escrow=false,anchor_sinks=2,"
                "witness=true,pin_separate=true"
            )

    def test_an_unknown_field_is_rejected(self) -> None:
        from waxseal.cli import _parse_declared_topology_spec

        with pytest.raises(ValueError, match="unknown declared_topology field"):
            _parse_declared_topology_spec(
                "seal_escrow=true,anchor_sinks=2,witness=true,pin_separate=true,"
                "extra=true"
            )

    def test_a_non_boolean_value_is_rejected(self) -> None:
        from waxseal.cli import _parse_declared_topology_spec

        with pytest.raises(ValueError, match="must be 'true' or 'false'"):
            _parse_declared_topology_spec(
                "seal_escrow=yes,anchor_sinks=2,witness=true,pin_separate=true"
            )

    def test_a_non_integer_anchor_sinks_is_rejected(self) -> None:
        from waxseal.cli import _parse_declared_topology_spec

        with pytest.raises(ValueError, match="must be an integer"):
            _parse_declared_topology_spec(
                "seal_escrow=true,anchor_sinks=two,witness=true,pin_separate=true"
            )


class TestDeclareViaCLI:
    """CLI flags that WRITE `expect_anchor_binding`/`max_anchor_age_s`/
    `declared_topology` onto the pin state (waxseal-ekd, closing
    conformance.md gap G2). Before this, the only route was hand-editing
    the JSON — every other test in this file used `_add_declared_topology`/
    `_add_expect_anchor_binding` as a stand-in for exactly this.
    """

    def test_expect_anchor_binding_alone_is_true_others_omitted(
        self, tmp_path: Path
    ) -> None:
        trail = tmp_path / "trail.jsonl"
        pin = tmp_path / "pin.json"
        make_trail(trail, 2)

        assert (
            main(["verify", str(trail), "--pin", str(pin), "--expect-anchor-binding"]) == 0
        )
        state = json.loads(pin.read_text())
        assert state["expect_anchor_binding"] is True
        assert "max_anchor_age_s" not in state
        assert "declared_topology" not in state

    def test_max_anchor_age_s_alone_writes_exactly_that_int(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        pin = tmp_path / "pin.json"
        make_trail(trail, 2)

        assert main(["verify", str(trail), "--pin", str(pin), "--max-anchor-age-s", "3600"]) == 0
        state = json.loads(pin.read_text())
        assert state["max_anchor_age_s"] == 3600
        assert state["expect_anchor_binding"] is False
        assert "declared_topology" not in state

    def test_declare_topology_all_four_together_writes_the_complete_object(
        self, tmp_path: Path
    ) -> None:
        trail = tmp_path / "trail.jsonl"
        pin = tmp_path / "pin.json"
        make_trail(trail, 2)

        code = main(
            [
                "verify", str(trail), "--pin", str(pin),
                "--declare-topology",
                "seal_escrow=true,anchor_sinks=2,witness=true,pin_separate=false",
            ]
        )
        assert code == 0
        state = json.loads(pin.read_text())
        assert state["declared_topology"] == {
            "seal_escrow": True,
            "anchor_sinks": 2,
            "witness": True,
            "pin_separate": False,
        }

    def test_declare_topology_partial_is_a_cli_usage_error(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        trail = tmp_path / "trail.jsonl"
        pin = tmp_path / "pin.json"
        make_trail(trail, 2)

        with pytest.raises(SystemExit) as exc:
            main(
                [
                    "verify", str(trail), "--pin", str(pin),
                    # missing witness/pin_separate — never silently False-filled
                    "--declare-topology", "seal_escrow=true,anchor_sinks=2",
                ]
            )
        assert exc.value.code == 2
        err = capsys.readouterr().err
        assert "declare-topology" in err
        assert "missing" in err
        # Nothing was read, nothing was written: the trail was never opened.
        assert not pin.exists()

    def test_declare_flags_without_pin_is_a_usage_error(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        trail = tmp_path / "trail.jsonl"
        make_trail(trail, 2)

        with pytest.raises(SystemExit) as exc:
            main(["verify", str(trail), "--expect-anchor-binding"])
        assert exc.value.code == 2
        assert "--pin" in capsys.readouterr().err

    def test_declare_on_a_broken_run_does_not_apply(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # A break freezes the pin (SPEC.md section 13) — a declaration
        # offered on that same run must not sneak onto a pin that was never
        # advanced.
        trail = tmp_path / "trail.jsonl"
        pin = tmp_path / "pin.json"
        make_trail(trail, 3)
        main(["verify", str(trail), "--pin", str(pin)])
        before = pin.read_text()
        rewrite_whole_trail(trail, 3)

        code = main(
            ["verify", str(trail), "--pin", str(pin), "--expect-anchor-binding"]
        )
        capsys.readouterr()
        assert code == 1
        assert pin.read_text() == before

    def test_declare_on_report_pin_flow_too(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        pin = tmp_path / "pin.json"
        make_trail(trail, 2)

        assert (
            main(["report", str(trail), "--pin", str(pin), "--expect-anchor-binding"]) == 0
        )
        assert json.loads(pin.read_text())["expect_anchor_binding"] is True

    def test_declaring_again_without_the_flag_preserves_the_prior_declaration(
        self, tmp_path: Path
    ) -> None:
        trail = tmp_path / "trail.jsonl"
        pin = tmp_path / "pin.json"
        make_trail(trail, 2)
        main(["verify", str(trail), "--pin", str(pin), "--max-anchor-age-s", "3600"])

        make_trail(trail, 1, start=2)
        assert main(["verify", str(trail), "--pin", str(pin)]) == 0
        assert json.loads(pin.read_text())["max_anchor_age_s"] == 3600

    def test_old_pin_without_the_fields_then_declaring_on_the_next_run_works(
        self, tmp_path: Path
    ) -> None:
        # A pin file in the exact shape a pre-0.1.4 build would have
        # written: no expect_anchor_binding/max_anchor_age_s/
        # declared_topology key anywhere. Still readable, and a declaration
        # offered on the very next run lands correctly (SPEC 13.1's backward
        # compatibility guarantee, exercised through the new flags rather
        # than by hand-editing).
        from waxseal.domain.checkpoint import checkpoint_for

        trail = tmp_path / "trail.jsonl"
        pin = tmp_path / "pin.json"
        make_trail(trail, 3)
        log = AuditLog.open(trail)
        head = checkpoint_for(log.entry_hashes())
        pin.write_text(
            json.dumps(
                {
                    "v": 1,
                    "target": str(trail.resolve()),
                    "chain_id": None,
                    "seq": head.seq,
                    "entry_hash": head.entry_hash,
                    "root": head.root,
                    "pinned_ts": "2020-01-01T00:00:00+00:00",
                }
            )
        )

        make_trail(trail, 1, start=3)
        code = main(
            ["verify", str(trail), "--pin", str(pin), "--expect-anchor-binding"]
        )
        assert code == 0
        state = json.loads(pin.read_text())
        assert state["expect_anchor_binding"] is True
        assert "max_anchor_age_s" not in state
        assert "declared_topology" not in state


@pytest.fixture
def witness_service():  # type: ignore[no-untyped-def]
    service = _WitnessService()
    httpd, thread, url = _start_witness(service)
    try:
        yield service, url
    finally:
        httpd.shutdown()
        thread.join(timeout=5)
        httpd.server_close()
