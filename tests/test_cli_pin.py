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

import json
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
