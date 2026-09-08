"""Tests for the auditor CLI surface: `report`, `export-proof`, `verify-proof`.

All three are read-only, like every command except `anchor` (CLAUDE.md's CLI
contract). Exit codes follow the same three-verdict rule the chain does:
0 intact, 1 broken, 2 intact-but-something-here-cannot-be-verified-by-name,
3 nothing was read because the path does not exist.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from waxseal import AuditLog
from waxseal.cli import main
from waxseal.domain.decision import DecisionRecord, HumanOversight, ModelRef
from waxseal.sources.decisions import commit_input, record_decision

PT = "application/vnd.test.event+json"


def make_trail(path: Path, n: int = 3) -> AuditLog:
    log = AuditLog.open(path)
    for i in range(n):
        log.append(payload={"i": i}, payload_type=PT)
    return log


def make_decision_trail(path: Path) -> AuditLog:
    log = AuditLog.open(path)
    record_decision(
        log,
        DecisionRecord(
            decision_id="d-1",
            decision_type="transaction_approval",
            system_id="payments-agent",
            model=ModelRef(name="risk-llm", version="2026.08"),
            input_commitment=commit_input({"amount": 250}),
            outcome="approve",
            human_oversight=HumanOversight(mode="automated"),
        ),
    )
    record_decision(
        log,
        DecisionRecord(
            decision_id="d-2",
            decision_type="risk_scanning",
            system_id="risk-agent",
            model=ModelRef(name="risk-llm", version="2026.08"),
            input_commitment=commit_input({"amount": 900000}),
            outcome="escalate",
        ),
    )
    return log


def start_fake_chain_server() -> tuple[Any, Any]:
    """A real socket serving REMOTE.md's contract, as tests/test_cli.py does —
    the CLI's URL path deserves an actual HTTP round trip, not a stub."""
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

        def do_GET(self) -> None:
            self._dispatch("GET")

        def do_POST(self) -> None:
            self._dispatch("POST")

        def log_message(self, *args: object) -> None:
            pass

    httpd = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, thread


def break_row(path: Path, seq: int) -> None:
    lines = path.read_text().splitlines()
    obj = json.loads(lines[seq])
    obj["header"]["ts"] = "2027-01-01T00:00:00+00:00"
    lines[seq] = json.dumps(obj)
    path.write_text("\n".join(lines) + "\n")


def make_unverifiable(path: Path, seq: int) -> None:
    """Re-sign a row under a fingerprint this build does not know.

    Changing a row's entry_hash orphans whatever row follows it, so callers
    that need the chain to stay linked must pick the last row.
    """
    from waxseal.domain.hashing import compute_entry_hash
    from waxseal.domain.header import EntryHeader

    lines = path.read_text().splitlines()
    obj = json.loads(lines[seq])
    obj["header"]["hash_version"] = "e" * 64
    obj["entry_hash"] = compute_entry_hash(EntryHeader(**obj["header"]))
    lines[seq] = json.dumps(obj)
    path.write_text("\n".join(lines) + "\n")


class TestReport:
    def test_intact_trail_exits_0_and_prints_markdown(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = tmp_path / "trail.jsonl"
        make_decision_trail(path)
        assert main(["report", str(path)]) == 0
        out = capsys.readouterr().out
        assert "# waxseal audit report" in out
        assert "transaction_approval" in out

    def test_json_flag_emits_parseable_json(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = tmp_path / "trail.jsonl"
        make_decision_trail(path)
        assert main(["report", str(path), "--json"]) == 0
        obj = json.loads(capsys.readouterr().out)
        assert obj["decisions"]["total"] == 2
        assert obj["decisions"]["oversight_unrecorded"] == 1

    def test_broken_trail_exits_1(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        path = tmp_path / "trail.jsonl"
        make_trail(path, 4)
        break_row(path, 1)
        assert main(["report", str(path)]) == 1
        assert "BROKEN" in capsys.readouterr().out

    def test_unverifiable_rows_exit_2_not_1(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = tmp_path / "trail.jsonl"
        make_trail(path, 3)
        make_unverifiable(path, 2)  # last row: the chain stays linked
        assert main(["report", str(path)]) == 2
        out = capsys.readouterr().out
        assert "NOT" in out and "tampering" in out.lower()

    def test_missing_trail_exits_3(self, tmp_path: Path) -> None:
        assert main(["report", str(tmp_path / "nope.jsonl")]) == 3

    def test_report_does_not_write_to_the_trail(self, tmp_path: Path) -> None:
        path = tmp_path / "trail.jsonl"
        make_decision_trail(path)
        before = path.read_bytes()
        main(["report", str(path)])
        assert path.read_bytes() == before

    def test_report_reports_drops_as_unmeasured_when_no_sidecar(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # A CLI process observed no writes, so it must not claim zero.
        path = tmp_path / "trail.jsonl"
        make_trail(path, 2)
        main(["report", str(path), "--json"])
        assert json.loads(capsys.readouterr().out)["completeness"]["dropped_writes"] is None

    def test_anchors_flag_includes_the_anchor_check(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from waxseal.adapters.anchors import FileAnchorSink

        path = tmp_path / "trail.jsonl"
        log = make_trail(path, 3)
        AuditLog(log._backend, anchor_sink=FileAnchorSink(path)).anchor()
        assert main(["report", str(path), "--anchors", "--json"]) == 0
        assert json.loads(capsys.readouterr().out)["anchors"] == {
            "ok": True,
            "checked": 1,
            "reason": None,
            "unverifiable": False,
            "notes": [],
        }

    def test_without_the_flag_anchors_are_reported_unchecked_not_ok(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = tmp_path / "trail.jsonl"
        make_trail(path, 2)
        main(["report", str(path), "--json"])
        assert json.loads(capsys.readouterr().out)["anchors"] is None

    def test_a_broken_anchor_makes_the_report_exit_1(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from waxseal.adapters.anchors import FileAnchorSink

        path = tmp_path / "trail.jsonl"
        log = make_trail(path, 3)
        AuditLog(log._backend, anchor_sink=FileAnchorSink(path)).anchor()
        # Truncate the trail after the checkpoint was taken.
        lines = path.read_text().splitlines()
        path.write_text("\n".join(lines[:2]) + "\n")
        assert main(["report", str(path), "--anchors"]) == 1
        assert "anchor_beyond_head" in capsys.readouterr().out

    def test_malformed_anchor_sidecar_is_a_verdict_not_a_crash(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = tmp_path / "trail.jsonl"
        make_trail(path, 2)
        (tmp_path / "trail.jsonl.anchors").write_text("{not json\n")
        assert main(["report", str(path), "--anchors"]) == 1
        assert "malformed_anchor" in capsys.readouterr().out

    def test_a_measured_drop_count_reaches_the_report(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # The sidecar's count survives the writing process; a fresh CLI run
        # must read it rather than reporting its own unmeasured None.
        path = tmp_path / "trail.jsonl"
        log = AuditLog.open(path, record_drops=True)
        log.append(payload={"i": 0}, payload_type=PT)
        assert log.try_append(payload="not a dict", payload_type=PT) is False  # type: ignore[arg-type]

        main(["report", str(path), "--json"])
        completeness = json.loads(capsys.readouterr().out)["completeness"]
        assert completeness["dropped_writes"] == 1
        assert completeness["drops_source"] == "sidecar"

    def test_anchors_flag_is_labelled_as_a_no_op_for_a_url_target(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # rule 6: a guard that cannot run must say so. A remote target has no
        # local .anchors sidecar, so --anchors would silently do nothing.
        httpd, thread = start_fake_chain_server()
        url = f"http://127.0.0.1:{httpd.server_address[1]}"
        try:
            log = AuditLog.open(url)
            log.append(payload={"i": 0}, payload_type=PT)
            assert main(["report", url, "--anchors"]) == 0
            captured = capsys.readouterr()
            assert "--anchors has no effect" in captured.err
            # And the report itself says the check did not run, rather than
            # rendering a pass it never performed.
            assert "not checked" in captured.out
        finally:
            httpd.shutdown()
            thread.join(timeout=5)


class TestReportSeparationDegree:
    """τ and the enumerated authorities `waxseal report` prints — closing
    conformance.md gap G1. Điều kiện R: these run `main()` for real and
    assert on stdout, not just `build_report()` directly."""

    def test_no_pin_at_all_reports_tau_not_declared(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = tmp_path / "trail.jsonl"
        make_trail(path, 2)
        assert main(["report", str(path), "--json"]) == 0
        obj = json.loads(capsys.readouterr().out)
        assert obj["separation"]["tau"] is None
        assert obj["separation"]["counted_authorities"] is None

        assert main(["report", str(path)]) == 0
        out = capsys.readouterr().out
        line = next(line for line in out.splitlines() if "separation degree" in line)
        assert "not declared" in line

    def test_pin_without_declared_topology_still_reports_not_declared(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = tmp_path / "trail.jsonl"
        pin = tmp_path / "pin.json"
        make_trail(path, 2)
        assert main(["report", str(path), "--pin", str(pin), "--json"]) == 0
        obj = json.loads(capsys.readouterr().out)
        assert obj["separation"]["tau"] is None

    def test_declared_topology_reports_the_number_and_the_enumeration(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = tmp_path / "trail.jsonl"
        pin = tmp_path / "pin.json"
        make_trail(path, 2)
        main(["report", str(path), "--pin", str(pin)])  # trust-on-first-use
        capsys.readouterr()

        state = json.loads(pin.read_text())
        state["declared_topology"] = {
            "seal_escrow": True,
            "anchor_sinks": 2,
            "witness": True,
            "pin_separate": True,
        }
        pin.write_text(json.dumps(state))

        assert main(["report", str(path), "--pin", str(pin), "--json"]) == 0
        obj = json.loads(capsys.readouterr().out)
        assert obj["separation"]["tau"] == 6
        assert obj["separation"]["counted_authorities"] == [
            {"name": "writer", "count": 1},
            {"name": "seal_escrow", "count": 1},
            {"name": "anchor_sinks", "count": 2},
            {"name": "witness", "count": 1},
            {"name": "pin_separate", "count": 1},
        ]

        assert main(["report", str(path), "--pin", str(pin)]) == 0
        out = capsys.readouterr().out
        line = next(line for line in out.splitlines() if "separation degree" in line)
        assert "6" in line
        assert "writer(1)" in line and "anchor_sinks(2)" in line and "witness(1)" in line


class TestExportProof:
    def test_prints_a_bundle_for_the_named_seq(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = tmp_path / "trail.jsonl"
        make_trail(path, 5)
        assert main(["export-proof", str(path), "2"]) == 0
        obj = json.loads(capsys.readouterr().out)
        assert obj["bundle_version"] == "waxseal-proof-bundle-v1"
        assert obj["header"]["seq"] == 2
        assert obj["batch_size"] == 5

    def test_seq_outside_the_trail_exits_1(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = tmp_path / "trail.jsonl"
        make_trail(path, 3)
        assert main(["export-proof", str(path), "9"]) == 1
        assert "9" in capsys.readouterr().err

    def test_negative_seq_exits_1(self, tmp_path: Path) -> None:
        path = tmp_path / "trail.jsonl"
        make_trail(path, 3)
        assert main(["export-proof", str(path), "-1"]) == 1

    def test_empty_trail_exits_1(self, tmp_path: Path) -> None:
        path = tmp_path / "trail.jsonl"
        path.write_text("")
        assert main(["export-proof", str(path), "0"]) == 1

    def test_missing_trail_exits_3(self, tmp_path: Path) -> None:
        assert main(["export-proof", str(tmp_path / "nope.jsonl"), "0"]) == 3

    def test_export_does_not_write_to_the_trail(self, tmp_path: Path) -> None:
        path = tmp_path / "trail.jsonl"
        make_trail(path, 3)
        before = path.read_bytes()
        main(["export-proof", str(path), "1"])
        assert path.read_bytes() == before


class TestVerifyProof:
    def export(self, tmp_path: Path, capsys: pytest.CaptureFixture[str], seq: int = 1) -> Path:
        trail = tmp_path / "trail.jsonl"
        if not trail.exists():
            make_trail(trail, 4)
        main(["export-proof", str(trail), str(seq)])
        bundle = tmp_path / "bundle.json"
        bundle.write_text(capsys.readouterr().out, encoding="utf-8")
        return bundle

    def test_a_freshly_exported_bundle_verifies(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        bundle = self.export(tmp_path, capsys)
        assert main(["verify-proof", str(bundle)]) == 0
        assert "ok" in capsys.readouterr().out

    def test_round_trip_works_for_every_row(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        make_trail(tmp_path / "trail.jsonl", 6)
        for seq in range(6):
            bundle = self.export(tmp_path, capsys, seq)
            assert main(["verify-proof", str(bundle)]) == 0
            capsys.readouterr()

    def test_a_tampered_payload_exits_1(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        import base64

        bundle = self.export(tmp_path, capsys)
        obj = json.loads(bundle.read_text())
        obj["payload_b64"] = base64.b64encode(b'{"i":99}').decode()
        bundle.write_text(json.dumps(obj))
        assert main(["verify-proof", str(bundle)]) == 1
        assert "payload_hash_mismatch" in capsys.readouterr().out

    def test_a_bundle_that_is_not_in_the_anchored_batch_exits_1(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        bundle = self.export(tmp_path, capsys)
        obj = json.loads(bundle.read_text())
        obj["root"] = "f" * 64
        bundle.write_text(json.dumps(obj))
        assert main(["verify-proof", str(bundle)]) == 1
        assert "membership_not_proven" in capsys.readouterr().out

    def test_an_unknown_fingerprint_exits_2_not_1(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # The library's central promise, at the single-row export level.
        trail = tmp_path / "trail.jsonl"
        make_trail(trail, 4)
        make_unverifiable(trail, 1)
        bundle = self.export(tmp_path, capsys, 1)
        assert main(["verify-proof", str(bundle)]) == 2
        out = capsys.readouterr().out
        assert "NOT" in out and "tampering" in out.lower()

    def test_malformed_json_is_a_verdict_not_a_traceback(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        bad = tmp_path / "bad.json"
        bad.write_text("{ not json at all")
        assert main(["verify-proof", str(bad)]) == 1
        err = capsys.readouterr().err
        assert "cannot read bundle" in err
        # A file this build cannot parse is not an accusation against anyone.
        assert "tamper" not in err.lower()

    def test_an_unknown_bundle_format_is_refused_not_called_tampered(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        bundle = self.export(tmp_path, capsys)
        obj = json.loads(bundle.read_text())
        obj["bundle_version"] = "waxseal-proof-bundle-v99"
        bundle.write_text(json.dumps(obj))
        assert main(["verify-proof", str(bundle)]) == 1
        err = capsys.readouterr().err
        assert "v99" in err
        assert "tamper" not in err.lower()

    def test_missing_bundle_file_exits_3(self, tmp_path: Path) -> None:
        assert main(["verify-proof", str(tmp_path / "nope.json")]) == 3

    def test_verify_proof_needs_no_trail_at_all(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # The point of a bundle: the auditor holds this file and nothing else.
        bundle = self.export(tmp_path, capsys)
        (tmp_path / "trail.jsonl").unlink()
        assert main(["verify-proof", str(bundle)]) == 0


class TestNarrowConsole:
    """A legacy console codepage must cost a dash, never a verdict.

    The 0.1.1 install bug was this exact failure class on Windows cp1252:
    the work completed, then writing the answer raised UnicodeEncodeError, so
    the operator got a traceback and a non-zero exit that said nothing about
    the chain. These tests pin the fix in both directions — degrade the stream
    that genuinely cannot carry the output, and leave alone the one that can.
    """

    class FakeStream:
        def __init__(self, encoding: str | None, raises: Exception | None = None) -> None:
            self.encoding = encoding
            self.errors: str | None = None
            self._raises = raises

        def reconfigure(self, *, errors: str) -> None:
            if self._raises is not None:
                raise self._raises
            self.errors = errors

    def test_a_console_that_cannot_encode_the_output_is_degraded(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        out = self.FakeStream("cp1252")
        err = self.FakeStream("cp1252")
        monkeypatch.setattr("waxseal.cli.sys.stdout", out)
        monkeypatch.setattr("waxseal.cli.sys.stderr", err)

        from waxseal.cli import _survive_a_narrow_console

        _survive_a_narrow_console()
        assert out.errors == "backslashreplace"
        assert err.errors == "backslashreplace"

    def test_a_capable_console_is_left_untouched(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Reconfiguring a console that can already encode the output would
        # silently change error handling the operator chose.
        out = self.FakeStream("utf-8")
        monkeypatch.setattr("waxseal.cli.sys.stdout", out)
        monkeypatch.setattr("waxseal.cli.sys.stderr", self.FakeStream("utf-8"))

        from waxseal.cli import _survive_a_narrow_console

        _survive_a_narrow_console()
        assert out.errors is None

    def test_an_unknown_codec_is_treated_as_incapable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # LookupError, not UnicodeEncodeError: a stream naming a codec Python
        # does not have cannot be trusted to carry the output either.
        out = self.FakeStream("not-a-real-codec")
        monkeypatch.setattr("waxseal.cli.sys.stdout", out)
        monkeypatch.setattr("waxseal.cli.sys.stderr", self.FakeStream("utf-8"))

        from waxseal.cli import _survive_a_narrow_console

        _survive_a_narrow_console()
        assert out.errors == "backslashreplace"

    @pytest.mark.parametrize("boom", [ValueError("detached"), OSError("no tty")])
    def test_a_stream_that_refuses_to_be_reconfigured_is_not_fatal(
        self, monkeypatch: pytest.MonkeyPatch, boom: Exception
    ) -> None:
        # Failing to improve the output must never cost more than the output.
        out = self.FakeStream("cp1252", raises=boom)
        monkeypatch.setattr("waxseal.cli.sys.stdout", out)
        monkeypatch.setattr("waxseal.cli.sys.stderr", self.FakeStream("utf-8"))

        from waxseal.cli import _survive_a_narrow_console

        _survive_a_narrow_console()  # must not raise
        assert out.errors is None

    def test_a_stream_without_reconfigure_or_encoding_is_skipped(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # A redirected/wrapped stdout is not necessarily a text stream at all.
        class Bare:
            pass

        monkeypatch.setattr("waxseal.cli.sys.stdout", Bare())
        monkeypatch.setattr("waxseal.cli.sys.stderr", self.FakeStream(None))

        from waxseal.cli import _survive_a_narrow_console

        _survive_a_narrow_console()  # must not raise
