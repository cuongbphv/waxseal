"""Tests for the CLI contract (CLAUDE.md): verify exits 0 intact / 1 broken /
2 intact-but-unverifiable-present. The CLI never writes to the log."""

import json
from pathlib import Path

import pytest

from waxseal import AuditLog
from waxseal.cli import main

PT = "application/vnd.test.event+json"


def make_trail(path: Path, n: int = 3) -> None:
    log = AuditLog.open(path)
    for i in range(n):
        log.append(payload={"i": i}, payload_type=PT)


class TestVerify:
    def test_intact_trail_exits_0(self, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        path = tmp_path / "trail.jsonl"
        make_trail(path)
        assert main(["verify", str(path)]) == 0
        assert "ok" in capsys.readouterr().out

    def test_broken_trail_exits_1_and_names_the_break(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        path = tmp_path / "trail.jsonl"
        make_trail(path, 4)
        lines = path.read_text().splitlines()
        obj = json.loads(lines[1])
        obj["header"]["ts"] = "2027-01-01T00:00:00+00:00"
        lines[1] = json.dumps(obj)
        path.write_text("\n".join(lines) + "\n")

        assert main(["verify", str(path)]) == 1
        out = capsys.readouterr().out
        assert "seq=1" in out
        assert "entry_hash_mismatch" in out

    def test_unverifiable_rows_exit_2_not_1(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        # The beads-v1.2.2 replay: rows from an unknown (newer) schema must
        # NOT be reported as tampering — exit 2, distinct from broken.
        path = tmp_path / "trail.jsonl"
        make_trail(path, 2)
        lines = path.read_text().splitlines()
        # Re-sign row 1 under a fingerprint this binary does not know.
        from waxseal.domain.hashing import compute_entry_hash
        from waxseal.domain.header import EntryHeader

        obj = json.loads(lines[1])
        obj["header"]["hash_version"] = "e" * 64
        header = EntryHeader(**obj["header"])
        obj["entry_hash"] = compute_entry_hash(header)
        lines[1] = json.dumps(obj)
        path.write_text("\n".join(lines) + "\n")

        assert main(["verify", str(path)]) == 2
        out = capsys.readouterr().out
        assert "unverifiable" in out

    def test_verify_does_not_modify_the_file(self, tmp_path: Path) -> None:
        path = tmp_path / "trail.jsonl"
        make_trail(path)
        before = path.read_bytes()
        main(["verify", str(path)])
        assert path.read_bytes() == before


class TestTailAndInspect:
    def test_tail_prints_last_entries(self, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        path = tmp_path / "trail.jsonl"
        make_trail(path, 5)
        assert main(["tail", str(path), "-n", "2"]) == 0
        out = capsys.readouterr().out
        assert "seq=3" in out
        assert "seq=4" in out
        assert "seq=2" not in out

    def test_inspect_prints_fingerprint_summary(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        path = tmp_path / "trail.jsonl"
        make_trail(path, 3)
        assert main(["inspect", str(path)]) == 0
        out = capsys.readouterr().out
        # lp64v2 is the wired default for every new trail (waxseal-7tk.7.4,
        # no opt-in) -- make_trail() writes real entries through
        # AuditLog.append(), so they carry fingerprint(), not v1.
        from waxseal.domain.fingerprint import fingerprint

        assert fingerprint()[:12] in out
        assert "3" in out


class TestDropCountReporting:
    """M5: verify/inspect surface `.drops` sidecar coverage without ever
    touching the chain's own exit code (completeness != integrity)."""

    def test_no_sidecar_prints_nothing_new(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        path = tmp_path / "trail.jsonl"
        make_trail(path)
        assert main(["verify", str(path)]) == 0
        assert "dropped_writes" not in capsys.readouterr().out

    def test_sidecar_drops_are_reported_on_verify(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        path = tmp_path / "trail.jsonl"
        log = AuditLog.open(path, record_drops=True)
        log.append(payload={"i": 0}, payload_type=PT)
        log.try_append(payload=object(), payload_type=PT)  # type: ignore[arg-type]
        log.try_append(payload=object(), payload_type=PT)  # type: ignore[arg-type]

        assert main(["verify", str(path)]) == 0  # chain is still intact...
        out = capsys.readouterr().out
        assert "dropped_writes >= 2" in out  # ...but two writes never landed
        assert "measured minimum" in out
        assert f"{path}.drops" in out

    def test_sidecar_drops_are_reported_on_inspect(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        path = tmp_path / "trail.jsonl"
        log = AuditLog.open(path, record_drops=True)
        log.append(payload={"i": 0}, payload_type=PT)
        log.try_append(payload=object(), payload_type=PT)  # type: ignore[arg-type]

        assert main(["inspect", str(path)]) == 0
        assert "dropped_writes >= 1" in capsys.readouterr().out

    def test_drop_count_does_not_change_a_broken_chains_exit_code(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        path = tmp_path / "trail.jsonl"
        log = AuditLog.open(path, record_drops=True)
        for i in range(3):
            log.append(payload={"i": i}, payload_type=PT)
        log.try_append(payload=object(), payload_type=PT)  # type: ignore[arg-type]

        lines = path.read_text().splitlines()
        obj = json.loads(lines[1])
        obj["header"]["ts"] = "2027-01-01T00:00:00+00:00"
        lines[1] = json.dumps(obj)
        path.write_text("\n".join(lines) + "\n")

        assert main(["verify", str(path)]) == 1  # integrity break still wins
        out = capsys.readouterr().out
        assert "entry_hash_mismatch" in out
        assert "dropped_writes >= 1" in out  # completeness is reported alongside it


class TestHead:
    def test_head_prints_seq_and_entry_hash_for_anchoring(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        # `waxseal head` exists so operators can anchor the chain head
        # externally (OpenTimestamps / RFC 3161 / a git commit): an attacker
        # who rewrites the suffix cannot also rewrite the anchored head.
        path = tmp_path / "trail.jsonl"
        make_trail(path, 3)
        assert main(["head", str(path)]) == 0
        out = capsys.readouterr().out.strip()
        import json as _json

        from waxseal import AuditLog as _AuditLog

        entries = list(_AuditLog.open(path)._backend.entries())
        obj = _json.loads(out)
        assert obj == {"seq": 2, "entry_hash": entries[-1].entry_hash}

    def test_head_on_empty_trail_exits_1(self, tmp_path: Path) -> None:
        path = tmp_path / "trail.jsonl"
        path.touch()
        assert main(["head", str(path)]) == 1


class TestCheckpoint:
    def test_checkpoint_prints_seq_entry_hash_and_root(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        path = tmp_path / "trail.jsonl"
        make_trail(path, 3)
        assert main(["checkpoint", str(path)]) == 0
        out = capsys.readouterr().out.strip()

        from waxseal import AuditLog as _AuditLog
        from waxseal.domain.anchoring import batch_root

        entries = list(_AuditLog.open(path)._backend.entries())
        hashes = [e.entry_hash for e in entries]
        obj = json.loads(out)
        assert obj == {
            "seq": 2,
            "entry_hash": entries[-1].entry_hash,
            "root": batch_root(hashes),
        }

    def test_checkpoint_on_empty_trail_exits_1(self, tmp_path: Path) -> None:
        path = tmp_path / "trail.jsonl"
        path.touch()
        assert main(["checkpoint", str(path)]) == 1

    def test_checkpoint_on_missing_path_exits_3(self, tmp_path: Path) -> None:
        assert main(["checkpoint", str(tmp_path / "nope.jsonl")]) == 3

    def test_checkpoint_does_not_modify_the_file(self, tmp_path: Path) -> None:
        path = tmp_path / "trail.jsonl"
        make_trail(path, 3)
        before = path.read_bytes()
        main(["checkpoint", str(path)])
        assert path.read_bytes() == before


class TestAnchorCommand:
    def test_anchor_appends_checkpoint_to_sidecar_and_prints_it(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        path = tmp_path / "trail.jsonl"
        make_trail(path, 3)
        assert main(["anchor", str(path)]) == 0
        lines = (tmp_path / "trail.jsonl.anchors").read_text().splitlines()
        assert len(lines) == 1
        assert json.loads(lines[0])["seq"] == 2
        out = json.loads(capsys.readouterr().out.strip())
        assert out["seq"] == 2

    def test_anchor_on_empty_trail_exits_1(self, tmp_path: Path) -> None:
        path = tmp_path / "trail.jsonl"
        path.touch()
        assert main(["anchor", str(path)]) == 1

    def test_a_refused_anchor_says_why(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # A bare non-zero exit with no message is the one outcome an operator
        # cannot act on, and the reason here is nameable.
        path = tmp_path / "trail.jsonl"
        path.touch()
        main(["anchor", str(path)])
        assert "empty trail" in capsys.readouterr().err

    def test_anchor_does_not_modify_the_trail_itself(self, tmp_path: Path) -> None:
        path = tmp_path / "trail.jsonl"
        make_trail(path, 3)
        before = path.read_bytes()
        main(["anchor", str(path)])
        assert path.read_bytes() == before


def _consistent_forge_at(path: Path, position: int) -> None:
    """Rewrite the header at `position`, then recompute entry_hash and every
    downstream prev_hash/entry_hash so verify_chain() still reports ok — the
    "whole trail rewrite" a plain hash chain cannot resist by itself, which
    external anchoring exists to catch (DESIGN.md).

    Dispatches on each row's own hash_version via VersionRegistry.encoder_for
    (rather than assuming header_frame/v1) — make_trail() writes lp64v2 rows
    since lp64v2 became the wired default (waxseal-7tk.7.4), and a real
    attacker forging a trail recomputes it under whatever encoding that
    trail was actually signed with, same as verify_chain does."""
    from waxseal.domain.hashing import compute_entry_hash
    from waxseal.domain.header import EntryHeader
    from waxseal.domain.registry import VersionRegistry

    registry = VersionRegistry()
    lines = path.read_text().splitlines()
    objs = [json.loads(line) for line in lines]
    objs[position]["header"]["ts"] = "2099-01-01T00:00:00+00:00"
    prev = objs[position]["header"]["prev_hash"]
    for i in range(position, len(objs)):
        objs[i]["header"]["prev_hash"] = prev
        header = EntryHeader(**objs[i]["header"])
        encoder = registry.encoder_for(header.hash_version)
        objs[i]["entry_hash"] = compute_entry_hash(header, frame=encoder)
        prev = objs[i]["entry_hash"]
    path.write_text("\n".join(json.dumps(o) for o in objs) + "\n")


class TestVerifyAnchors:
    def test_ok_with_intact_anchors(self, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        path = tmp_path / "trail.jsonl"
        make_trail(path, 3)
        main(["anchor", str(path)])
        assert main(["verify", str(path), "--anchors"]) == 0
        assert "anchors ok" in capsys.readouterr().out

    def test_no_sidecar_keeps_the_chain_exit_code_absence_is_not_failure(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        path = tmp_path / "trail.jsonl"
        make_trail(path, 3)
        assert main(["verify", str(path), "--anchors"]) == 0
        assert "no anchors found" in capsys.readouterr().out

    def test_consistent_suffix_rewrite_after_anchor_is_caught(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        # A consistent hash-chain forgery that reaches the anchored seq
        # always changes THAT entry's own hash too (that is the point of
        # chaining), so this is caught as anchor_entry_hash_mismatch —
        # anchor_root_mismatch is the distinct case where an earlier entry
        # changes while the anchored tip's hash stays byte-identical, which
        # is unreachable via a self-consistent rewrite; it is exercised
        # directly against a manipulated hash list in test_checkpoint.py.
        path = tmp_path / "trail.jsonl"
        make_trail(path, 4)
        main(["anchor", str(path)])  # anchors seq=3, the current tip
        _consistent_forge_at(path, 1)

        assert main(["verify", str(path), "--anchors"]) == 1
        out = capsys.readouterr().out
        assert "ANCHOR BROKEN at seq=3: anchor_entry_hash_mismatch" in out

    def test_truncation_past_the_anchored_seq_is_beyond_head(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        path = tmp_path / "trail.jsonl"
        make_trail(path, 4)
        main(["anchor", str(path)])  # anchors seq=3
        lines = path.read_text().splitlines()
        path.write_text("\n".join(lines[:2]) + "\n")  # only seq 0, 1 remain

        assert main(["verify", str(path), "--anchors"]) == 1
        out = capsys.readouterr().out
        assert "ANCHOR BROKEN at seq=3: anchor_beyond_head" in out

    def test_malformed_anchor_record_is_a_verdict_not_a_crash(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        path = tmp_path / "trail.jsonl"
        make_trail(path, 3)
        main(["anchor", str(path)])
        with open(tmp_path / "trail.jsonl.anchors", "a") as f:
            f.write("{this is not json\n")

        assert main(["verify", str(path), "--anchors"]) == 1
        assert "malformed_anchor" in capsys.readouterr().out

    def test_forging_both_trail_and_sidecar_consistently_is_undetected_locally(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        # Honest limit (documented in REMOTE.md/SPEC.md, not hidden): a local
        # sidecar is not an independent witness. An attacker who controls
        # BOTH the trail and its own anchor sidecar can forge both
        # consistently and re-anchor — this is exactly why anchoring is only
        # meaningful once its receipt (or the sidecar itself) is copied
        # somewhere that same attacker does not also control.
        path = tmp_path / "trail.jsonl"
        make_trail(path, 4)
        _consistent_forge_at(path, 1)
        main(["anchor", str(path)])  # re-anchor the forged trail from scratch

        assert main(["verify", str(path), "--anchors"]) == 0
        assert "anchors ok" in capsys.readouterr().out


class TestMissingTrail:
    def test_verify_on_missing_sqlite_path_does_not_create_a_database(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        # Read-only contract: opening a missing .db used to CREATE an empty
        # 8KB database (mkdir + DDL) and then report "ok, checked=0".
        path = tmp_path / "nope.db"
        assert main(["verify", str(path)]) == 3
        assert not path.exists()
        assert "no such trail" in capsys.readouterr().err

    def test_verify_on_missing_jsonl_path_is_an_error_not_ok(self, tmp_path: Path) -> None:
        # A typo'd path must not verify as an intact empty chain.
        assert main(["verify", str(tmp_path / "nope.jsonl")]) == 3

    def test_tail_and_inspect_and_head_error_on_missing_path(self, tmp_path: Path) -> None:
        for command in ("tail", "inspect", "head", "checkpoint", "anchor"):
            assert main([command, str(tmp_path / "nope.jsonl")]) == 3


class TestRemoteURLTarget:
    """M7 E2E: the CLI against an actual localhost chain server, not a fake
    transport — proves the URL-dispatch path (log.py + cli.py) works with a
    real socket, the same bar test_remote.py's own real-server test sets."""

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

            def do_GET(self) -> None:
                self._dispatch("GET")

            def do_POST(self) -> None:
                self._dispatch("POST")

            def log_message(self, *args: object) -> None:
                pass

        httpd = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        return server, httpd, thread

    def test_verify_against_a_reachable_remote_chain_exits_0(
        self, capsys: pytest.CaptureFixture
    ) -> None:
        from waxseal import AuditLog

        server, httpd, thread = self._start_server()
        port = httpd.server_address[1]
        url = f"http://127.0.0.1:{port}"
        try:
            log = AuditLog.open(url)
            for i in range(3):
                log.append(payload={"i": i}, payload_type=PT)
            assert main(["verify", url]) == 0
            assert "ok (checked=3)" in capsys.readouterr().out
        finally:
            httpd.shutdown()
            thread.join(timeout=5)

    def test_unreachable_remote_chain_exits_3(self) -> None:
        # Start and immediately stop a server to get a real "nobody's
        # listening" port instead of guessing at an unused one.
        server, httpd, thread = self._start_server()
        port = httpd.server_address[1]
        httpd.shutdown()
        thread.join(timeout=5)
        httpd.server_close()

        url = f"http://127.0.0.1:{port}"
        assert main(["verify", url]) == 3

    def test_tamper_on_the_server_is_caught_with_the_right_broken_seq(
        self, capsys: pytest.CaptureFixture
    ) -> None:
        from waxseal import AuditLog

        server, httpd, thread = self._start_server()
        port = httpd.server_address[1]
        url = f"http://127.0.0.1:{port}"
        try:
            log = AuditLog.open(url)
            for i in range(4):
                log.append(payload={"i": i}, payload_type=PT)
            server.corrupt("default", 1, header={"ts": "2027-01-01T00:00:00+00:00"})

            assert main(["verify", url]) == 1
            out = capsys.readouterr().out
            assert "seq=1" in out
            assert "entry_hash_mismatch" in out
        finally:
            httpd.shutdown()
            thread.join(timeout=5)

    def test_zero_entries_on_a_url_target_gets_an_honest_caveat(
        self, capsys: pytest.CaptureFixture
    ) -> None:
        # The wire contract's GET /entries 404 means "empty" identically for
        # a genuinely fresh chain and for a mistyped chain_id/wrong path —
        # unlike a local path, there is no Path.exists() probe to tell them
        # apart. Reporting a bare "ok" here would let a typo silently verify
        # nothing while looking successful; CLAUDE.md rule 6 requires the
        # ambiguity be visible in the output instead.
        server, httpd, thread = self._start_server()
        port = httpd.server_address[1]
        url = f"http://127.0.0.1:{port}"
        try:
            assert main(["verify", url]) == 0
            out = capsys.readouterr().out
            assert "checked=0" in out
            assert "cannot" in out.lower() or "unreachable" in out.lower()
        finally:
            httpd.shutdown()
            thread.join(timeout=5)

    def test_verify_anchors_on_a_url_target_is_labelled_not_silent(
        self, capsys: pytest.CaptureFixture
    ) -> None:
        # main() already forces check_anchors False for a URL target (no
        # local .anchors sidecar to check) — CLAUDE.md rule 6 requires that
        # degradation be RECORDED in the output, not just silently dropped
        # the way an unlabelled `--anchors` no-op would read.
        from waxseal import AuditLog

        server, httpd, thread = self._start_server()
        port = httpd.server_address[1]
        url = f"http://127.0.0.1:{port}"
        try:
            log = AuditLog.open(url)
            log.append(payload={"i": 0}, payload_type=PT)
            assert main(["verify", url, "--anchors"]) == 0
            assert "anchors" in capsys.readouterr().err.lower()
        finally:
            httpd.shutdown()
            thread.join(timeout=5)

    def test_anchor_command_is_refused_for_a_url_target(
        self, capsys: pytest.CaptureFixture
    ) -> None:
        # No local sidecar location to write .anchors to — refuse instead of
        # guessing one (M7 CLI decision, documented in cli.py's main()).
        assert main(["anchor", "http://example.invalid/v1/chains/default"]) == 1
        assert "local sidecar location" in capsys.readouterr().err

    def test_a_local_path_oserror_still_propagates_unchanged(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        # The URL try/except added in M7 wraps the whole dispatch — it must
        # only swallow OSError/RemoteError for a URL target. A LOCAL path
        # hitting an OSError (e.g. a permissions error mid-read) is not
        # "unreachable", and must keep raising exactly as it did pre-M7.
        path = tmp_path / "trail.jsonl"
        make_trail(path)

        def raise_oserror(*_a: object, **_kw: object) -> AuditLog:
            raise OSError("simulated local I/O failure")

        monkeypatch.setattr(AuditLog, "open", staticmethod(raise_oserror))
        with pytest.raises(OSError, match="simulated local I/O failure"):
            main(["verify", str(path)])


class TestMixedVersionTrailThroughRealCli:
    """waxseal-7tk.7.5: prove the registry's per-row dispatch runs for real
    through the FULL CLI stack (main(argv) -> AuditLog.open -> log.verify()/
    log.entries()), not just the domain layer directly the way
    waxseal-7tk.7.4's own test (tests/test_auditlog.py) already did."""

    def _build_mixed_trail(self, path: Path) -> None:
        # seq 0: a hand-built v1 row, bypassing AuditLog.append() entirely --
        # the shape a pre-7tk.7.4 build would have written. seq 1..3: real
        # v2 rows via the public AuditLog.append() API. Same construction
        # pattern as test_auditlog.py's
        # test_hand_built_v1_row_mixed_with_real_v2_appends_verifies_both.
        from waxseal.domain.fingerprint import fingerprint
        from waxseal.domain.hashing import compute_entry_hash, compute_payload_hash, header_frame
        from waxseal.domain.header import Entry, EntryHeader

        log = AuditLog.open(path, now_fn=lambda: "2026-08-21T06:00:00+00:00")
        payload0 = b'{"i":0}'

        def build_v1(seq: int, prev_hash: str) -> Entry:
            header = EntryHeader(
                seq=seq,
                ts="2026-08-21T06:00:00+00:00",
                hash_version=fingerprint(),
                payload_type=PT,
                payload_hash=compute_payload_hash(payload0),
                prev_hash=prev_hash,
            )
            return Entry(
                header=header,
                entry_hash=compute_entry_hash(header, frame=header_frame),
                payload=payload0,
            )

        v1_entry = log._backend.append(build_v1)
        assert v1_entry.header.hash_version == fingerprint()
        for i in range(1, 4):
            log.append(payload={"i": i}, payload_type=PT)

    def test_verify_on_mixed_trail_exits_0(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        path = tmp_path / "trail.jsonl"
        self._build_mixed_trail(path)

        assert main(["verify", str(path)]) == 0
        assert "ok (checked=4)" in capsys.readouterr().out

    def test_report_json_on_mixed_trail_counts_both_the_v1_and_v2_rows(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        # `checked` counting all 4 rows (not just the 3 real v2 appends) is
        # the proof that the registry dispatch actually ran for the v1 row
        # through the whole CLI stack, rather than the row being silently
        # skipped or the command failing before it got there.
        path = tmp_path / "trail.jsonl"
        self._build_mixed_trail(path)

        assert main(["report", str(path), "--json"]) == 0
        report = json.loads(capsys.readouterr().out)
        assert report["chain"]["ok"] is True
        assert report["chain"]["checked"] == 4


class TestReportCommandThroughRealCli:
    def test_report_json_on_an_intact_v2_trail_exits_0(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        path = tmp_path / "trail.jsonl"
        make_trail(path, 3)  # real AuditLog.append() calls -- lp64v2 by default

        assert main(["report", str(path), "--json"]) == 0
        report = json.loads(capsys.readouterr().out)
        assert report["chain"]["ok"] is True
        assert report["chain"]["checked"] == 3


class TestExportProofAndVerifyProofThroughRealCli:
    def test_export_then_verify_proof_round_trips_a_v2_row(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        # This is the CLI-level proof that domain/export.py's
        # registry.encoder_for() dispatch fix (landed in waxseal-7tk.7.4,
        # which that bead tested only at the domain-function level) also
        # works when reached through `export-proof`/`verify-proof` as real
        # subcommands, on a row actually stamped lp64v2 by the wired default.
        path = tmp_path / "trail.jsonl"
        make_trail(path, 3)  # seq 0..2, real v2 appends

        assert main(["export-proof", str(path), "1"]) == 0
        bundle_json = capsys.readouterr().out
        bundle_path = tmp_path / "bundle.json"
        bundle_path.write_text(bundle_json)

        assert main(["verify-proof", str(bundle_path)]) == 0
        out = capsys.readouterr().out
        assert "verified against root" in out

    def test_export_proof_for_a_missing_seq_exits_1(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        path = tmp_path / "trail.jsonl"
        make_trail(path, 2)  # seq 0, 1 only

        assert main(["export-proof", str(path), "5"]) == 1
        assert capsys.readouterr().err


class TestConsistencyCommandThroughRealCli:
    def test_current_head_extends_an_earlier_checkpoint_on_a_v2_trail(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        path = tmp_path / "trail.jsonl"
        make_trail(path, 2)  # seq 0, 1 -- real v2 appends

        assert main(["checkpoint", str(path)]) == 0
        old = json.loads(capsys.readouterr().out.strip())

        AuditLog.open(path).append(payload={"i": 99}, payload_type=PT)  # extend to seq 2

        assert (
            main(
                [
                    "consistency",
                    str(path),
                    "--old-seq",
                    str(old["seq"]),
                    "--old-root",
                    old["root"],
                ]
            )
            == 0
        )
        assert "consistent" in capsys.readouterr().out
