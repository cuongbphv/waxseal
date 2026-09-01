"""`waxseal verify`/`report --rpc/--liveness/--registry` (F4, Phase 4).

The one property every test here defends: a chain disagreement or an
unreachable ledger is NEVER a `broken` (exit 1) verdict, only `unverifiable`
(exit 2) — `LivenessVerdict.to_verify_verdict()` and
`RegistryFinding.to_verdict()` both exclude BROKEN from their range by
construction (domain/liveness.py, domain/registry.py), so this file asserts
the CLI wiring never manages to reach exit 1 through this dimension even
when the underlying chain reading is as bad as it can be (delinquent,
disagreeing, unreachable).
"""

from __future__ import annotations

import base64
import http.server
import json
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from tests._fake_evm_rpc import (
    CallHandler,
    dynamic_bytes,
    full_node,
    head_return,
    liveness_node,
    rpc_ok,
    start_fake_node,
)
from waxseal import AuditLog
from waxseal.cli import main
from waxseal.domain.fingerprint import HEADER_FIELDS, fingerprint_for
from waxseal.domain.registry import descriptor_frame

LIVENESS_ADDR = "0x" + "11" * 20
REGISTRY_ADDR = "0x" + "22" * 20

PT = "application/vnd.test.event+json"

AGREEING_DESCRIPTOR = descriptor_frame(HEADER_FIELDS)
TRAIL_FINGERPRINT = fingerprint_for(HEADER_FIELDS)


def make_trail(path: Path, n: int = 1) -> None:
    log = AuditLog.open(path)
    for i in range(n):
        log.append(payload={"i": i}, payload_type=PT)


@pytest.fixture
def two_nodes() -> Iterator[Callable[[CallHandler], list[str]]]:
    started: list[tuple[http.server.HTTPServer, http.server.HTTPServer]] = []

    def factory(handler: CallHandler) -> list[str]:
        url_a, server_a = start_fake_node(handler)
        url_b, server_b = start_fake_node(handler)
        started.append((server_a, server_b))
        return [url_a, url_b]

    yield factory
    for server_a, server_b in started:
        server_a.shutdown()
        server_b.shutdown()


class TestVerifyLiveness:
    def test_live_is_exit_0(
        self,
        tmp_path: Path,
        two_nodes: Callable[[CallHandler], list[str]],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        path = tmp_path / "t.jsonl"
        make_trail(path)
        urls = two_nodes(liveness_node(deadline=3600))
        code = main(
            [
                "verify", str(path), "--liveness", LIVENESS_ADDR,
                "--rpc", urls[0], "--rpc", urls[1],
            ]
        )
        out = capsys.readouterr().out
        assert code == 0
        assert "ledger liveness: live" in out

    def test_delinquent_is_exit_2_never_1(
        self,
        tmp_path: Path,
        two_nodes: Callable[[CallHandler], list[str]],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        path = tmp_path / "t.jsonl"
        make_trail(path)
        urls = two_nodes(
            liveness_node(
                head=head_return(
                    seq=1, entry_hash="ab" * 32, root="cd" * 32, block_time=1_000_000_000
                ),
                deadline=1,
            )
        )
        code = main(
            [
                "verify", str(path), "--liveness", LIVENESS_ADDR,
                "--rpc", urls[0], "--rpc", urls[1],
            ]
        )
        out = capsys.readouterr().out
        assert code == 2
        assert "ledger liveness: delinquent" in out
        assert "ledger_delinquent" not in out or "delinquent" in out

    def test_disagreement_is_exit_2_and_names_both_endpoints(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = tmp_path / "t.jsonl"
        make_trail(path)
        url_a, server_a = start_fake_node(liveness_node(deadline=3600))
        url_b, server_b = start_fake_node(liveness_node(deadline=7200))
        try:
            code = main(
                [
                    "verify", str(path), "--liveness", LIVENESS_ADDR,
                    "--rpc", url_a, "--rpc", url_b,
                ]
            )
        finally:
            server_a.shutdown()
            server_b.shutdown()
        out = capsys.readouterr().out
        assert code == 2
        assert "DISAGREEMENT" in out
        assert url_a in out and url_b in out

    def test_bad_rpc_count_is_exit_2_unverifiable(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = tmp_path / "t.jsonl"
        make_trail(path)
        code = main(
            ["verify", str(path), "--liveness", LIVENESS_ADDR, "--rpc", "http://only-one"]
        )
        out = capsys.readouterr().out
        assert code == 2
        assert "ledger:" in out
        assert "unverifiable" in out.lower()

    def test_trail_id_without_liveness_or_registry_is_a_usage_error(
        self, tmp_path: Path
    ) -> None:
        path = tmp_path / "t.jsonl"
        make_trail(path)
        with pytest.raises(SystemExit) as exc:
            main(["verify", str(path), "--trail-id", "custom"])
        assert exc.value.code == 2

    def test_a_genuine_break_still_wins_over_ledger_unverifiable(
        self,
        tmp_path: Path,
        two_nodes: Callable[[CallHandler], list[str]],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        # BROKEN (a real tamper) must survive combination with an
        # UNVERIFIABLE ledger dimension: Verdict.join keeps the worse
        # finding by severity order, never by raw exit-code magnitude.
        path = tmp_path / "t.jsonl"
        make_trail(path, n=2)
        lines = path.read_text(encoding="utf-8").splitlines()
        obj = json.loads(lines[0])
        # payload_b64 changes without payload_hash following it: a mismatch
        # the chain check catches regardless of what the ledger side says.
        obj["payload_b64"] = base64.b64encode(b'{"tampered":true}').decode("ascii")
        lines[0] = json.dumps(obj)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        urls = two_nodes(liveness_node(deadline=3600))
        code = main(
            [
                "verify", str(path), "--liveness", LIVENESS_ADDR,
                "--rpc", urls[0], "--rpc", urls[1],
            ]
        )
        out = capsys.readouterr().out
        assert code == 1
        assert "BROKEN" in out


class TestVerifyRegistry:
    def test_agrees_is_exit_0(
        self,
        tmp_path: Path,
        two_nodes: Callable[[CallHandler], list[str]],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        path = tmp_path / "t.jsonl"
        make_trail(path)
        lookup = rpc_ok(dynamic_bytes(AGREEING_DESCRIPTOR))
        urls = two_nodes(full_node(deadline=3600, lookup=lookup))
        code = main(
            [
                "verify", str(path), "--liveness", LIVENESS_ADDR,
                "--registry", REGISTRY_ADDR, "--rpc", urls[0], "--rpc", urls[1],
            ]
        )
        out = capsys.readouterr().out
        assert code == 0
        assert f"ledger registry {TRAIL_FINGERPRINT}: agrees" in out

    def test_disagrees_is_exit_2_never_1(
        self,
        tmp_path: Path,
        two_nodes: Callable[[CallHandler], list[str]],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        path = tmp_path / "t.jsonl"
        make_trail(path)
        wrong = rpc_ok(dynamic_bytes(b"not-the-real-descriptor"))
        urls = two_nodes(full_node(deadline=3600, lookup=wrong))
        code = main(
            [
                "verify", str(path), "--liveness", LIVENESS_ADDR,
                "--registry", REGISTRY_ADDR, "--rpc", urls[0], "--rpc", urls[1],
            ]
        )
        out = capsys.readouterr().out
        assert code == 2
        assert "registry_disagreement" in out

    def test_registry_only_without_liveness_is_supported(
        self,
        tmp_path: Path,
        two_nodes: Callable[[CallHandler], list[str]],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        # --registry does not require --liveness: the ledger dimension only
        # asks the chain about whichever flags were actually given.
        path = tmp_path / "t.jsonl"
        make_trail(path)
        lookup = rpc_ok(dynamic_bytes(AGREEING_DESCRIPTOR))
        urls = two_nodes(full_node(deadline=3600, lookup=lookup))
        code = main(
            ["verify", str(path), "--registry", REGISTRY_ADDR, "--rpc", urls[0], "--rpc", urls[1]]
        )
        out = capsys.readouterr().out
        assert code == 0
        assert "ledger liveness" not in out
        assert f"ledger registry {TRAIL_FINGERPRINT}: agrees" in out

    def test_registry_no_entries_without_liveness(
        self,
        tmp_path: Path,
        two_nodes: Callable[[CallHandler], list[str]],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        path = tmp_path / "empty.jsonl"
        path.touch()
        urls = two_nodes(full_node(deadline=3600))
        code = main(
            ["verify", str(path), "--registry", REGISTRY_ADDR, "--rpc", urls[0], "--rpc", urls[1]]
        )
        out = capsys.readouterr().out
        assert code == 0
        assert "no entries on this trail to cross-check" in out

    def test_registry_disagreement_between_endpoints_is_exit_2(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # Two endpoints answering DIFFERENT raw bytes for the same lookup —
        # a real eclipse-shaped LedgerDisagreement, distinct from the
        # DISAGREES finding above (same node, wrong descriptor).
        path = tmp_path / "t.jsonl"
        make_trail(path)
        lookup_a = rpc_ok(dynamic_bytes(AGREEING_DESCRIPTOR))
        lookup_b = rpc_ok(dynamic_bytes(b"a-different-descriptor-entirely"))
        url_a, server_a = start_fake_node(full_node(deadline=3600, lookup=lookup_a))
        url_b, server_b = start_fake_node(full_node(deadline=3600, lookup=lookup_b))
        try:
            code = main(
                [
                    "verify", str(path), "--registry", REGISTRY_ADDR,
                    "--rpc", url_a, "--rpc", url_b,
                ]
            )
        finally:
            server_a.shutdown()
            server_b.shutdown()
        out = capsys.readouterr().out
        assert code == 2
        assert "ledger registry" in out and "DISAGREEMENT" in out


class TestReport:
    def test_json_mode_carries_a_ledger_key(
        self,
        tmp_path: Path,
        two_nodes: Callable[[CallHandler], list[str]],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        path = tmp_path / "t.jsonl"
        make_trail(path)
        urls = two_nodes(liveness_node(deadline=3600))
        code = main(
            [
                "report", str(path), "--json", "--liveness", LIVENESS_ADDR,
                "--rpc", urls[0], "--rpc", urls[1],
            ]
        )
        payload = json.loads(capsys.readouterr().out)
        assert code == 0
        assert payload["ledger"]["ok"] is True
        assert payload["ledger"]["unverifiable"] is False
        assert "live" in payload["ledger"]["detail"]

    def test_markdown_mode_carries_a_ledger_section(
        self,
        tmp_path: Path,
        two_nodes: Callable[[CallHandler], list[str]],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        path = tmp_path / "t.jsonl"
        make_trail(path)
        urls = two_nodes(liveness_node(deadline=3600))
        code = main(
            ["report", str(path), "--liveness", LIVENESS_ADDR, "--rpc", urls[0], "--rpc", urls[1]]
        )
        out = capsys.readouterr().out
        assert code == 0
        assert "## Ledger" in out
        assert "ledger liveness: live" in out

    def test_delinquent_is_exit_2_never_1_in_report_too(
        self,
        tmp_path: Path,
        two_nodes: Callable[[CallHandler], list[str]],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        path = tmp_path / "t.jsonl"
        make_trail(path)
        urls = two_nodes(
            liveness_node(
                head=head_return(
                    seq=1, entry_hash="ab" * 32, root="cd" * 32, block_time=1_000_000_000
                ),
                deadline=1,
            )
        )
        code = main(
            [
                "report", str(path), "--json", "--liveness", LIVENESS_ADDR,
                "--rpc", urls[0], "--rpc", urls[1],
            ]
        )
        payload = json.loads(capsys.readouterr().out)
        assert code == 2
        assert payload["ledger"]["unverifiable"] is True
