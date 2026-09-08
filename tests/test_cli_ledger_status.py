"""`waxseal ledger-status` (F4): the liveness/registry/bond ternaries for a
trail's on-chain state, exit codes matching `reconcile-tickets`'s own
convention exactly (cli.py's `_reconcile_tickets`):

  0 = every configured dimension came back clean.
  1 = a POSITIVELY DETECTED finding (delinquent / slashed / unbonded) — the
      same "detected, not tampered" sense `reconcile-tickets` gives exit 1.
  2 = unreachable, endpoints disagree, or malformed input — never rendered
      as "0 findings" (CLAUDE.md rule 5).
  3 = no such trail — main()'s shared trail-opening plumbing, exercised here
      once for this command specifically.

Two REAL localhost JSON-RPC servers back every test (`_fake_evm_rpc.py`):
`EvmLedgerReader` refuses fewer than two endpoints (adapters/evm.py), so a
single-fake test would never exercise the actual code path an operator hits.
"""

from __future__ import annotations

import http.server
import json
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from tests._fake_evm_rpc import (
    CallHandler,
    bond_return,
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
BOND_ADDR = "0x" + "33" * 20
WRITER = "0x" + "44" * 20

PT = "application/vnd.test.event+json"

AGREEING_DESCRIPTOR = descriptor_frame(HEADER_FIELDS)
TRAIL_FINGERPRINT = fingerprint_for(HEADER_FIELDS)


def make_trail(path: Path, n: int = 1) -> None:
    log = AuditLog.open(path)
    for i in range(n):
        log.append(payload={"i": i}, payload_type=PT)


@pytest.fixture
def two_nodes() -> Iterator[Callable[[CallHandler], list[str]]]:
    def _start(
        handler: CallHandler,
    ) -> tuple[list[str], tuple[http.server.HTTPServer, http.server.HTTPServer]]:
        url_a, server_a = start_fake_node(handler)
        url_b, server_b = start_fake_node(handler)
        return [url_a, url_b], (server_a, server_b)

    started: list[tuple[http.server.HTTPServer, http.server.HTTPServer]] = []

    def factory(handler: CallHandler) -> list[str]:
        urls, servers = _start(handler)
        started.append(servers)
        return urls

    yield factory
    for server_a, server_b in started:
        server_a.shutdown()
        server_b.shutdown()


class TestMissingTrail:
    def test_nonexistent_trail_exits_3(self, tmp_path: Path) -> None:
        code = main(
            [
                "ledger-status",
                str(tmp_path / "nope.jsonl"),
                "--liveness",
                LIVENESS_ADDR,
                "--rpc",
                "http://a",
                "--rpc",
                "http://b",
            ]
        )
        assert code == 3


class TestUsageErrors:
    def test_bond_without_writer_is_a_usage_error(self, tmp_path: Path) -> None:
        path = tmp_path / "t.jsonl"
        make_trail(path)
        with pytest.raises(SystemExit) as exc:
            main(
                [
                    "ledger-status",
                    str(path),
                    "--liveness",
                    LIVENESS_ADDR,
                    "--bond",
                    BOND_ADDR,
                    "--rpc",
                    "http://a",
                    "--rpc",
                    "http://b",
                ]
            )
        assert exc.value.code == 2

    def test_missing_liveness_is_a_usage_error(self, tmp_path: Path) -> None:
        path = tmp_path / "t.jsonl"
        make_trail(path)
        with pytest.raises(SystemExit) as exc:
            main(["ledger-status", str(path), "--rpc", "http://a", "--rpc", "http://b"])
        assert exc.value.code == 2


class TestLivenessOnly:
    def test_live_exits_0(
        self,
        tmp_path: Path,
        two_nodes: Callable[[CallHandler], list[str]],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        import time

        path = tmp_path / "t.jsonl"
        make_trail(path)
        urls = two_nodes(
            liveness_node(
                head=head_return(
                    seq=1, entry_hash="ab" * 32, root="cd" * 32, block_time=int(time.time())
                ),
                deadline=3600,
            )
        )
        code = main(
            [
                "ledger-status",
                str(path),
                "--liveness",
                LIVENESS_ADDR,
                "--rpc",
                urls[0],
                "--rpc",
                urls[1],
            ]
        )
        out = capsys.readouterr().out
        assert code == 0
        assert "liveness: live" in out
        assert "ledger-status: ok" in out

    def test_delinquent_exits_1(
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
                "ledger-status",
                str(path),
                "--liveness",
                LIVENESS_ADDR,
                "--rpc",
                urls[0],
                "--rpc",
                urls[1],
            ]
        )
        out = capsys.readouterr().out
        assert code == 1
        assert "liveness: delinquent" in out
        assert "ledger-status: broken" in out

    def test_no_deadline_configured_is_unmeasured_exit_2(
        self,
        tmp_path: Path,
        two_nodes: Callable[[CallHandler], list[str]],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        path = tmp_path / "t.jsonl"
        make_trail(path)
        urls = two_nodes(liveness_node(deadline=0))  # deadlineOf returns 0 -> None
        code = main(
            [
                "ledger-status",
                str(path),
                "--liveness",
                LIVENESS_ADDR,
                "--rpc",
                urls[0],
                "--rpc",
                urls[1],
            ]
        )
        out = capsys.readouterr().out
        assert code == 2
        assert "liveness: unreachable" in out
        assert "deadline_unavailable" in out

    def test_too_few_rpc_endpoints_is_unverifiable_exit_2(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = tmp_path / "t.jsonl"
        make_trail(path)
        code = main(
            ["ledger-status", str(path), "--liveness", LIVENESS_ADDR, "--rpc", "http://only-one"]
        )
        out = capsys.readouterr().out
        assert code == 2
        assert "unverifiable" in out.lower()

    def test_no_rpc_at_all_is_unverifiable_exit_2(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = tmp_path / "t.jsonl"
        make_trail(path)
        code = main(["ledger-status", str(path), "--liveness", LIVENESS_ADDR])
        out = capsys.readouterr().out
        assert code == 2
        assert "unverifiable" in out.lower()

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
                    "ledger-status",
                    str(path),
                    "--liveness",
                    LIVENESS_ADDR,
                    "--rpc",
                    url_a,
                    "--rpc",
                    url_b,
                ]
            )
        finally:
            server_a.shutdown()
            server_b.shutdown()
        out = capsys.readouterr().out
        assert code == 2
        assert "DISAGREEMENT" in out
        assert url_a in out and url_b in out

    def test_json_mode_shape(
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
                "ledger-status",
                str(path),
                "--liveness",
                LIVENESS_ADDR,
                "--rpc",
                urls[0],
                "--rpc",
                urls[1],
                "--json",
            ]
        )
        payload = json.loads(capsys.readouterr().out)
        assert code == 0
        assert payload["verdict"] == "ok"
        assert payload["trail_id"]
        [finding] = payload["findings"]
        assert finding["dimension"] == "liveness"
        assert finding["verdict"] == "ok"

    def test_trail_id_override(
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
                "ledger-status",
                str(path),
                "--liveness",
                LIVENESS_ADDR,
                "--rpc",
                urls[0],
                "--rpc",
                urls[1],
                "--trail-id",
                "custom-trail",
                "--json",
            ]
        )
        payload = json.loads(capsys.readouterr().out)
        assert code == 0
        assert payload["trail_id"] == "custom-trail"


class TestRegistry:
    def test_agrees_exits_0(
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
                "ledger-status",
                str(path),
                "--liveness",
                LIVENESS_ADDR,
                "--registry",
                REGISTRY_ADDR,
                "--rpc",
                urls[0],
                "--rpc",
                urls[1],
            ]
        )
        out = capsys.readouterr().out
        assert code == 0
        assert f"registry {TRAIL_FINGERPRINT}: agrees" in out

    def test_disagrees_exits_2_never_1(
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
                "ledger-status",
                str(path),
                "--liveness",
                LIVENESS_ADDR,
                "--registry",
                REGISTRY_ADDR,
                "--rpc",
                urls[0],
                "--rpc",
                urls[1],
            ]
        )
        out = capsys.readouterr().out
        assert code == 2  # never 1: a disagreement is not a broken verdict
        assert "disagrees" in out
        assert "registry_disagreement" in out

    def test_registry_disagreement_between_endpoints_is_exit_2(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # A real eclipse-shaped LedgerDisagreement — two endpoints answering
        # DIFFERENT raw bytes — distinct from the DISAGREES finding above
        # (one node, wrong descriptor).
        path = tmp_path / "t.jsonl"
        make_trail(path)
        lookup_a = rpc_ok(dynamic_bytes(AGREEING_DESCRIPTOR))
        lookup_b = rpc_ok(dynamic_bytes(b"a-different-descriptor-entirely"))
        url_a, server_a = start_fake_node(full_node(deadline=3600, lookup=lookup_a))
        url_b, server_b = start_fake_node(full_node(deadline=3600, lookup=lookup_b))
        try:
            code = main(
                [
                    "ledger-status",
                    str(path),
                    "--liveness",
                    LIVENESS_ADDR,
                    "--registry",
                    REGISTRY_ADDR,
                    "--rpc",
                    url_a,
                    "--rpc",
                    url_b,
                ]
            )
        finally:
            server_a.shutdown()
            server_b.shutdown()
        out = capsys.readouterr().out
        assert code == 2
        assert "registry" in out and "DISAGREEMENT" in out

    def test_no_entries_on_trail_is_nothing_to_check(
        self,
        tmp_path: Path,
        two_nodes: Callable[[CallHandler], list[str]],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        path = tmp_path / "empty.jsonl"
        path.touch()  # exists, 0 entries — AuditLog.open() alone would not create it
        urls = two_nodes(full_node(deadline=3600))
        code = main(
            [
                "ledger-status",
                str(path),
                "--liveness",
                LIVENESS_ADDR,
                "--registry",
                REGISTRY_ADDR,
                "--rpc",
                urls[0],
                "--rpc",
                urls[1],
            ]
        )
        out = capsys.readouterr().out
        assert code == 0
        assert "no entries on this trail" in out


class TestBond:
    def test_malformed_bond_answer_is_unreachable_exit_2(
        self,
        tmp_path: Path,
        two_nodes: Callable[[CallHandler], list[str]],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        from tests._fake_evm_rpc import hexdata, word

        path = tmp_path / "t.jsonl"
        make_trail(path)
        # bondOf returns 4 words on the real contract; one word back is a
        # shape this build cannot read, which degrades to `unreachable`
        # (not a crash) with amount_wei left None (never a bare 0 — rule 5).
        urls = two_nodes(full_node(deadline=3600, bond=rpc_ok(hexdata(word(1)))))
        code = main(
            [
                "ledger-status",
                str(path),
                "--liveness",
                LIVENESS_ADDR,
                "--bond",
                BOND_ADDR,
                "--writer",
                WRITER,
                "--rpc",
                urls[0],
                "--rpc",
                urls[1],
            ]
        )
        out = capsys.readouterr().out
        assert code == 2
        assert "bond: unreachable" in out
        assert "amount_wei=" not in out

    def test_bonded_exits_0(
        self,
        tmp_path: Path,
        two_nodes: Callable[[CallHandler], list[str]],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        path = tmp_path / "t.jsonl"
        make_trail(path)
        urls = two_nodes(full_node(deadline=3600, bond=bond_return(amount_wei=10**18)))
        code = main(
            [
                "ledger-status",
                str(path),
                "--liveness",
                LIVENESS_ADDR,
                "--bond",
                BOND_ADDR,
                "--writer",
                WRITER,
                "--rpc",
                urls[0],
                "--rpc",
                urls[1],
            ]
        )
        out = capsys.readouterr().out
        assert code == 0
        assert "bond: bonded" in out
        assert "amount_wei=" in out

    def test_slashed_exits_1(
        self,
        tmp_path: Path,
        two_nodes: Callable[[CallHandler], list[str]],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        path = tmp_path / "t.jsonl"
        make_trail(path)
        urls = two_nodes(full_node(deadline=3600, bond=bond_return(amount_wei=5, slashed=True)))
        code = main(
            [
                "ledger-status",
                str(path),
                "--liveness",
                LIVENESS_ADDR,
                "--bond",
                BOND_ADDR,
                "--writer",
                WRITER,
                "--rpc",
                urls[0],
                "--rpc",
                urls[1],
            ]
        )
        out = capsys.readouterr().out
        assert code == 1
        assert "bond: slashed" in out

    def test_unbonded_exits_1(
        self,
        tmp_path: Path,
        two_nodes: Callable[[CallHandler], list[str]],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        path = tmp_path / "t.jsonl"
        make_trail(path)
        urls = two_nodes(full_node(deadline=3600, bond=bond_return(amount_wei=0)))
        code = main(
            [
                "ledger-status",
                str(path),
                "--liveness",
                LIVENESS_ADDR,
                "--bond",
                BOND_ADDR,
                "--writer",
                WRITER,
                "--rpc",
                urls[0],
                "--rpc",
                urls[1],
            ]
        )
        out = capsys.readouterr().out
        assert code == 1
        assert "bond: unbonded" in out

    def test_bond_disagreement_exits_2(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = tmp_path / "t.jsonl"
        make_trail(path)
        url_a, server_a = start_fake_node(full_node(deadline=3600, bond=bond_return(amount_wei=1)))
        url_b, server_b = start_fake_node(full_node(deadline=3600, bond=bond_return(amount_wei=2)))
        try:
            code = main(
                [
                    "ledger-status",
                    str(path),
                    "--liveness",
                    LIVENESS_ADDR,
                    "--bond",
                    BOND_ADDR,
                    "--writer",
                    WRITER,
                    "--rpc",
                    url_a,
                    "--rpc",
                    url_b,
                ]
            )
        finally:
            server_a.shutdown()
            server_b.shutdown()
        out = capsys.readouterr().out
        assert code == 2
        assert "bond: DISAGREEMENT" in out


class TestCombinedFindingsUseWorstVerdict:
    def test_delinquent_liveness_beats_registry_disagreement(
        self,
        tmp_path: Path,
        two_nodes: Callable[[CallHandler], list[str]],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        # BROKEN (delinquent) must win over UNVERIFIABLE (registry disagree)
        # under Verdict.join's severity order, exactly as reconcile-tickets's
        # own join(UNVERIFIABLE) can only ever weaken an OK, never a BROKEN.
        path = tmp_path / "t.jsonl"
        make_trail(path)
        wrong = rpc_ok(dynamic_bytes(b"not-the-real-descriptor"))
        urls = two_nodes(
            full_node(
                head=head_return(
                    seq=1, entry_hash="ab" * 32, root="cd" * 32, block_time=1_000_000_000
                ),
                deadline=1,
                lookup=wrong,
            )
        )
        code = main(
            [
                "ledger-status",
                str(path),
                "--liveness",
                LIVENESS_ADDR,
                "--registry",
                REGISTRY_ADDR,
                "--rpc",
                urls[0],
                "--rpc",
                urls[1],
            ]
        )
        out = capsys.readouterr().out
        assert code == 1
        assert "ledger-status: broken" in out
