"""The 0.1.5 reads that take an argument, and the validation that guards them.

Every read here reaches the CLI with a flag built from a query parameter, which
is the one place this server turns caller input into argv. So each route is
tested twice: once that it carries the command's real answer through, and once
that a value which is not what it claims to be never reaches `argv` at all.

The check that a rejected value is absent from `argv` is the point. A validator
that rejects after the subprocess ran has already run it.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from waxseal_server.app import create_app
from waxseal_server.config import Settings

HEX64 = "a" * 64


@pytest.fixture
def client(tmp_path: Path) -> TestClient:
    return TestClient(create_app(Settings(data_dir=tmp_path / "data")))


@pytest.fixture
def stocked(client: TestClient, envelopes: list[dict[str, Any]]) -> TestClient:
    for env in envelopes:
        client.post("/v1/chains/default/entries", json=env)
    return client


class TestTail:
    def test_it_returns_the_last_entries(self, stocked: TestClient) -> None:
        body = stocked.get("/v1/chains/default/tail?n=2").json()
        assert body["status"] == "ok"
        assert body["stdout"].count("seq=") == 2

    def test_it_defaults_to_the_commands_own_default(self, stocked: TestClient) -> None:
        # No `-n` in argv when the caller did not ask for one: the CLI's default
        # is the CLI's to choose, and restating it here would be a second
        # default to keep in step.
        body = stocked.get("/v1/chains/default/tail").json()
        assert "-n" not in body["argv"]
        assert body["status"] == "ok"

    @pytest.mark.parametrize("bad", ["0", "-1", "abc", "1e3", "--help", ""])
    def test_a_count_that_is_not_a_positive_integer_never_reaches_argv(
        self, stocked: TestClient, bad: str
    ) -> None:
        response = stocked.get(f"/v1/chains/default/tail?n={bad}")
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_count"

    def test_an_absent_chain_is_absent_not_broken(self, client: TestClient) -> None:
        body = client.get("/v1/chains/nope/tail").json()
        assert body["status"] == "absent"
        assert body["verdict"] is None


class TestCheckpoint:
    def test_it_returns_the_seq_hash_and_root(self, stocked: TestClient) -> None:
        body = stocked.get("/v1/chains/default/checkpoint").json()
        assert body["status"] == "ok"
        printed = json.loads(body["stdout"])
        assert printed["seq"] == 4
        assert len(printed["root"]) == 64


class TestConsistency:
    def test_a_prefix_of_the_same_chain_is_consistent(self, stocked: TestClient) -> None:
        checkpoint = json.loads(stocked.get("/v1/chains/default/checkpoint").json()["stdout"])
        body = stocked.get(
            "/v1/chains/default/consistency"
            f"?old_seq={checkpoint['seq']}&old_root={checkpoint['root']}"
        ).json()
        assert body["verdict"] == "ok"

    def test_a_root_from_another_history_is_broken_not_unverifiable(
        self, stocked: TestClient
    ) -> None:
        # A root this chain never had is a positively detected disagreement, and
        # the comparison is deterministic — so it is a break, never an unknown.
        body = stocked.get(f"/v1/chains/default/consistency?old_seq=1&old_root={HEX64}").json()
        assert body["verdict"] == "broken"

    @pytest.mark.parametrize("seq", ["-1", "x", "1.5", ""])
    def test_a_seq_that_is_not_a_whole_number_never_reaches_argv(
        self, stocked: TestClient, seq: str
    ) -> None:
        response = stocked.get(f"/v1/chains/default/consistency?old_seq={seq}&old_root={HEX64}")
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_seq"

    @pytest.mark.parametrize("root", ["deadbeef", "A" * 64, "z" * 64, "", "-" * 64])
    def test_a_root_that_is_not_64_lowercase_hex_never_reaches_argv(
        self, stocked: TestClient, root: str
    ) -> None:
        response = stocked.get(f"/v1/chains/default/consistency?old_seq=1&old_root={root}")
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_root"


class TestVerifyHandoff:
    def test_a_trail_with_no_binding_has_nothing_to_check(self, stocked: TestClient) -> None:
        # "Nothing to check" is exit 0 by the CLI contract, and it is not the
        # same statement as "every binding holds".
        body = stocked.get("/v1/chains/default/verify-handoff?origin=default").json()
        assert body["verdict"] == "ok"
        assert "nothing to check" in body["stdout"]

    def test_the_origin_trail_is_named_in_argv(self, stocked: TestClient) -> None:
        argv = stocked.get("/v1/chains/default/verify-handoff?origin=default").json()["argv"]
        assert "--origin" in argv

    def test_an_origin_that_is_not_a_safe_chain_id_never_reaches_argv(
        self, stocked: TestClient
    ) -> None:
        response = stocked.get("/v1/chains/default/verify-handoff?origin=../etc/passwd")
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_origin_id"

    def test_a_missing_origin_parameter_is_a_400_not_a_verdict(self, stocked: TestClient) -> None:
        assert stocked.get("/v1/chains/default/verify-handoff").status_code == 422


class TestReconcileTickets:
    def test_no_issuer_data_is_unmeasured_never_zero_drops(self, stocked: TestClient) -> None:
        # Rule 5, and the reason this route exists at all: with no `--issued`
        # range the answer is "unmeasured", which must never render as "0 drops
        # detected".
        body = stocked.get("/v1/chains/default/reconcile-tickets?issuer=acme&lease_size=10").json()
        assert body["verdict"] == "unverifiable"
        assert body["reconciliation"]["measured"] is False
        assert body["reconciliation"]["missing"] is None

    def test_the_parsed_reconciliation_is_returned_beside_the_stdout(
        self, stocked: TestClient
    ) -> None:
        body = stocked.get("/v1/chains/default/reconcile-tickets?issuer=acme&lease_size=10").json()
        assert body["reconciliation"]["issuer"] == "acme"

    @pytest.mark.parametrize("size", ["0", "-4", "x", ""])
    def test_a_lease_size_that_is_not_a_positive_integer_is_refused(
        self, stocked: TestClient, size: str
    ) -> None:
        response = stocked.get(
            f"/v1/chains/default/reconcile-tickets?issuer=acme&lease_size={size}"
        )
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_lease_size"

    @pytest.mark.parametrize("issuer", ["../x", "with space", "", "-flag"])
    def test_an_issuer_that_is_not_a_safe_name_is_refused(
        self, stocked: TestClient, issuer: str
    ) -> None:
        response = stocked.get(
            f"/v1/chains/default/reconcile-tickets?issuer={issuer}&lease_size=10"
        )
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_issuer"

    def test_an_issued_spec_is_passed_through_when_given(self, stocked: TestClient) -> None:
        argv = stocked.get(
            "/v1/chains/default/reconcile-tickets?issuer=acme&lease_size=10&issued=1-10"
        ).json()["argv"]
        assert "--issued" in argv

    @pytest.mark.parametrize("spec", ["; rm -rf /", "--json", "1..10"])
    def test_an_issued_spec_that_is_not_a_range_is_refused(
        self, stocked: TestClient, spec: str
    ) -> None:
        response = stocked.get(
            f"/v1/chains/default/reconcile-tickets?issuer=acme&lease_size=10&issued={spec}"
        )
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_issued"

    def test_an_unreadable_report_leaves_the_parsed_field_null(self, client: TestClient) -> None:
        # An absent chain prints nothing. None is "no reconciliation", never an
        # empty one that could read as "nothing missing".
        body = client.get("/v1/chains/nope/reconcile-tickets?issuer=acme&lease_size=10").json()
        assert body["reconciliation"] is None


class TestCadence:
    QUERY = "lam=100&c=0.5&w=1000&rho=0.01&delta=2&t_max=60"

    def test_it_opens_no_trail_and_still_answers(self, client: TestClient) -> None:
        # The one read with no chain in it: a fresh server with no chains at all
        # must still be able to answer it.
        body = client.get(f"/v1/cadence?{self.QUERY}").json()
        assert body["exit_code"] == 0
        assert "N_opt" in body["stdout"]

    def test_no_chain_id_appears_in_argv(self, client: TestClient) -> None:
        argv = client.get(f"/v1/cadence?{self.QUERY}").json()["argv"]
        assert not any("chains" in arg for arg in argv)

    def test_the_multiplier_is_optional(self, client: TestClient) -> None:
        assert "--M" not in client.get(f"/v1/cadence?{self.QUERY}").json()["argv"]

    def test_the_multiplier_is_passed_when_given(self, client: TestClient) -> None:
        argv = client.get(f"/v1/cadence?{self.QUERY}&m=3").json()["argv"]
        assert "--M" in argv

    def test_an_infeasible_anchor_technology_is_exit_1_not_a_crash(
        self, client: TestClient
    ) -> None:
        # delta > t_max: the anchor technology is wrong, not the cadence.
        body = client.get("/v1/cadence?lam=100&c=0.5&w=1000&rho=0.01&delta=90&t_max=60").json()
        assert body["exit_code"] == 1

    @pytest.mark.parametrize(
        "query",
        [
            "c=0.5&w=1000&rho=0.01&delta=2&t_max=60",
            "lam=100&w=1000&rho=0.01&delta=2&t_max=60",
            "lam=100&c=0.5&rho=0.01&delta=2&t_max=60",
        ],
    )
    def test_a_missing_required_measurement_is_422_not_a_guess(
        self, client: TestClient, query: str
    ) -> None:
        assert client.get(f"/v1/cadence?{query}").status_code == 422

    @pytest.mark.parametrize("bad", ["abc", "--help", "", "1,5"])
    def test_a_measurement_that_is_not_a_number_never_reaches_argv(
        self, client: TestClient, bad: str
    ) -> None:
        response = client.get(f"/v1/cadence?lam={bad}&c=0.5&w=1000&rho=0.01&delta=2&t_max=60")
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_measurement"


class TestTheChainIdIsCheckedOnEveryOneOfThem:
    """A bad chain id is a 400 on each route, not a path joined to anything.

    Each of these routes validates its own flag first, so without a case per
    route the chain-id check could be missing from one of them and every other
    test would still pass.
    """

    @pytest.mark.parametrize(
        "path",
        [
            "/v1/chains/a%20b/tail",
            "/v1/chains/a%20b/consistency?old_seq=1&old_root=" + HEX64,
            "/v1/chains/a%20b/verify-handoff?origin=default",
            "/v1/chains/a%20b/reconcile-tickets?issuer=acme&lease_size=10",
        ],
    )
    def test_a_chain_id_that_is_not_a_safe_name_is_refused(
        self, client: TestClient, path: str
    ) -> None:
        response = client.get(path)
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_chain_id"


class TestTheseReadsAreStillReadsOnly:
    @pytest.mark.parametrize(
        "path",
        [
            "/v1/chains/default/tail",
            "/v1/chains/default/checkpoint",
            f"/v1/chains/default/consistency?old_seq=1&old_root={HEX64}",
            "/v1/chains/default/verify-handoff?origin=default",
            "/v1/chains/default/reconcile-tickets?issuer=acme&lease_size=10",
            "/v1/cadence?lam=100&c=0.5&w=1000&rho=0.01&delta=2&t_max=60",
        ],
    )
    def test_every_new_route_refuses_an_unauthenticated_caller(
        self, tmp_path: Path, path: str
    ) -> None:
        keyed = TestClient(
            create_app(Settings(data_dir=tmp_path / "data", api_key="chain-write-key"))
        )
        assert keyed.get(path).status_code == 401

    @pytest.mark.parametrize(
        "path",
        [
            "/v1/chains/default/tail",
            "/v1/chains/default/checkpoint",
            "/v1/cadence",
        ],
    )
    def test_no_new_route_accepts_a_write(self, client: TestClient, path: str) -> None:
        for method in (client.post, client.put, client.patch, client.delete):
            assert method(path).status_code == 405


class TestLedgerStatus:
    """The read whose arguments come from the settings store, not the request.

    Three outcomes, and the point of each test is that none of them is a status
    nobody read. An unconfigured ledger is a STATE; a single RPC endpoint is the
    command's own refusal carried through; a bond without a writer is named
    rather than sent to argparse to be rejected as a usage error.
    """

    ADDRESS = "0x" + "ab" * 20
    PAIR = "https://rpc-a.example.test,https://rpc-b.example.test"

    def test_an_unconfigured_ledger_is_a_state_not_an_error(self, stocked: TestClient) -> None:
        body = stocked.get("/v1/chains/default/ledger-status")
        assert body.status_code == 200
        assert body.json() == {
            "configured": False,
            "reason": "no_liveness_address",
            "missing": ["ledger_liveness_address"],
            "outcome": None,
        }

    def test_it_never_reports_a_status_it_did_not_read(self, stocked: TestClient) -> None:
        # No green tick borrowed from a chain nobody queried.
        assert stocked.get("/v1/chains/default/ledger-status").json()["outcome"] is None

    def test_configuring_the_liveness_address_makes_the_command_run(
        self, stocked: TestClient
    ) -> None:
        stocked.put("/v1/settings/ledger_liveness_address", json={"value": self.ADDRESS})
        body = stocked.get("/v1/chains/default/ledger-status").json()
        assert body["configured"] is True
        assert body["outcome"]["command"] == "ledger-status"
        assert self.ADDRESS in body["outcome"]["argv"]

    def test_with_no_endpoints_the_command_itself_says_unverifiable(
        self, stocked: TestClient
    ) -> None:
        # Carried through verbatim rather than translated: the library refuses
        # to cross-check against fewer than two voices, and that refusal is the
        # answer.
        stocked.put("/v1/settings/ledger_liveness_address", json={"value": self.ADDRESS})
        outcome = stocked.get("/v1/chains/default/ledger-status").json()["outcome"]
        assert outcome["verdict"] == "unverifiable"
        assert "disagree with itself" in outcome["stdout"] + outcome["stderr"]

    def test_two_endpoints_both_reach_argv(self, stocked: TestClient) -> None:
        stocked.put("/v1/settings/ledger_liveness_address", json={"value": self.ADDRESS})
        stocked.put("/v1/settings/ledger_rpc_urls", json={"value": self.PAIR})
        argv = stocked.get("/v1/chains/default/ledger-status").json()["outcome"]["argv"]
        assert argv.count("--rpc") == 2

    def test_a_bond_without_a_writer_is_named_not_sent(self, stocked: TestClient) -> None:
        # argparse would answer "usage error", which is a server bug wearing no
        # verdict. Naming the missing setting is the useful answer.
        stocked.put("/v1/settings/ledger_liveness_address", json={"value": self.ADDRESS})
        stocked.put("/v1/settings/ledger_bond_address", json={"value": self.ADDRESS})
        body = stocked.get("/v1/chains/default/ledger-status").json()
        assert body["configured"] is False
        assert body["reason"] == "bond_without_writer"
        assert body["missing"] == ["ledger_writer_address"]
        assert body["outcome"] is None

    def test_a_bond_with_its_writer_runs(self, stocked: TestClient) -> None:
        for key in (
            "ledger_liveness_address",
            "ledger_bond_address",
            "ledger_writer_address",
        ):
            stocked.put(f"/v1/settings/{key}", json={"value": self.ADDRESS})
        argv = stocked.get("/v1/chains/default/ledger-status").json()["outcome"]["argv"]
        assert "--bond" in argv
        assert "--writer" in argv

    def test_every_optional_contract_reaches_argv_when_set(self, stocked: TestClient) -> None:
        for key in (
            "ledger_liveness_address",
            "ledger_registry_address",
            "ledger_bond_address",
            "ledger_writer_address",
        ):
            stocked.put(f"/v1/settings/{key}", json={"value": self.ADDRESS})
        stocked.put("/v1/settings/ledger_trail_id", json={"value": "prod"})
        argv = stocked.get("/v1/chains/default/ledger-status").json()["outcome"]["argv"]
        for flag in ("--liveness", "--registry", "--bond", "--writer", "--trail-id"):
            assert flag in argv, flag

    def test_the_endpoints_come_from_the_store_never_from_the_request(
        self, stocked: TestClient
    ) -> None:
        # A caller must not be able to aim this server's RPC client at a host of
        # their choosing.
        stocked.put("/v1/settings/ledger_liveness_address", json={"value": self.ADDRESS})
        argv = stocked.get(
            "/v1/chains/default/ledger-status?rpc=http://attacker.example.test"
        ).json()["outcome"]["argv"]
        assert not any("attacker" in arg for arg in argv)

    def test_a_bad_chain_id_is_refused_before_anything_runs(self, client: TestClient) -> None:
        response = client.get("/v1/chains/a%20b/ledger-status")
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_chain_id"

    def test_it_refuses_an_unauthenticated_caller(self, tmp_path: Path) -> None:
        keyed = TestClient(
            create_app(Settings(data_dir=tmp_path / "data", api_key="chain-write-key"))
        )
        assert keyed.get("/v1/chains/default/ledger-status").status_code == 401
