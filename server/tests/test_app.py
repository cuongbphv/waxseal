"""HTTP surface: REMOTE.md sections 4, 5, 7, 8 and 10.

The status codes here are the contract, not an implementation detail — the
waxseal client branches on them and on nothing else (it never parses an error
body). A 200 where the contract says 404, or a 500 where it says 409, changes
what every client in the field concludes.
"""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from waxseal_server.app import Settings, create_app

CHECKPOINT = {"seq": 4, "entry_hash": "aa" * 32, "root": "bb" * 32}


@pytest.fixture
def client(tmp_path: Path) -> TestClient:
    return TestClient(create_app(Settings(data_dir=tmp_path / "data")))


@pytest.fixture
def keyed_client(tmp_path: Path) -> TestClient:
    return TestClient(
        create_app(
            Settings(
                data_dir=tmp_path / "data",
                api_key="chain-write-key",
                witness_api_key="witness-read-key",
            )
        )
    )


def _post(client: TestClient, envelope: dict[str, Any], chain: str = "default") -> Any:
    return client.post(f"/v1/chains/{chain}/entries", json=envelope)


class TestHeadEndpoint:
    def test_an_empty_chain_answers_404(self, client: TestClient) -> None:
        # REMOTE.md section 4: 404 here means "no entries yet". The client turns
        # it into (seq=-1, GENESIS) and appends seq 0 — never an error path.
        assert client.get("/v1/chains/default/head").status_code == 404

    def test_head_reports_seq_and_entry_hash(
        self, client: TestClient, envelopes: list[dict[str, Any]]
    ) -> None:
        _post(client, envelopes[0])
        resp = client.get("/v1/chains/default/head")
        assert resp.status_code == 200
        assert resp.json() == {"seq": 0, "entry_hash": envelopes[0]["entry_hash"]}

    def test_an_invalid_chain_id_is_a_400(self, client: TestClient) -> None:
        assert client.get("/v1/chains/a%20b/head").status_code == 400

    def test_a_traversal_attempt_never_reads_outside_the_root(self, client: TestClient) -> None:
        # Two layers have to fail for this to escape: the URL router (which
        # matches one path segment) and the chain_id check. The assertion is on
        # the outcome rather than on which layer caught it.
        assert client.get("/v1/chains/..%2Fescape/head").status_code in (400, 404)


class TestAppendEndpoint:
    def test_a_valid_entry_is_201(
        self, client: TestClient, envelopes: list[dict[str, Any]]
    ) -> None:
        assert _post(client, envelopes[0]).status_code == 201

    def test_the_201_body_carries_the_receipt(
        self, client: TestClient, envelopes: list[dict[str, Any]]
    ) -> None:
        # REMOTE.md section 10: both fields or neither.
        body = _post(client, envelopes[0]).json()
        assert body["receipt_seq"] == 0
        assert len(body["receipt_head"]) == 64

    def test_a_replayed_entry_is_409(
        self, client: TestClient, envelopes: list[dict[str, Any]]
    ) -> None:
        _post(client, envelopes[0])
        assert _post(client, envelopes[0]).status_code == 409

    def test_an_entry_that_skips_a_seq_is_409(
        self, client: TestClient, envelopes: list[dict[str, Any]]
    ) -> None:
        assert _post(client, envelopes[1]).status_code == 409

    def test_a_forked_prev_hash_is_409(
        self, client: TestClient, envelopes: list[dict[str, Any]]
    ) -> None:
        _post(client, envelopes[0])
        forked = copy.deepcopy(envelopes[1])
        forked["header"]["prev_hash"] = "ff" * 32
        assert _post(client, forked).status_code == 409

    def test_a_malformed_envelope_is_400_not_409(
        self, client: TestClient, envelopes: list[dict[str, Any]]
    ) -> None:
        # 400 and 409 mean different things to the client: 409 is retried
        # against a fresh head, 400 never is. Collapsing them would spin a
        # client 32 times over a body that can never be accepted.
        broken = copy.deepcopy(envelopes[0])
        broken.pop("entry_hash")
        assert _post(client, broken).status_code == 400

    def test_a_body_that_is_not_json_is_400(self, client: TestClient) -> None:
        resp = client.post(
            "/v1/chains/default/entries",
            content=b"<html>proxy error</html>",
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code == 400

    def test_an_invalid_chain_id_is_400(
        self, client: TestClient, envelopes: list[dict[str, Any]]
    ) -> None:
        assert _post(client, envelopes[0], chain="a b").status_code == 400


class TestEntriesEndpoint:
    def test_an_empty_chain_answers_404(self, client: TestClient) -> None:
        assert client.get("/v1/chains/default/entries").status_code == 404

    def test_entries_come_back_in_append_order_with_a_null_cursor(
        self, client: TestClient, envelopes: list[dict[str, Any]]
    ) -> None:
        for env in envelopes:
            _post(client, env)
        body = client.get("/v1/chains/default/entries").json()
        assert [e["header"]["seq"] for e in body["entries"]] == [0, 1, 2, 3, 4]
        assert body["next_cursor"] is None

    def test_a_page_boundary_hands_back_a_cursor_that_advances(
        self, tmp_path: Path, envelopes: list[dict[str, Any]]
    ) -> None:
        client = TestClient(create_app(Settings(data_dir=tmp_path / "d", page_size=2)))
        for env in envelopes:
            _post(client, env)
        seen: list[int] = []
        url = "/v1/chains/default/entries"
        while True:
            body = client.get(url).json()
            seen.extend(e["header"]["seq"] for e in body["entries"])
            if body["next_cursor"] is None:
                break
            url = f"/v1/chains/default/entries?cursor={body['next_cursor']}"
        assert seen == [0, 1, 2, 3, 4]

    def test_an_unrecognized_cursor_is_400(
        self, client: TestClient, envelopes: list[dict[str, Any]]
    ) -> None:
        _post(client, envelopes[0])
        assert client.get("/v1/chains/default/entries?cursor=nope").status_code == 400

    def test_a_stored_envelope_is_returned_verbatim(
        self, client: TestClient, envelopes: list[dict[str, Any]]
    ) -> None:
        _post(client, envelopes[0])
        body = client.get("/v1/chains/default/entries").json()
        assert body["entries"] == [envelopes[0]]


class TestReceiptsHeadEndpoint:
    def test_no_receipts_yet_is_404_not_an_error(self, client: TestClient) -> None:
        assert client.get("/v1/chains/default/receipts/head").status_code == 404

    def test_the_head_matches_the_last_201(
        self, client: TestClient, envelopes: list[dict[str, Any]]
    ) -> None:
        _post(client, envelopes[0])
        issued = _post(client, envelopes[1]).json()
        assert client.get("/v1/chains/default/receipts/head").json() == {
            "receipt_seq": issued["receipt_seq"],
            "receipt_head": issued["receipt_head"],
        }

    def test_it_is_readable_without_the_write_credential(
        self, keyed_client: TestClient, envelopes: list[dict[str, Any]]
    ) -> None:
        # REMOTE.md section 10: the write credential grants nothing here, and a
        # third party auditing the server's acknowledgment history is the whole
        # reason the endpoint exists.
        keyed_client.post(
            "/v1/chains/default/entries",
            json=envelopes[0],
            headers={"Authorization": "Bearer chain-write-key"},
        )
        assert keyed_client.get("/v1/chains/default/receipts/head").status_code == 200


class TestAuthentication:
    def test_an_append_without_a_bearer_token_is_401(
        self, keyed_client: TestClient, envelopes: list[dict[str, Any]]
    ) -> None:
        assert _post(keyed_client, envelopes[0]).status_code == 401

    def test_an_append_with_the_wrong_token_is_401(
        self, keyed_client: TestClient, envelopes: list[dict[str, Any]]
    ) -> None:
        resp = keyed_client.post(
            "/v1/chains/default/entries",
            json=envelopes[0],
            headers={"Authorization": "Bearer not-the-key"},
        )
        assert resp.status_code == 401

    def test_an_append_with_the_right_token_is_201(
        self, keyed_client: TestClient, envelopes: list[dict[str, Any]]
    ) -> None:
        resp = keyed_client.post(
            "/v1/chains/default/entries",
            json=envelopes[0],
            headers={"Authorization": "Bearer chain-write-key"},
        )
        assert resp.status_code == 201

    def test_reading_the_chain_api_also_needs_the_token(self, keyed_client: TestClient) -> None:
        assert keyed_client.get("/v1/chains/default/head").status_code == 401

    def test_the_public_api_never_asks_for_a_credential(self, keyed_client: TestClient) -> None:
        assert keyed_client.get("/public/v1/chains").status_code == 200

    def test_an_unconfigured_key_is_reported_as_open_not_as_secured(
        self, client: TestClient
    ) -> None:
        # CLAUDE.md rule 6: a degraded guard is labelled in the output, never
        # swallowed. An open server that describes itself as authenticated is
        # the false-confidence half of the collapse this project exists to stop.
        assert client.get("/v1/meta").json()["write_auth"] == "open"

    def test_a_configured_key_is_reported_as_required(self, keyed_client: TestClient) -> None:
        assert keyed_client.get("/v1/meta").json()["write_auth"] == "bearer_required"


class TestPublicReadApi:
    def test_it_lists_chains(self, client: TestClient, envelopes: list[dict[str, Any]]) -> None:
        _post(client, envelopes[0], chain="alpha")
        assert client.get("/public/v1/chains").json() == {"chains": ["alpha"]}

    def test_it_serves_head(self, client: TestClient, envelopes: list[dict[str, Any]]) -> None:
        _post(client, envelopes[0])
        assert client.get("/public/v1/chains/default/head").json()["seq"] == 0

    def test_it_serves_entries(self, client: TestClient, envelopes: list[dict[str, Any]]) -> None:
        _post(client, envelopes[0])
        assert len(client.get("/public/v1/chains/default/entries").json()["entries"]) == 1

    def test_it_serves_the_receipt_head(
        self, client: TestClient, envelopes: list[dict[str, Any]]
    ) -> None:
        _post(client, envelopes[0])
        assert client.get("/public/v1/chains/default/receipts/head").json()["receipt_seq"] == 0

    def test_it_verifies_the_servers_own_receipt_log(
        self, client: TestClient, envelopes: list[dict[str, Any]]
    ) -> None:
        for env in envelopes[:3]:
            _post(client, env)
        body = client.get("/public/v1/chains/default/receipts/verify").json()
        assert body == {
            "verdict": "ok",
            "checked": 3,
            "reason": None,
            "broken_receipt_seq": None,
            "exit_code": 0,
        }

    def test_an_absent_receipt_log_reports_not_recorded_never_zero(
        self, client: TestClient
    ) -> None:
        body = client.get("/public/v1/chains/default/receipts/verify").json()
        assert body["checked"] is None
        assert body["reason"] == "not_recorded"

    def test_a_tampered_receipt_log_reports_broken(
        self, tmp_path: Path, envelopes: list[dict[str, Any]]
    ) -> None:
        app = create_app(Settings(data_dir=tmp_path / "d"))
        client = TestClient(app)
        _post(client, envelopes[0])
        _post(client, envelopes[1])
        log = tmp_path / "d" / "chains" / "default" / "receipts.jsonl"
        lines = log.read_text().splitlines()
        tampered = lines[1].replace('"receipt_head":"', '"receipt_head":"a')[:-1]
        log.write_text(lines[0] + "\n" + tampered + "\n")
        body = client.get("/public/v1/chains/default/receipts/verify").json()
        assert body["verdict"] == "broken"
        assert body["exit_code"] == 1

    def test_the_public_api_exposes_no_write_route(self, client: TestClient) -> None:
        # The plan's mirror-node adoption is architectural, not a credential
        # check: the read authority is a different surface, so there is nothing
        # under /public for a caller to write to even by accident.
        paths = client.app.openapi()["paths"]  # type: ignore[attr-defined]
        public = {p: ops for p, ops in paths.items() if p.startswith("/public")}
        assert public
        for path, operations in public.items():
            assert set(operations) <= {"get", "head"}, path


class TestWitnessEndpoint:
    def test_posting_a_checkpoint_is_201_with_a_receipt(self, client: TestClient) -> None:
        resp = client.post("/v1/witness/w1", json=CHECKPOINT)
        assert resp.status_code == 201
        assert isinstance(resp.json()["receipt"], str)

    def test_a_witness_with_nothing_yet_is_404(self, client: TestClient) -> None:
        # REMOTE.md section 8: "this witness has seen nothing" is an answer.
        assert client.get("/v1/witness/w1").status_code == 404

    def test_checkpoints_are_handed_back_oldest_first(self, client: TestClient) -> None:
        for seq in (1, 2, 3):
            client.post("/v1/witness/w1", json={**CHECKPOINT, "seq": seq})
        body = client.get("/v1/witness/w1").json()
        assert [c["seq"] for c in body["checkpoints"]] == [1, 2, 3]

    def test_the_aggregate_binding_keys_round_trip(self, client: TestClient) -> None:
        # REMOTE.md section 9: both keys appear together or neither does.
        bound = {**CHECKPOINT, "agg_commit": "cc" * 32, "agg_epoch": 7}
        client.post("/v1/witness/w1", json=bound)
        [stored] = client.get("/v1/witness/w1").json()["checkpoints"]
        assert stored["agg_commit"] == "cc" * 32
        assert stored["agg_epoch"] == 7

    def test_a_malformed_checkpoint_is_400(self, client: TestClient) -> None:
        assert client.post("/v1/witness/w1", json={"seq": 1}).status_code == 400

    def test_a_checkpoint_with_a_non_hex_root_is_400(self, client: TestClient) -> None:
        assert client.post("/v1/witness/w1", json={**CHECKPOINT, "root": "zz"}).status_code == 400

    def test_an_invalid_witness_id_is_400(self, client: TestClient) -> None:
        assert client.post("/v1/witness/a b", json=CHECKPOINT).status_code == 400

    def test_the_witness_credential_is_required_when_configured(
        self, keyed_client: TestClient
    ) -> None:
        assert keyed_client.post("/v1/witness/w1", json=CHECKPOINT).status_code == 401

    def test_the_witness_credential_is_accepted(self, keyed_client: TestClient) -> None:
        resp = keyed_client.post(
            "/v1/witness/w1",
            json=CHECKPOINT,
            headers={"Authorization": "Bearer witness-read-key"},
        )
        assert resp.status_code == 201

    def test_the_chain_write_key_is_refused_at_the_witness(self, keyed_client: TestClient) -> None:
        # REMOTE.md section 8: a witness is a DIFFERENT administrative
        # authority. A witness that accepted the chain's write credential could
        # append forged entries to the very chain it exists to cross-check.
        resp = keyed_client.post(
            "/v1/witness/w1",
            json=CHECKPOINT,
            headers={"Authorization": "Bearer chain-write-key"},
        )
        assert resp.status_code == 401

    def test_the_public_read_point_serves_witness_checkpoints(
        self, keyed_client: TestClient
    ) -> None:
        keyed_client.post(
            "/v1/witness/w1",
            json=CHECKPOINT,
            headers={"Authorization": "Bearer witness-read-key"},
        )
        assert keyed_client.get("/public/v1/witness/w1").status_code == 200


class TestHealth:
    def test_health_is_ok(self, client: TestClient) -> None:
        assert client.get("/health").json() == {"status": "ok"}


class TestSettingsFromEnv:
    def test_env_supplies_the_credentials_and_data_dir(self) -> None:
        settings = Settings.from_env(
            {
                "WAXSEAL_SERVER_DATA_DIR": "/tmp/waxseal-data",
                "WAXSEAL_API_KEY": "k1",
                "WAXSEAL_WITNESS_API_KEY": "k2",
            }
        )
        assert settings.data_dir == Path("/tmp/waxseal-data")
        assert settings.api_key == "k1"
        assert settings.witness_api_key == "k2"

    def test_absent_credentials_are_none_not_empty_strings(self) -> None:
        settings = Settings.from_env({"WAXSEAL_SERVER_DATA_DIR": "/tmp/x"})
        assert settings.api_key is None
        assert settings.witness_api_key is None

    def test_the_data_dir_has_a_default(self) -> None:
        assert Settings.from_env({}).data_dir == Path("/var/lib/waxseal")


class TestInvalidIdsAcrossEveryRoute:
    """One bad id, every door. A path check that holds on `/head` and not on
    `/entries` is not a path check."""

    @pytest.mark.parametrize(
        "path",
        [
            "/v1/chains/a%20b/head",
            "/v1/chains/a%20b/entries",
            "/v1/chains/a%20b/receipts/head",
            "/public/v1/chains/a%20b/head",
            "/public/v1/chains/a%20b/entries",
            "/public/v1/chains/a%20b/receipts/head",
            "/public/v1/chains/a%20b/receipts/verify",
            "/v1/witness/a%20b",
            "/public/v1/witness/a%20b",
        ],
    )
    def test_a_bad_id_is_400_everywhere(self, client: TestClient, path: str) -> None:
        assert client.get(path).status_code == 400


class TestCheckpointValidation:
    @pytest.mark.parametrize(
        ("body", "why"),
        [
            (["not", "an", "object"], "not-an-object"),
            ({**CHECKPOINT, "seq": "4"}, "seq-not-an-int"),
            ({**CHECKPOINT, "seq": -1}, "seq-negative"),
            ({**CHECKPOINT, "seq": True}, "seq-a-bool"),
            ({**CHECKPOINT, "entry_hash": 7}, "entry_hash-not-a-string"),
            ({**CHECKPOINT, "agg_commit": "cc" * 32}, "commit-without-epoch"),
            ({**CHECKPOINT, "agg_epoch": 1}, "epoch-without-commit"),
            ({**CHECKPOINT, "agg_commit": "nope", "agg_epoch": 1}, "commit-not-hex"),
            ({**CHECKPOINT, "agg_commit": "cc" * 32, "agg_epoch": "1"}, "epoch-not-an-int"),
        ],
    )
    def test_a_malformed_checkpoint_is_400(self, client: TestClient, body: Any, why: str) -> None:
        assert client.post("/v1/witness/w1", json=body).status_code == 400, why

    def test_a_witness_body_that_is_not_json_is_400(self, client: TestClient) -> None:
        resp = client.post(
            "/v1/witness/w1",
            content=b"not json",
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code == 400


class TestPublicScopeStatement:
    """The frozen scope statement, served from the library that owns it.

    The dashboard prints it verbatim on every verdict. Reading it from the
    library rather than retyping it in JavaScript is what stops the UI's copy
    drifting from the frozen prose — SCOPE_ID exists precisely so a control
    narrative citing `waxseal-scope-v1` can still say what those words were.
    """

    def test_it_serves_the_frozen_statement(self, client: TestClient) -> None:
        from waxseal.domain.report import SCOPE_ID, SCOPE_LINE, SCOPE_STATEMENT

        assert client.get("/public/v1/scope").json() == {
            "id": SCOPE_ID,
            "statement": SCOPE_STATEMENT,
            "line": SCOPE_LINE,
        }

    def test_it_needs_no_credential_and_no_chain(self, keyed_client: TestClient) -> None:
        # Available on an empty server: the statement qualifies every verdict,
        # so it cannot depend on a chain existing to be readable.
        assert keyed_client.get("/public/v1/scope").status_code == 200
