"""The Settings surface: what it shows, what it changes, what it refuses.

The refusals carry the weight here. A "show me the configuration" screen is
exactly the shape of thing that ends up disclosing a credential, so the tests
that matter most are the ones proving no secret VALUE is ever in a response and
no credential can be written through either mutating route.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from waxseal_server.app import create_app
from waxseal_server.config import Settings
from waxseal_server.domain.settings import FORBIDDEN, SPECS
from waxseal_server.storage.operators_memory import InMemoryOperatorStore
from waxseal_server.storage.settings_memory import InMemorySettingsStore

CHAIN_KEY = "chain-write-key-do-not-disclose"
WITNESS_KEY = "witness-key-do-not-disclose"
DB_URL = "postgresql://user:secret-password@db.internal/waxseal"

# Two endpoints, always: one cannot disagree with itself.
RPC = "https://rpc-a.example.test,https://rpc-b.example.test"
ADDRESS = "0x" + "ab" * 20


@pytest.fixture
def client(tmp_path: Path) -> TestClient:
    return TestClient(create_app(Settings(data_dir=tmp_path / "data")))


@pytest.fixture
def keyed(tmp_path: Path) -> TestClient:
    """A server with every credential configured — the leak-test fixture.

    The stores are injected so a `database_url` that LOOKS real (it carries a
    password, which is the point) is never dialled. What is under test is how
    the setting is reported, not whether the host resolves.
    """
    return TestClient(
        create_app(
            Settings(
                data_dir=tmp_path / "data",
                api_key=CHAIN_KEY,
                witness_api_key=WITNESS_KEY,
                database_url=DB_URL,
            ),
            operators=InMemoryOperatorStore(),
            config=InMemorySettingsStore(),
        )
    )


def auth() -> dict[str, str]:
    return {"Authorization": f"Bearer {CHAIN_KEY}"}


class TestNoSecretIsEverDisclosed:
    def test_no_credential_value_appears_anywhere_in_the_response(self, keyed: TestClient) -> None:
        # The whole body as text, so a secret cannot hide in a field this test
        # forgot to name.
        body = keyed.get("/v1/settings", headers=auth()).text
        assert CHAIN_KEY not in body
        assert WITNESS_KEY not in body
        assert DB_URL not in body
        assert "secret-password" not in body

    @pytest.mark.parametrize("key", ["api_key", "witness_api_key", "database_url"])
    def test_a_secret_reports_only_whether_it_is_set(self, keyed: TestClient, key: str) -> None:
        rows = keyed.get("/v1/settings", headers=auth()).json()["deployment"]
        [row] = [r for r in rows if r["key"] == key]
        assert row["state"] == "set"
        assert row["secret"] is True
        assert row["editable"] is False
        # There is no field a value could occupy.
        assert "value" not in row

    @pytest.mark.parametrize("key", ["api_key", "witness_api_key", "database_url"])
    def test_an_unset_secret_says_unset_rather_than_being_omitted(
        self, client: TestClient, key: str
    ) -> None:
        # Omitting the row would make "no credential configured" — a real and
        # important deployment state — indistinguishable from "not reported".
        rows = client.get("/v1/settings").json()["deployment"]
        [row] = [r for r in rows if r["key"] == key]
        assert row["state"] == "unset"


class TestNoCredentialCanBeWritten:
    @pytest.mark.parametrize("key", sorted(FORBIDDEN))
    def test_writing_an_environment_only_setting_is_refused(
        self, client: TestClient, key: str
    ) -> None:
        response = client.put(f"/v1/settings/{key}", json={"value": "attacker-supplied"})
        assert response.status_code == 404
        assert response.json()["error"] == "no_such_setting"

    @pytest.mark.parametrize("key", sorted(FORBIDDEN))
    def test_resetting_an_environment_only_setting_is_refused(
        self, client: TestClient, key: str
    ) -> None:
        assert client.post(f"/v1/settings/{key}/reset").status_code == 404

    def test_the_refusal_says_why_rather_than_just_no(self, client: TestClient) -> None:
        detail = client.put("/v1/settings/api_key", json={"value": "x"}).json()["detail"]
        assert "environment-only" in detail

    def test_an_unknown_key_is_refused_too(self, client: TestClient) -> None:
        assert client.put("/v1/settings/nonsense", json={"value": "x"}).status_code == 404


class TestReadingTheConfiguration:
    def test_every_registered_setting_is_reported(self, client: TestClient) -> None:
        stored = client.get("/v1/settings").json()["stored"]
        assert {row["key"] for row in stored} == {spec.key for spec in SPECS}

    def test_an_untouched_setting_reports_its_default_as_the_source(
        self, client: TestClient
    ) -> None:
        stored = client.get("/v1/settings").json()["stored"]
        [page] = [r for r in stored if r["key"] == "page_size"]
        assert page["value"] == "500"
        assert page["source"] == "default"

    def test_an_unconfigured_setting_is_null_not_an_empty_string(self, client: TestClient) -> None:
        stored = client.get("/v1/settings").json()["stored"]
        [rpc] = [r for r in stored if r["key"] == "ledger_rpc_urls"]
        assert rpc["value"] is None
        assert rpc["source"] == "default"

    def test_the_open_deployment_reports_write_auth_open(self, client: TestClient) -> None:
        # Rule 6: a fail-open must be visible, not implied by an absent row.
        rows = client.get("/v1/settings").json()["deployment"]
        [row] = [r for r in rows if r["key"] == "write_auth"]
        assert row["value"] == "open"

    def test_a_keyed_deployment_reports_bearer_required(self, keyed: TestClient) -> None:
        rows = keyed.get("/v1/settings", headers=auth()).json()["deployment"]
        [row] = [r for r in rows if r["key"] == "write_auth"]
        assert row["value"] == "bearer_required"

    def test_the_backend_in_use_is_named(self, client: TestClient) -> None:
        # The in-memory store forgets on restart, so which one is answering is
        # a fact an operator needs rather than an implementation detail.
        assert client.get("/v1/settings").json()["backend"] == "memory"


class TestChangingASetting:
    def test_a_value_is_stored_and_read_back(self, client: TestClient) -> None:
        assert client.put("/v1/settings/ledger_rpc_urls", json={"value": RPC}).status_code == 200
        stored = client.get("/v1/settings").json()["stored"]
        [rpc] = [r for r in stored if r["key"] == "ledger_rpc_urls"]
        assert rpc["value"] == RPC
        assert rpc["source"] == "stored"

    def test_a_stored_value_equal_to_the_default_still_reads_as_stored(
        self, client: TestClient
    ) -> None:
        # "Somebody chose 500" and "nobody has touched it" are different facts.
        client.put("/v1/settings/page_size", json={"value": "500"})
        stored = client.get("/v1/settings").json()["stored"]
        [page] = [r for r in stored if r["key"] == "page_size"]
        assert page["source"] == "stored"

    def test_an_address_round_trips(self, client: TestClient) -> None:
        client.put("/v1/settings/ledger_liveness_address", json={"value": ADDRESS})
        stored = client.get("/v1/settings").json()["stored"]
        [row] = [r for r in stored if r["key"] == "ledger_liveness_address"]
        assert row["value"] == ADDRESS

    @pytest.mark.parametrize(
        ("key", "bad"),
        [
            ("page_size", "0"),
            ("page_size", "abc"),
            ("ledger_rpc_urls", "file:///etc/passwd"),
            ("ledger_liveness_address", "0xdead"),
            ("ledger_trail_id", "../etc"),
        ],
    )
    def test_a_value_failing_its_spec_is_400_and_is_not_stored(
        self, client: TestClient, key: str, bad: str
    ) -> None:
        response = client.put(f"/v1/settings/{key}", json={"value": bad})
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_setting_value"
        stored = client.get("/v1/settings").json()["stored"]
        [row] = [r for r in stored if r["key"] == key]
        assert row["source"] == "default"

    def test_a_file_url_is_refused_so_the_server_cannot_be_aimed_at_its_own_disk(
        self, client: TestClient
    ) -> None:
        # The server fetches this endpoint itself, so a `file://` value would
        # turn an operator-supplied string into a read of the server's disk.
        assert (
            client.put(
                "/v1/settings/ledger_rpc_urls", json={"value": "file:///etc/passwd"}
            ).status_code
            == 400
        )

    @pytest.mark.parametrize("body", ['{"value": 500}', '{"nope": "x"}', "[]", "not json"])
    def test_a_body_that_is_not_a_string_value_is_refused(
        self, client: TestClient, body: str
    ) -> None:
        response = client.put(
            "/v1/settings/page_size", content=body, headers={"Content-Type": "application/json"}
        )
        assert response.status_code == 400


class TestResetting:
    def test_reset_reverts_to_the_default(self, client: TestClient) -> None:
        client.put("/v1/settings/page_size", json={"value": "250"})
        assert client.post("/v1/settings/page_size/reset").json()["reset"] is True
        stored = client.get("/v1/settings").json()["stored"]
        [page] = [r for r in stored if r["key"] == "page_size"]
        assert page["value"] == "500"
        assert page["source"] == "default"

    def test_resetting_twice_reports_that_it_did_nothing(self, client: TestClient) -> None:
        # Same shape as revoke: a retry says what it did rather than claiming
        # it acted.
        client.put("/v1/settings/page_size", json={"value": "250"})
        client.post("/v1/settings/page_size/reset")
        assert client.post("/v1/settings/page_size/reset").json()["reset"] is False

    def test_resetting_something_never_set_reports_false(self, client: TestClient) -> None:
        assert client.post("/v1/settings/ledger_bond_address/reset").json()["reset"] is False


class TestAuthority:
    @pytest.mark.parametrize(
        ("method", "path"),
        [
            ("get", "/v1/settings"),
            ("put", "/v1/settings/page_size"),
            ("post", "/v1/settings/page_size/reset"),
        ],
    )
    def test_every_route_refuses_an_unauthenticated_caller(
        self, keyed: TestClient, method: str, path: str
    ) -> None:
        assert getattr(keyed, method)(path).status_code == 401

    def test_the_read_needs_keys_manage_not_merely_trails_read(self, tmp_path: Path) -> None:
        # An auditor's scope deliberately does not reach this screen: where a
        # server keeps its data and which authorities are closed is
        # administrative reconnaissance, not an audit finding.
        from waxseal_server.domain.operators import Role

        operators = InMemoryOperatorStore()
        operators.create_operator(
            username="auditor", display_name="a", email=None, role=Role.AUDITOR
        )
        plaintext, _ = operators.mint_key(username="auditor", label="k")
        client = TestClient(create_app(Settings(data_dir=tmp_path / "data"), operators=operators))
        response = client.get("/v1/settings", headers={"Authorization": f"Bearer {plaintext}"})
        assert response.status_code == 403
        assert "keys:manage" in response.json()["detail"]
