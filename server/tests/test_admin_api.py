"""Operators, keys, and what each credential is actually allowed to do.

The scope tests here are the ones that matter. A writer key is what the Claude
Code hook carries on a developer's machine, and the whole reason it is a
separate role is that leaking it must not leak the trail: it can extend the
chain and discover the tail it is extending, and it cannot read what is on it.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from waxseal_server.app import Settings, create_app
from waxseal_server.storage.operators_memory import InMemoryOperatorStore

BOOTSTRAP = "bootstrap-key"


@pytest.fixture
def store() -> InMemoryOperatorStore:
    return InMemoryOperatorStore()


@pytest.fixture
def client(tmp_path: Path, store: InMemoryOperatorStore) -> TestClient:
    settings = Settings(data_dir=tmp_path / "data", api_key=BOOTSTRAP)
    return TestClient(create_app(settings, operators=store))


@pytest.fixture
def open_client(tmp_path: Path, store: InMemoryOperatorStore) -> TestClient:
    return TestClient(create_app(Settings(data_dir=tmp_path / "d"), operators=store))


def admin(client: TestClient) -> dict[str, str]:
    return {"Authorization": f"Bearer {BOOTSTRAP}"}


def seed(client: TestClient, username: str, role: str) -> str:
    """Create an operator and return a usable key for it."""
    client.post(
        "/v1/operators",
        json={"username": username, "display_name": username, "role": role},
        headers=admin(client),
    )
    minted = client.post(
        "/v1/keys", json={"username": username, "label": "test"}, headers=admin(client)
    )
    return str(minted.json()["key"])


class TestWhoami:
    def test_the_bootstrap_credential_is_not_reported_as_an_operator(
        self, client: TestClient
    ) -> None:
        # It has no record, no history and no name of its own. Listing it as a
        # person would put a user in the UI that the store has never heard of.
        body = client.get("/v1/whoami", headers=admin(client)).json()
        assert body["username"] == "bootstrap"
        assert body["is_operator"] is False
        assert body["key_id"] is None

    def test_an_operator_key_reports_its_operator(self, client: TestClient) -> None:
        key = seed(client, "user-waxseal", "writer")
        body = client.get("/v1/whoami", headers={"Authorization": f"Bearer {key}"}).json()
        assert body["username"] == "user-waxseal"
        assert body["role"] == "writer"
        assert body["is_operator"] is True
        assert sorted(body["scopes"]) == ["entries:append", "head:read"]

    def test_no_credential_is_401(self, client: TestClient) -> None:
        assert client.get("/v1/whoami").status_code == 401

    def test_an_open_server_reports_itself_as_unauthenticated(
        self, open_client: TestClient
    ) -> None:
        body = open_client.get("/v1/whoami").json()
        assert body["username"] == "unauthenticated"
        assert body["is_operator"] is False


class TestSeedingClosesAnOpenServer:
    def test_a_server_with_nothing_configured_is_open(self, open_client: TestClient) -> None:
        assert open_client.get("/v1/meta").json()["write_auth"] == "open"

    def test_minting_the_first_key_closes_it(
        self, open_client: TestClient, store: InMemoryOperatorStore
    ) -> None:
        # Seeding IS the securing step. A deployment cannot be left open by
        # forgetting a separate "now turn auth on" flag, because there is none.
        open_client.post(
            "/v1/operators",
            json={"username": "admin", "display_name": "Admin", "role": "admin"},
        )
        open_client.post("/v1/keys", json={"username": "admin", "label": "first"})
        assert open_client.get("/v1/meta").json()["write_auth"] == "bearer_required"
        assert open_client.get("/v1/whoami").status_code == 401


class TestOperatorRoutes:
    def test_creating_and_listing_an_operator(self, client: TestClient) -> None:
        created = client.post(
            "/v1/operators",
            json={
                "username": "admin",
                "display_name": "Admin",
                "email": "cuongbphv@gmail.com",
                "role": "admin",
            },
            headers=admin(client),
        )
        assert created.status_code == 201
        assert created.json()["role"] == "admin"
        assert "keys:manage" in created.json()["scopes"]

        listed = client.get("/v1/operators", headers=admin(client)).json()["operators"]
        assert [o["username"] for o in listed] == ["admin"]

    def test_an_absent_email_stays_null(self, client: TestClient) -> None:
        created = client.post(
            "/v1/operators",
            json={"username": "ci", "display_name": "ci", "role": "writer"},
            headers=admin(client),
        )
        assert created.json()["email"] is None

    def test_a_duplicate_username_is_409(self, client: TestClient) -> None:
        body = {"username": "admin", "display_name": "Admin", "role": "admin"}
        client.post("/v1/operators", json=body, headers=admin(client))
        again = client.post("/v1/operators", json=body, headers=admin(client))
        assert again.status_code == 409
        assert again.json()["error"] == "operator_exists"

    def test_an_unknown_role_is_400_and_names_the_valid_ones(
        self, client: TestClient
    ) -> None:
        resp = client.post(
            "/v1/operators",
            json={"username": "x", "display_name": "x", "role": "superuser"},
            headers=admin(client),
        )
        assert resp.status_code == 400
        assert "admin" in resp.json()["detail"]

    def test_an_unsafe_username_is_400(self, client: TestClient) -> None:
        resp = client.post(
            "/v1/operators",
            json={"username": "../escape", "display_name": "x", "role": "viewer"},
            headers=admin(client),
        )
        assert resp.status_code == 400

    def test_a_body_that_is_not_json_is_400(self, client: TestClient) -> None:
        resp = client.post(
            "/v1/operators",
            content=b"not json",
            headers={**admin(client), "Content-Type": "application/json"},
        )
        assert resp.status_code == 400

    def test_a_body_that_is_not_an_object_is_400(self, client: TestClient) -> None:
        resp = client.post("/v1/operators", json=[1, 2], headers=admin(client))
        assert resp.status_code == 400


class TestKeyRoutes:
    def test_a_minted_key_is_returned_once_with_a_notice(self, client: TestClient) -> None:
        client.post(
            "/v1/operators",
            json={"username": "ci", "display_name": "ci", "role": "writer"},
            headers=admin(client),
        )
        minted = client.post(
            "/v1/keys", json={"username": "ci", "label": "hook"}, headers=admin(client)
        )
        assert minted.status_code == 201
        body = minted.json()
        assert body["key"].startswith("wxs_live_")
        assert "SHA-256" in body["notice"]

    def test_the_listing_never_carries_the_secret(self, client: TestClient) -> None:
        secret = seed(client, "ci", "writer")
        listed = client.get("/v1/keys", headers=admin(client)).json()["keys"]
        assert secret not in str(listed)
        assert listed[0]["fingerprint"].endswith("…")

    def test_minting_for_an_unknown_operator_is_404(self, client: TestClient) -> None:
        resp = client.post(
            "/v1/keys", json={"username": "ghost", "label": "x"}, headers=admin(client)
        )
        assert resp.status_code == 404
        assert resp.json()["error"] == "no_such_operator"

    def test_keys_filter_by_operator(self, client: TestClient) -> None:
        seed(client, "admin2", "admin")
        seed(client, "ci", "writer")
        listed = client.get("/v1/keys?username=ci", headers=admin(client)).json()["keys"]
        assert [k["username"] for k in listed] == ["ci"]

    def test_revoking_reports_what_it_did(self, client: TestClient) -> None:
        key = seed(client, "ci", "writer")
        key_id = client.get("/v1/keys", headers=admin(client)).json()["keys"][0]["key_id"]
        assert client.post(f"/v1/keys/{key_id}/revoke", headers=admin(client)).json() == {
            "revoked": True
        }
        # A retry says it did nothing rather than moving the timestamp.
        assert client.post(f"/v1/keys/{key_id}/revoke", headers=admin(client)).json() == {
            "revoked": False
        }
        revoked_call = client.get(
            "/v1/whoami", headers={"Authorization": f"Bearer {key}"}
        )
        assert revoked_call.status_code == 401

    def test_revoking_an_unknown_key_reports_that_it_did_nothing(
        self, client: TestClient
    ) -> None:
        assert client.post("/v1/keys/nope/revoke", headers=admin(client)).json() == {
            "revoked": False
        }

    def test_a_body_that_is_not_json_is_400(self, client: TestClient) -> None:
        resp = client.post(
            "/v1/keys",
            content=b"{{{",
            headers={**admin(client), "Content-Type": "application/json"},
        )
        assert resp.status_code == 400


class TestScopeEnforcement:
    """A leaked writer key must not become a leaked audit trail."""

    @pytest.fixture
    def writer(self, client: TestClient) -> dict[str, str]:
        return {"Authorization": f"Bearer {seed(client, 'user-waxseal', 'writer')}"}

    @pytest.fixture
    def viewer(self, client: TestClient) -> dict[str, str]:
        return {"Authorization": f"Bearer {seed(client, 'looker', 'viewer')}"}

    @pytest.fixture
    def auditor(self, client: TestClient) -> dict[str, str]:
        return {"Authorization": f"Bearer {seed(client, 'checker', 'auditor')}"}

    def test_a_writer_may_read_the_head(self, client: TestClient, writer: Any) -> None:
        # 404 is "chain empty", which means the guard let it through.
        assert client.get("/v1/chains/default/head", headers=writer).status_code == 404

    def test_a_writer_may_not_read_the_entries(
        self, client: TestClient, writer: Any
    ) -> None:
        resp = client.get("/v1/chains/default/entries", headers=writer)
        assert resp.status_code == 403
        assert "trails:read" in resp.json()["detail"]

    def test_a_writer_may_not_run_verify(self, client: TestClient, writer: Any) -> None:
        assert client.get("/v1/chains/default/verify", headers=writer).status_code == 403

    def test_a_writer_may_not_manage_keys(self, client: TestClient, writer: Any) -> None:
        assert client.get("/v1/keys", headers=writer).status_code == 403
        assert client.get("/v1/operators", headers=writer).status_code == 403

    def test_a_writer_may_not_import(self, client: TestClient, writer: Any) -> None:
        resp = client.post(
            "/v1/imports", files={"file": ("t.jsonl", b"x", "text/plain")}, headers=writer
        )
        assert resp.status_code == 403

    def test_a_viewer_may_read_but_not_append(
        self, client: TestClient, viewer: Any, envelopes: list[dict[str, Any]]
    ) -> None:
        assert client.get("/v1/chains/default/entries", headers=viewer).status_code == 404
        resp = client.post("/v1/chains/default/entries", json=envelopes[0], headers=viewer)
        assert resp.status_code == 403
        assert "entries:append" in resp.json()["detail"]

    def test_a_viewer_may_not_run_verify(self, client: TestClient, viewer: Any) -> None:
        assert client.get("/v1/chains/default/verify", headers=viewer).status_code == 403

    def test_an_auditor_may_verify_and_export_but_not_append(
        self, client: TestClient, auditor: Any, envelopes: list[dict[str, Any]]
    ) -> None:
        assert client.get("/v1/chains/default/verify", headers=auditor).status_code == 200
        assert (
            client.get("/v1/chains/default/export-proof/0", headers=auditor).status_code == 200
        )
        resp = client.post("/v1/chains/default/entries", json=envelopes[0], headers=auditor)
        assert resp.status_code == 403

    def test_an_auditor_may_not_manage_keys(self, client: TestClient, auditor: Any) -> None:
        assert client.get("/v1/keys", headers=auditor).status_code == 403

    def test_a_writer_can_actually_append(
        self, client: TestClient, writer: Any, envelopes: list[dict[str, Any]]
    ) -> None:
        # The permission model has to permit the thing it exists to permit.
        resp = client.post("/v1/chains/default/entries", json=envelopes[0], headers=writer)
        assert resp.status_code == 201

    def test_an_unknown_token_is_401_not_403(self, client: TestClient) -> None:
        # 403 would confirm the token exists and is merely under-scoped.
        resp = client.get("/v1/keys", headers={"Authorization": "Bearer wxs_live_nope"})
        assert resp.status_code == 401

    def test_the_public_surface_still_needs_nothing(self, client: TestClient) -> None:
        assert client.get("/public/v1/chains").status_code == 200
        assert client.get("/public/v1/scope").status_code == 200


class TestWitnessAuthorityStaysSeparate:
    def test_an_operator_key_does_not_open_the_witness(self, tmp_path: Path) -> None:
        # REMOTE.md section 8: a witness is a different administrative
        # authority. An admin key of THIS server must not be one of its keys.
        store = InMemoryOperatorStore()
        settings = Settings(
            data_dir=tmp_path / "d", api_key=BOOTSTRAP, witness_api_key="witness-key"
        )
        client = TestClient(create_app(settings, operators=store))
        key = seed(client, "admin", "admin")
        resp = client.post(
            "/v1/witness/w1",
            json={"seq": 1, "entry_hash": "aa" * 32, "root": "bb" * 32},
            headers={"Authorization": f"Bearer {key}"},
        )
        assert resp.status_code == 401


class TestKeyAdministrationIsAdminOnly:
    """The write half of key management, not just the listing.

    A credential that could mint itself a wider one would make every other
    scope check decorative.
    """

    @pytest.fixture
    def writer(self, client: TestClient) -> dict[str, str]:
        return {"Authorization": f"Bearer {seed(client, 'user-waxseal', 'writer')}"}

    def test_a_writer_may_not_create_an_operator(
        self, client: TestClient, writer: Any
    ) -> None:
        resp = client.post(
            "/v1/operators",
            json={"username": "sneaky", "display_name": "s", "role": "admin"},
            headers=writer,
        )
        assert resp.status_code == 403
        assert client.get("/v1/operators", headers=admin(client)).json()["operators"] == [
            o for o in client.get("/v1/operators", headers=admin(client)).json()["operators"]
            if o["username"] != "sneaky"
        ]

    def test_a_writer_may_not_mint_itself_a_wider_key(
        self, client: TestClient, writer: Any
    ) -> None:
        resp = client.post(
            "/v1/keys", json={"username": "user-waxseal", "label": "wider"}, headers=writer
        )
        assert resp.status_code == 403

    def test_a_writer_may_not_revoke_a_key(self, client: TestClient, writer: Any) -> None:
        key_id = client.get("/v1/keys", headers=admin(client)).json()["keys"][0]["key_id"]
        assert client.post(f"/v1/keys/{key_id}/revoke", headers=writer).status_code == 403


class TestCorrectingAnOperator:
    """A typo in an email is the ordinary case.

    Without this route the only fix is editing the database by hand, which is
    how a product teaches its operators to bypass it.
    """

    def test_an_email_can_be_corrected(self, client: TestClient) -> None:
        client.post(
            "/v1/operators",
            json={
                "username": "admin",
                "display_name": "Admin",
                "email": "wrong@example.test",
                "role": "admin",
            },
            headers=admin(client),
        )
        fixed = client.patch(
            "/v1/operators/admin",
            json={"email": "right@example.test"},
            headers=admin(client),
        )
        assert fixed.status_code == 200
        assert fixed.json()["email"] == "right@example.test"

    def test_omitting_a_field_leaves_it_alone(self, client: TestClient) -> None:
        seed(client, "admin", "admin")
        client.patch(
            "/v1/operators/admin", json={"email": "a@b.c"}, headers=admin(client)
        )
        after = client.patch(
            "/v1/operators/admin", json={"display_name": "Renamed"}, headers=admin(client)
        ).json()
        assert after["display_name"] == "Renamed"
        assert after["email"] == "a@b.c"

    def test_an_explicit_null_email_clears_it(self, client: TestClient) -> None:
        # "leave it alone" and "remove it" are different instructions and must
        # not share a value.
        seed(client, "ci", "writer")
        client.patch("/v1/operators/ci", json={"email": "x@y.z"}, headers=admin(client))
        after = client.patch(
            "/v1/operators/ci", json={"email": None}, headers=admin(client)
        ).json()
        assert after["email"] is None

    def test_a_role_change_changes_the_scopes(self, client: TestClient) -> None:
        seed(client, "x", "viewer")
        after = client.patch(
            "/v1/operators/x", json={"role": "auditor"}, headers=admin(client)
        ).json()
        assert after["role"] == "auditor"
        assert "verify:run" in after["scopes"]

    def test_deactivating_stops_the_operators_keys_working(
        self, client: TestClient
    ) -> None:
        key = seed(client, "x", "admin")
        client.patch("/v1/operators/x", json={"active": False}, headers=admin(client))
        assert (
            client.get("/v1/whoami", headers={"Authorization": f"Bearer {key}"}).status_code
            == 401
        )

    def test_reactivating_restores_them(self, client: TestClient) -> None:
        key = seed(client, "x", "admin")
        client.patch("/v1/operators/x", json={"active": False}, headers=admin(client))
        client.patch("/v1/operators/x", json={"active": True}, headers=admin(client))
        assert (
            client.get("/v1/whoami", headers={"Authorization": f"Bearer {key}"}).status_code
            == 200
        )

    def test_an_unknown_operator_is_404(self, client: TestClient) -> None:
        resp = client.patch(
            "/v1/operators/ghost", json={"email": "x@y.z"}, headers=admin(client)
        )
        assert resp.status_code == 404

    def test_an_unknown_role_is_400(self, client: TestClient) -> None:
        seed(client, "x", "viewer")
        resp = client.patch(
            "/v1/operators/x", json={"role": "superuser"}, headers=admin(client)
        )
        assert resp.status_code == 400

    def test_a_non_boolean_active_is_400(self, client: TestClient) -> None:
        seed(client, "x", "viewer")
        resp = client.patch(
            "/v1/operators/x", json={"active": "yes"}, headers=admin(client)
        )
        assert resp.status_code == 400

    def test_a_malformed_body_is_400(self, client: TestClient) -> None:
        seed(client, "x", "viewer")
        resp = client.patch(
            "/v1/operators/x",
            content=b"{{{",
            headers={**admin(client), "Content-Type": "application/json"},
        )
        assert resp.status_code == 400

    def test_a_writer_may_not_correct_an_operator(self, client: TestClient) -> None:
        writer_key = seed(client, "user-waxseal", "writer")
        resp = client.patch(
            "/v1/operators/user-waxseal",
            json={"role": "admin"},
            headers={"Authorization": f"Bearer {writer_key}"},
        )
        assert resp.status_code == 403
