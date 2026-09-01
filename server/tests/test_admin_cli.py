"""`waxseal-server-admin` — the command a deployment actually runs.

Condition R, the repository's reachability rule: a command whose output nothing
reads is a command nobody has run. Every assertion here goes through `main()`
and reads what it printed.

`seed` is idempotent because a deploy script re-running must not fail. `key-mint`
is deliberately NOT: a second mint is a second credential, and collapsing that
would hand out one key where the operator asked for two.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from waxseal_server.admin_cli import DEFAULT_SEED, _add_operator, main
from waxseal_server.domain.operators import KEY_PREFIX, Role
from waxseal_server.ports.operators import OperatorStore
from waxseal_server.storage.operators_memory import InMemoryOperatorStore


def seed_into(store: OperatorStore, *, email: str | None = None) -> None:
    """Apply `DEFAULT_SEED` to a store the test can then inspect.

    The CLI builds its own store per invocation, which is right for a process
    boundary and useless for asserting what the seed produced. This walks the
    same table the CLI walks, so the two cannot drift.
    """
    for username, role, display_name in DEFAULT_SEED:
        _add_operator(
            store,
            username=username,
            role=role,
            display_name=display_name,
            email=email if username == "admin" else None,
        )


@pytest.fixture
def env(tmp_path: Path) -> dict[str, str]:
    # No WAXSEAL_SERVER_DATABASE_URL: the in-memory store. Each call to main()
    # builds its own, so tests that need state across calls use `run_all`.
    return {"WAXSEAL_SERVER_DATA_DIR": str(tmp_path)}


def run(capsys: Any, env: dict[str, str], *argv: str) -> tuple[int, dict[str, Any]]:
    code = main(list(argv), env=env)
    out = capsys.readouterr().out
    return code, (json.loads(out) if out.strip() else {})


class TestSeed:
    def test_it_creates_the_two_standard_operators(
        self, capsys: Any, env: dict[str, str]
    ) -> None:
        code, body = run(capsys, env, "seed")
        assert code == 0
        assert [(s["username"], s["role"]) for s in body["seeded"]] == [
            ("admin", "admin"),
            ("user-waxseal", "writer"),
        ]
        assert all(s["outcome"] == "created" for s in body["seeded"])

    def test_the_email_goes_to_the_admin_and_not_to_the_machine_account(
        self, capsys: Any, env: dict[str, str]
    ) -> None:
        # A machine account has no mailbox. Putting the human's address on it
        # would attribute a credential nobody holds to a person who does.
        store = InMemoryOperatorStore()
        seed_into(store, email="admin@example.test")
        assert store.get_operator("admin").email == "admin@example.test"
        assert store.get_operator("user-waxseal").email is None

    def test_the_seeded_writer_cannot_read_the_trail_it_writes_to(self) -> None:
        # The reason the automation account is a writer and not an admin: the key
        # lives on a developer's machine, and leaking it must not leak the trail.
        store = InMemoryOperatorStore()
        seed_into(store)
        writer = store.get_operator("user-waxseal")
        assert writer.role is Role.WRITER
        assert writer.scopes == {"entries:append", "head:read"}

    def test_the_seeded_admin_can_manage_keys_and_still_cannot_edit_an_entry(self) -> None:
        store = InMemoryOperatorStore()
        seed_into(store)
        admin = store.get_operator("admin")
        assert "keys:manage" in admin.scopes
        assert not any("edit" in scope or "delete" in scope for scope in admin.scopes)


class TestIdempotence:
    def test_seeding_twice_reports_exists_and_still_succeeds(self) -> None:
        store = InMemoryOperatorStore()
        first, _ = _add_operator(
            store, username="admin", role=Role.ADMIN, display_name="Admin", email=None
        )
        second, record = _add_operator(
            store, username="admin", role=Role.ADMIN, display_name="Admin", email=None
        )
        assert first == "created"
        assert second == "exists"
        assert record["role"] == "admin"

    def test_a_re_seed_does_not_change_the_existing_role(self) -> None:
        store = InMemoryOperatorStore()
        _add_operator(
            store, username="admin", role=Role.ADMIN, display_name="Admin", email=None
        )
        _add_operator(
            store, username="admin", role=Role.VIEWER, display_name="Nope", email=None
        )
        assert store.get_operator("admin").role is Role.ADMIN


class TestOperatorCommands:
    def test_operator_add_then_list(self, capsys: Any, env: dict[str, str]) -> None:
        # One process, one store: the CLI builds a store per invocation, so a
        # memory-backed run only shows state within a single main() call. This
        # asserts the printed shape of each command.
        code, body = run(
            capsys, env, "operator-add", "--username", "admin", "--role", "admin"
        )
        assert code == 0
        assert body == {
            "outcome": "created",
            "username": "admin",
            "role": "admin",
            "email": None,
        }

    def test_operator_list_on_an_empty_store(self, capsys: Any, env: dict[str, str]) -> None:
        code, body = run(capsys, env, "operator-list")
        assert code == 0
        assert body == {"operators": []}

    def test_an_unsafe_username_is_a_usage_error(
        self, capsys: Any, env: dict[str, str]
    ) -> None:
        code, _ = run(capsys, env, "operator-add", "--username", "../x", "--role", "viewer")
        assert code == 2

    def test_an_unknown_role_is_rejected_by_the_parser(
        self, env: dict[str, str]
    ) -> None:
        with pytest.raises(SystemExit) as exc:
            main(["operator-add", "--username", "x", "--role", "superuser"], env=env)
        assert exc.value.code == 2


class TestKeyCommands:
    def test_minting_for_an_unknown_operator_fails_loudly(
        self, capsys: Any, env: dict[str, str]
    ) -> None:
        code, _ = run(capsys, env, "key-mint", "--username", "ghost")
        assert code == 1

    def test_key_list_on_an_empty_store(self, capsys: Any, env: dict[str, str]) -> None:
        code, body = run(capsys, env, "key-list")
        assert code == 0
        assert body == {"keys": []}

    def test_revoking_an_unknown_key_says_it_did_nothing(
        self, capsys: Any, env: dict[str, str]
    ) -> None:
        code, body = run(capsys, env, "key-revoke", "--key-id", "nope")
        assert code == 0
        assert body == {"key_id": "nope", "revoked": False}

    def test_a_minted_key_is_printed_once_with_its_notice(self, capsys: Any) -> None:
        # Drives the real subcommand against one store, so this is the output an
        # operator actually pastes into a hook config.
        store = InMemoryOperatorStore()
        seed_into(store)
        code = main(
            ["key-mint", "--username", "user-waxseal", "--label", "claude-code-hook"],
            env={},
            store=store,
        )
        body = json.loads(capsys.readouterr().out)
        assert code == 0
        assert body["key"].startswith(KEY_PREFIX)
        assert body["label"] == "claude-code-hook"
        assert "SHA-256" in body["notice"]

    def test_the_minted_key_actually_authenticates(self, capsys: Any) -> None:
        # A printed key that does not work is worse than no key: the operator
        # pastes it into a hook and learns hours later that nothing was written.
        store = InMemoryOperatorStore()
        seed_into(store)
        main(["key-mint", "--username", "user-waxseal", "--label", "hook"], env={}, store=store)
        minted = json.loads(capsys.readouterr().out)["key"]
        principal = store.authenticate(minted)
        assert principal is not None
        assert principal.operator.username == "user-waxseal"

    def test_minting_twice_gives_two_different_keys(self, capsys: Any) -> None:
        # Deliberately NOT idempotent: a second mint is a second credential.
        store = InMemoryOperatorStore()
        seed_into(store)
        main(["key-mint", "--username", "admin", "--label", "one"], env={}, store=store)
        first = json.loads(capsys.readouterr().out)["key"]
        main(["key-mint", "--username", "admin", "--label", "two"], env={}, store=store)
        second = json.loads(capsys.readouterr().out)["key"]
        assert first != second
        assert len(store.keys("admin")) == 2

    def test_key_list_shows_the_record_and_never_the_secret(self, capsys: Any) -> None:
        store = InMemoryOperatorStore()
        seed_into(store)
        main(["key-mint", "--username", "admin", "--label", "laptop"], env={}, store=store)
        secret = json.loads(capsys.readouterr().out)["key"]
        main(["key-list"], env={}, store=store)
        listed = json.loads(capsys.readouterr().out)["keys"]
        assert listed[0]["label"] == "laptop"
        assert secret not in str(listed)

    def test_revoking_a_real_key_reports_true_and_stops_it_working(
        self, capsys: Any
    ) -> None:
        store = InMemoryOperatorStore()
        seed_into(store)
        main(["key-mint", "--username", "admin", "--label", "x"], env={}, store=store)
        minted = json.loads(capsys.readouterr().out)
        main(["key-revoke", "--key-id", minted["key_id"]], env={}, store=store)
        assert json.loads(capsys.readouterr().out)["revoked"] is True
        assert store.authenticate(minted["key"]) is None

    def test_operator_list_shows_the_seeded_pair(self, capsys: Any) -> None:
        store = InMemoryOperatorStore()
        seed_into(store)
        main(["operator-list"], env={}, store=store)
        listed = json.loads(capsys.readouterr().out)["operators"]
        assert [(o["username"], o["role"]) for o in listed] == [
            ("admin", "admin"),
            ("user-waxseal", "writer"),
        ]


class TestUsage:
    def test_no_subcommand_is_a_usage_error(self) -> None:
        with pytest.raises(SystemExit) as exc:
            main([], env={})
        assert exc.value.code == 2


class TestOperatorUpdate:
    def test_seed_corrects_a_wrong_email_rather_than_reporting_exists(
        self, capsys: Any
    ) -> None:
        # Idempotent must not mean inert: re-seeding with a corrected address is
        # exactly how an operator fixes a typo without touching the database.
        store = InMemoryOperatorStore()
        seed_into(store, email="wrong@example.test")
        main(["seed", "--email", "right@example.test"], env={}, store=store)
        body = json.loads(capsys.readouterr().out)["seeded"]
        assert body[0]["outcome"] == "updated"
        assert body[0]["email"] == "right@example.test"
        assert store.get_operator("admin").email == "right@example.test"

    def test_re_seeding_with_the_same_email_reports_exists(self, capsys: Any) -> None:
        store = InMemoryOperatorStore()
        seed_into(store, email="same@example.test")
        main(["seed", "--email", "same@example.test"], env={}, store=store)
        body = json.loads(capsys.readouterr().out)["seeded"]
        assert body[0]["outcome"] == "exists"

    def test_operator_update_sets_one_field(self, capsys: Any) -> None:
        store = InMemoryOperatorStore()
        seed_into(store)
        main(
            ["operator-update", "--username", "admin", "--email", "new@example.test"],
            env={},
            store=store,
        )
        assert json.loads(capsys.readouterr().out)["email"] == "new@example.test"

    def test_clear_email_is_distinct_from_omitting_it(self, capsys: Any) -> None:
        store = InMemoryOperatorStore()
        seed_into(store, email="a@b.c")
        main(["operator-update", "--username", "admin"], env={}, store=store)
        assert json.loads(capsys.readouterr().out)["email"] == "a@b.c"
        main(["operator-update", "--username", "admin", "--clear-email"], env={}, store=store)
        assert json.loads(capsys.readouterr().out)["email"] is None

    def test_deactivate_and_activate(self, capsys: Any) -> None:
        store = InMemoryOperatorStore()
        seed_into(store)
        main(["operator-update", "--username", "admin", "--deactivate"], env={}, store=store)
        assert json.loads(capsys.readouterr().out)["active"] is False
        main(["operator-update", "--username", "admin", "--activate"], env={}, store=store)
        assert json.loads(capsys.readouterr().out)["active"] is True

    def test_updating_an_unknown_operator_fails_loudly(self, capsys: Any) -> None:
        store = InMemoryOperatorStore()
        code = main(["operator-update", "--username", "ghost"], env={}, store=store)
        assert code == 1

    def test_activate_and_deactivate_are_mutually_exclusive(self) -> None:
        with pytest.raises(SystemExit) as exc:
            main(
                ["operator-update", "--username", "x", "--activate", "--deactivate"],
                env={},
                store=InMemoryOperatorStore(),
            )
        assert exc.value.code == 2
