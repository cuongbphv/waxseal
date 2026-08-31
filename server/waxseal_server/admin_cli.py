"""`waxseal-server-admin` — seed operators and mint keys.

Runs against the same store the server uses, so `docker compose exec` is the
whole deployment story for creating the first admin. Configuration comes from
the environment, never from a flag: a key or a DSN in argv is visible in a
process listing (REMOTE.md section 5's reason, applied to this side too).

Every command is idempotent where it can be. `operator add` on an existing name
reports that it already exists and exits 0, so re-running a seed script during a
deploy is safe. Minting is NOT idempotent and must not be: a second `key mint`
is a second credential, and pretending otherwise would silently hand out one key
where the operator asked for two.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Mapping, Sequence
from typing import Any, Final

from waxseal_server.app import build_operator_store
from waxseal_server.config import Settings
from waxseal_server.domain.errors import InvalidIdentifier, NoSuchOperator, OperatorExists
from waxseal_server.domain.operators import Role
from waxseal_server.ports.operators import OperatorStore

EXIT_OK: Final = 0
EXIT_USAGE: Final = 2
EXIT_FAILED: Final = 1

#: The two accounts a dogfood deployment needs: a human administrator and the
#: machine account the Claude Code hook writes with. The writer deliberately
#: cannot read the trail it appends to.
DEFAULT_SEED: Final[tuple[tuple[str, Role, str], ...]] = (
    ("admin", Role.ADMIN, "Administrator"),
    ("user-waxseal", Role.WRITER, "waxseal dogfood writer"),
)


def _store(env: Mapping[str, str]) -> OperatorStore:
    return build_operator_store(Settings.from_env(env))


def _emit(out: Any, payload: dict[str, Any]) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True), file=out)


def _add_operator(
    store: OperatorStore, *, username: str, role: Role, display_name: str, email: str | None
) -> tuple[str, dict[str, Any]]:
    """Create, or reconcile an existing operator with what was asked for.

    Idempotent on purpose: a deploy script re-running must not fail. But
    "already exists" is the wrong answer when the seed carries a corrected
    email — leaving the old one would mean the only way to fix a typo is
    editing the database by hand. So a differing email is applied and the
    outcome says `updated`, which is the difference between idempotent and
    inert.
    """
    try:
        operator = store.create_operator(
            username=username, display_name=display_name, email=email, role=role
        )
    except OperatorExists:
        existing = store.get_operator(username)
        assert existing is not None  # noqa: S101 - OperatorExists proved it
        if email is not None and email != existing.email:
            existing = store.update_operator(username, email=email)
            return "updated", {
                "username": existing.username,
                "role": existing.role.value,
                "email": existing.email,
            }
        return "exists", {
            "username": existing.username,
            "role": existing.role.value,
            "email": existing.email,
        }
    return "created", {
        "username": operator.username,
        "role": operator.role.value,
        "email": operator.email,
    }


def main(
    argv: Sequence[str] | None = None,
    *,
    env: Mapping[str, str] | None = None,
    store: OperatorStore | None = None,
) -> int:
    """`store` is injectable for the same reason `run` is in `__main__.py`:
    a test needs to drive several subcommands against one store, and a process
    boundary is not a thing a test should have to stand up to do that."""
    source = os.environ if env is None else env
    parser = argparse.ArgumentParser(
        prog="waxseal-server-admin",
        description="Seed operators and mint API keys for a waxseal server.",
        epilog="Configuration comes from the environment: "
        "WAXSEAL_SERVER_DATABASE_URL, WAXSEAL_SERVER_DATA_DIR.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_seed = sub.add_parser("seed", help="create the standard operators, idempotently")
    p_seed.add_argument("--email", default=None, help="email for the admin operator")

    p_add = sub.add_parser("operator-add", help="create one operator")
    p_add.add_argument("--username", required=True)
    p_add.add_argument("--role", required=True, choices=[r.value for r in Role])
    p_add.add_argument("--display-name", default=None)
    p_add.add_argument("--email", default=None)

    p_update = sub.add_parser("operator-update", help="correct an operator")
    p_update.add_argument("--username", required=True)
    p_update.add_argument("--display-name", default=None)
    p_update.add_argument("--email", default=None)
    p_update.add_argument(
        "--clear-email",
        action="store_true",
        help="remove the email — distinct from omitting --email, which leaves it alone",
    )
    p_update.add_argument("--role", default=None, choices=[r.value for r in Role])
    activity = p_update.add_mutually_exclusive_group()
    activity.add_argument("--deactivate", action="store_true")
    activity.add_argument("--activate", action="store_true")

    sub.add_parser("operator-list", help="list operators")

    p_mint = sub.add_parser("key-mint", help="mint an API key (printed once)")
    p_mint.add_argument("--username", required=True)
    p_mint.add_argument("--label", default="unnamed")

    p_keys = sub.add_parser("key-list", help="list API key records (never the secrets)")
    p_keys.add_argument("--username", default=None)

    p_revoke = sub.add_parser("key-revoke", help="revoke an API key")
    p_revoke.add_argument("--key-id", required=True)

    args = parser.parse_args(argv)
    if store is None:
        store = _store(source)

    if args.command == "seed":
        results = []
        for username, role, display_name in DEFAULT_SEED:
            email = args.email if username == "admin" else None
            outcome, record = _add_operator(
                store,
                username=username,
                role=role,
                display_name=display_name,
                email=email,
            )
            results.append({"outcome": outcome, **record})
        _emit(sys.stdout, {"seeded": results})
        return EXIT_OK

    if args.command == "operator-add":
        try:
            outcome, record = _add_operator(
                store,
                username=args.username,
                role=Role(args.role),
                display_name=args.display_name or args.username,
                email=args.email,
            )
        except InvalidIdentifier as exc:
            print(f"waxseal-server-admin: {exc}", file=sys.stderr)
            return EXIT_USAGE
        _emit(sys.stdout, {"outcome": outcome, **record})
        return EXIT_OK

    if args.command == "operator-update":
        active = True if args.activate else (False if args.deactivate else None)
        try:
            operator = store.update_operator(
                args.username,
                display_name=args.display_name,
                email=args.email,
                clear_email=args.clear_email,
                role=Role(args.role) if args.role else None,
                active=active,
            )
        except NoSuchOperator as exc:
            print(f"waxseal-server-admin: {exc}", file=sys.stderr)
            return EXIT_FAILED
        _emit(
            sys.stdout,
            {
                "username": operator.username,
                "display_name": operator.display_name,
                "email": operator.email,
                "role": operator.role.value,
                "active": operator.active,
            },
        )
        return EXIT_OK

    if args.command == "operator-list":
        _emit(
            sys.stdout,
            {
                "operators": [
                    {
                        "username": o.username,
                        "display_name": o.display_name,
                        "email": o.email,
                        "role": o.role.value,
                        "active": o.active,
                        "created_at": o.created_at,
                    }
                    for o in store.operators()
                ]
            },
        )
        return EXIT_OK

    if args.command == "key-mint":
        try:
            plaintext, minted = store.mint_key(username=args.username, label=args.label)
        except NoSuchOperator as exc:
            print(f"waxseal-server-admin: {exc}", file=sys.stderr)
            return EXIT_FAILED
        _emit(
            sys.stdout,
            {
                "key_id": minted.key_id,
                "username": minted.username,
                "label": minted.label,
                # Printed here and nowhere else, ever again.
                "key": plaintext,
                "notice": "copy this now; the server stores only its SHA-256",
            },
        )
        return EXIT_OK

    if args.command == "key-list":
        _emit(
            sys.stdout,
            {
                "keys": [
                    {
                        "key_id": k.key_id,
                        "username": k.username,
                        "label": k.label,
                        "fingerprint": k.fingerprint,
                        "created_at": k.created_at,
                        "last_used_at": k.last_used_at,
                        "revoked_at": k.revoked_at,
                        "active": k.active,
                    }
                    for k in store.keys(args.username)
                ]
            },
        )
        return EXIT_OK

    # key-revoke: `revoked` says what THIS call did, so a retry is honest.
    _emit(sys.stdout, {"key_id": args.key_id, "revoked": store.revoke_key(args.key_id)})
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover - exercised as a subprocess
    sys.exit(main())
