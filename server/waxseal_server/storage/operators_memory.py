"""In-memory `OperatorStore`, for the fast test path and for a dev run.

Held to the same contract as the Postgres adapter, which is what makes it a
stand-in rather than a convenient fiction. It is NOT a deployment option: it
forgets every operator and every key on restart, and `create_app` says so if it
is ever wired in.
"""

from __future__ import annotations

from dataclasses import replace

from waxseal_server.domain.clock import utc_now
from waxseal_server.domain.errors import NoSuchOperator, OperatorExists
from waxseal_server.domain.operators import (
    ApiKey,
    Operator,
    Principal,
    Role,
    hash_key,
    key_fingerprint,
    mint_key,
    new_key_id,
    require_username,
)


class InMemoryOperatorStore:
    def __init__(self) -> None:
        self._operators: dict[str, Operator] = {}
        self._keys: dict[str, ApiKey] = {}
        # fingerprint of the secret -> key_id. Lookup is by hash, so the
        # plaintext is never held anywhere, even in a test double.
        self._by_hash: dict[str, str] = {}
        self._order: list[str] = []

    def create_operator(
        self, *, username: str, display_name: str, email: str | None, role: Role
    ) -> Operator:
        require_username(username)
        if username in self._operators:
            raise OperatorExists(f"operator {username!r} already exists")
        operator = Operator(
            username=username,
            display_name=display_name,
            email=email,
            role=role,
            created_at=utc_now(),
        )
        self._operators[username] = operator
        return operator

    def update_operator(
        self,
        username: str,
        *,
        display_name: str | None = None,
        email: str | None = None,
        clear_email: bool = False,
        role: Role | None = None,
        active: bool | None = None,
    ) -> Operator:
        current = self._operators.get(username)
        if current is None:
            raise NoSuchOperator(f"no operator {username!r}")
        updated = replace(
            current,
            display_name=current.display_name if display_name is None else display_name,
            email=None if clear_email else (current.email if email is None else email),
            role=current.role if role is None else role,
            active=current.active if active is None else active,
        )
        self._operators[username] = updated
        return updated

    def get_operator(self, username: str) -> Operator | None:
        return self._operators.get(username)

    def operators(self) -> list[Operator]:
        return list(self._operators.values())

    def mint_key(self, *, username: str, label: str) -> tuple[str, ApiKey]:
        if username not in self._operators:
            raise NoSuchOperator(f"no operator {username!r}")
        plaintext, fingerprint_hash = mint_key()
        record = ApiKey(
            key_id=new_key_id(),
            username=username,
            label=label,
            fingerprint=key_fingerprint(plaintext),
            created_at=utc_now(),
        )
        self._keys[record.key_id] = record
        self._by_hash[fingerprint_hash] = record.key_id
        self._order.append(record.key_id)
        return plaintext, record

    def keys(self, username: str | None = None) -> list[ApiKey]:
        newest_first = [self._keys[key_id] for key_id in reversed(self._order)]
        if username is None:
            return newest_first
        return [key for key in newest_first if key.username == username]

    def revoke_key(self, key_id: str) -> bool:
        record = self._keys.get(key_id)
        if record is None or not record.active:
            return False
        self._keys[key_id] = replace(record, revoked_at=utc_now())
        return True

    def has_active_key(self) -> bool:
        return any(key.active for key in self._keys.values())

    def authenticate(self, plaintext: str) -> Principal | None:
        key_id = self._by_hash.get(hash_key(plaintext)) if plaintext else None
        if key_id is None:
            return None
        record = self._keys[key_id]
        operator = self._operators.get(record.username)
        # One None for every failure — unknown, revoked, deactivated — so a
        # caller cannot learn which of them a guessed key hit.
        if not record.active or operator is None or not operator.active:
            return None
        self._keys[key_id] = replace(record, last_used_at=utc_now())
        return Principal(operator=operator, key_id=key_id, scopes=operator.scopes)
