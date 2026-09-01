"""`OperatorStore`: where operators and their API keys live.

A Protocol rather than a class so the storage decision stays a deployment
decision. Two adapters satisfy it: Postgres in production, and an in-memory one
the fast tests run against. Both are held to the same contract test, which is
what makes the in-memory one a real stand-in rather than a convenient fiction.

This is the SERVER's own data. It has nothing to do with the waxseal library or
its CLI: a trail is a file the stock `waxseal verify` can read, and it stays
that way. Putting a trail in a database would make this server the only thing
that could verify it, which is exactly the trust concentration the public read
point exists to avoid.
"""

from __future__ import annotations

from typing import Protocol

from waxseal_server.domain.operators import ApiKey, Operator, Principal, Role


class OperatorStore(Protocol):
    def create_operator(
        self, *, username: str, display_name: str, email: str | None, role: Role
    ) -> Operator:
        """Register an operator. Raises `OperatorExists` if the name is taken.

        Never silently updates: two callers seeding the same name is a
        deployment mistake worth surfacing, not a last-write-wins race over who
        is an admin.
        """
        ...

    def get_operator(self, username: str) -> Operator | None:
        """The operator, or None. None is "no such operator", never a guest."""
        ...

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
        """Correct an operator. Raises `NoSuchOperator` rather than creating one.

        Every field is optional and `None` means "not supplied", so a caller
        fixing a typo cannot blank the other three by omission. Clearing an
        email is therefore its own flag: "leave it alone" and "remove it" are
        different instructions and must not share a value.

        There is no delete. An operator who acted is part of the history, and
        removing the row would orphan every key that names them; deactivating
        revokes their access while leaving that history readable.
        """
        ...

    def operators(self) -> list[Operator]:
        """Every operator, oldest first."""
        ...

    def mint_key(self, *, username: str, label: str) -> tuple[str, ApiKey]:
        """A new key for an operator: `(plaintext, record)`.

        The plaintext is returned HERE and nowhere else, ever again. Raises
        `NoSuchOperator` rather than creating one — a key belonging to nobody is
        a credential with no role, which is worse than no credential.
        """
        ...

    def keys(self, username: str | None = None) -> list[ApiKey]:
        """Key records, newest first. Revoked keys are listed, not hidden: a
        revocation is part of the history an auditor came to read."""
        ...

    def revoke_key(self, key_id: str) -> bool:
        """Revoke a key. True if this call revoked it, False if it was already
        revoked or unknown — so a retry is safe and says what it did."""
        ...

    def has_active_key(self) -> bool:
        """Whether any usable credential exists.

        A server with no key configured anywhere is open, and says so. The
        moment the first key is minted it stops being open — so seeding is what
        secures a deployment, rather than a separate step somebody can forget.
        """
        ...

    def authenticate(self, plaintext: str) -> Principal | None:
        """Resolve a bearer token to who is calling, or None.

        None covers every failure — unknown key, revoked key, deactivated
        operator — on purpose: telling a caller *which* of those it was tells an
        attacker whether a guessed key exists.
        """
        ...
