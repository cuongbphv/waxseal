"""`SettingsStore`: the server's own operational configuration.

A Protocol for the same reason `OperatorStore` is one — the storage decision
stays a deployment decision, and the in-memory adapter is held to the same
contract test as Postgres so it is a stand-in rather than a convenient fiction.

What this store holds is narrow on purpose. It is not a copy of the process
environment: `data_dir`, `database_url` and both API keys stay where they are
and are never written here (`domain/settings.py` refuses them by name). What it
holds is the operational knobs an operator legitimately changes without a
redeploy — page size, and the ledger endpoint and contract addresses that
`ledger-status` needs.

An unset setting reads as `None`, never as an empty string and never as a zero.
"Not configured" is a state; a screen renders it as unset rather than as a blank
value that looks configured.
"""

from __future__ import annotations

from typing import Protocol


class SettingsStore(Protocol):
    def get(self, key: str) -> str | None:
        """The stored value, or None when nothing was stored for it.

        None means "not stored" and the caller applies the spec's default. It is
        never an empty string: a setting somebody deliberately blanked and a
        setting nobody ever touched are different facts, and only one of them
        should fall back to a default.

        Raises `NoSuchSetting` for a key outside the registry, including the
        environment-only ones — a store that answered None for `api_key` would
        be implying such a setting could exist here.
        """
        ...

    def all(self) -> dict[str, str]:
        """Every stored value, by key. Unset settings are absent, not blank."""
        ...

    def set(self, key: str, value: str) -> str:
        """Store one value and return it. Raises `NoSuchSetting` /
        `InvalidIdentifier` rather than storing something unvalidated.

        Validation happens in the domain, not here, so both adapters cannot
        disagree about what a valid value is.
        """
        ...

    def unset(self, key: str) -> bool:
        """Remove one stored value, reverting it to its default.

        True if this call removed something, False if there was nothing stored —
        so a retry is safe and says what it did, the same shape as
        `OperatorStore.revoke_key`. Distinct from setting an empty string, which
        is refused: "back to default" and "explicitly blank" are different
        instructions and must not share a value.
        """
        ...
