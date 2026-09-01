"""In-memory `SettingsStore`, for the fast test path and a dev run.

Held to the same contract as the Postgres adapter. It forgets everything on
restart, which for settings means the deployment silently reverts to defaults —
so `/v1/settings` reports which backend is in use rather than leaving an
operator to wonder where their ledger endpoint went.
"""

from __future__ import annotations

from waxseal_server.domain.settings import require_value, spec_for


class InMemorySettingsStore:
    def __init__(self) -> None:
        self._values: dict[str, str] = {}

    def get(self, key: str) -> str | None:
        # `spec_for` first: an unknown or environment-only key must raise rather
        # than answer None, which would imply the setting could live here.
        spec_for(key)
        return self._values.get(key)

    def all(self) -> dict[str, str]:
        return dict(self._values)

    def set(self, key: str, value: str) -> str:
        # Validated BEFORE the assignment, so a refused write cannot leave the
        # previous value replaced by a bad one.
        checked = require_value(key, value)
        self._values[key] = checked
        return checked

    def unset(self, key: str) -> bool:
        spec_for(key)
        return self._values.pop(key, None) is not None
