"""Server settings an operator may change, and the ones they may not.

Two rules shape this module, and both are refusals.

**A setting is either in the registry or it does not exist.** This is not a
free-form key-value store. A store that accepted any key would accept a typo,
and a typo that saves cleanly looks exactly like a change that took effect —
the operator would then be reading a setting nothing consults. `Role` is parsed
the same way, for the same reason.

**No credential is storable.** `WAXSEAL_API_KEY` and `WAXSEAL_WITNESS_API_KEY`
stay environment-only (REMOTE.md section 5, and the CLI contract in CLAUDE.md).
Putting them here would defeat three separate things: the operator store keeps
only a key's SHA-256 precisely so a database cannot leak a live credential; the
witness key belongs to a DIFFERENT administrative authority and a shared
settings table would put both under one editor; and a credential editable from
the console it authenticates is a credential that can lock the console out of
itself, or be widened by whoever already holds it. `database_url` cannot live in
the database it names, and `data_dir` is held open by the running process.

`FORBIDDEN` names them explicitly rather than leaving them merely absent. An
absent setting looks like an oversight and invites a helpful addition; a named
refusal with a reason does not.
"""

from __future__ import annotations

import enum
import re
from dataclasses import dataclass
from typing import Final

from waxseal_server.domain.errors import InvalidIdentifier, NoSuchSetting

#: Settings that are environment-only, and why. Read by the API so the screen
#: can show the refusal beside the value rather than silently omitting it.
FORBIDDEN: Final[dict[str, str]] = {
    "api_key": "credential_env_only",
    "witness_api_key": "credential_env_only",
    "database_url": "cannot_live_in_the_database_it_names",
    "data_dir": "held_open_by_the_running_process",
}


class SettingKind(enum.Enum):
    """How a value is validated. Not a display hint — the store enforces it."""

    COUNT = "count"
    TEXT = "text"
    #: Two or more http(s) endpoints, comma separated. Not a single URL, and the
    #: plural is load-bearing: `adapters/evm.py` refuses one endpoint because it
    #: cannot disagree with itself, which is exactly the eclipse an operator
    #: relying on one voice would be blind to. A setting that accepted one would
    #: let this server ask for a cross-check it cannot perform.
    URL_LIST = "url_list"
    #: An EVM contract address: `0x` and 40 hex characters.
    ADDRESS = "address"


#: `https?` only. A settings row is fetched by the server itself, so a `file://`
#: or `gopher://` endpoint would turn an operator-supplied string into a read of
#: the server's own filesystem.
_URL_RE: Final = re.compile(r"^https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{1,2000}$")
_ADDRESS_RE: Final = re.compile(r"^0x[0-9a-fA-F]{40}$")
_TEXT_RE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

_COUNT_MAX: Final = 10_000

#: `adapters/evm.py`'s floor, restated here so the setting cannot be saved in a
#: state the command would then refuse.
MIN_RPC_ENDPOINTS: Final = 2


@dataclass(frozen=True, slots=True)
class SettingSpec:
    """One knob: its name, how it is checked, and what it means when unset."""

    key: str
    kind: SettingKind
    #: `None` means "not configured", which is a state, never a zero or an empty
    #: string. A screen renders it as unset rather than as a blank value.
    default: str | None = None


#: The whole vocabulary. Adding a setting is an entry here plus its test.
SPECS: Final[tuple[SettingSpec, ...]] = (
    # How many entries a page of `/v1/chains/{id}/entries` carries. Operational,
    # not a secret, and the one existing setting that was a bare constant.
    SettingSpec("page_size", SettingKind.COUNT, "500"),
    # Workstream F's ledger surface. These are the four values `ledger-status`
    # needs and the reason the Ledger screen could only ever say "not
    # configured": there was nowhere to put them.
    SettingSpec("ledger_rpc_urls", SettingKind.URL_LIST),
    #: The one setting that decides whether the ledger surface is configured at
    #: all: `ledger-status` requires it, so with this unset there is no command
    #: to run and the screen says so rather than showing a status nobody read.
    SettingSpec("ledger_liveness_address", SettingKind.ADDRESS),
    SettingSpec("ledger_registry_address", SettingKind.ADDRESS),
    SettingSpec("ledger_bond_address", SettingKind.ADDRESS),
    #: Required BY THE COMMAND whenever a bond address is set. The pairing is
    #: enforced where the argv is built, not here: one setting cannot see the
    #: other's value.
    SettingSpec("ledger_writer_address", SettingKind.ADDRESS),
    SettingSpec("ledger_trail_id", SettingKind.TEXT),
)

BY_KEY: Final[dict[str, SettingSpec]] = {spec.key: spec for spec in SPECS}


def spec_for(key: str) -> SettingSpec:
    """The spec, or a refusal naming why this key is not one.

    A forbidden key gets a different message from an unknown one: "you may not
    store this, and here is why" is a different fact from "no such setting", and
    collapsing them would make the deliberate refusal look like a gap.
    """
    if key in FORBIDDEN:
        raise NoSuchSetting(f"{key!r} is environment-only ({FORBIDDEN[key]}) and cannot be stored")
    spec = BY_KEY.get(key)
    if spec is None:
        raise NoSuchSetting(f"no such setting {key!r}; known: {sorted(BY_KEY)}")
    return spec


def rpc_endpoints(value: str | None) -> list[str]:
    """The endpoint list, split. Empty when unset — never a one-item list."""
    if not value:
        return []
    return [part.strip() for part in value.split(",") if part.strip()]


def require_value(key: str, value: str) -> str:
    """Check one value against its spec, returning it unchanged.

    Never coerced, never trimmed into shape. A value this server quietly
    rewrote would not be the value the operator can see they set.
    """
    spec = spec_for(key)
    if spec.kind is SettingKind.COUNT:
        if not value.isdigit() or value == "0" or int(value) > _COUNT_MAX:
            raise InvalidIdentifier(
                f"{key} must be a whole number from 1 to {_COUNT_MAX}, got {value!r}"
            )
    elif spec.kind is SettingKind.URL_LIST:
        endpoints = [part.strip() for part in value.split(",") if part.strip()]
        if len(endpoints) < MIN_RPC_ENDPOINTS:
            raise InvalidIdentifier(
                f"{key} needs at least {MIN_RPC_ENDPOINTS} comma-separated endpoints; "
                "one endpoint cannot disagree with itself, so a cross-check "
                f"against it is not one. Got {len(endpoints)}"
            )
        for endpoint in endpoints:
            if not _URL_RE.match(endpoint):
                raise InvalidIdentifier(f"{key} entry must be an http(s) URL, got {endpoint!r}")
    elif spec.kind is SettingKind.ADDRESS:
        if not _ADDRESS_RE.match(value):
            raise InvalidIdentifier(
                f"{key} must be 0x followed by 40 hex characters, got {value!r}"
            )
    elif not _TEXT_RE.match(value):
        raise InvalidIdentifier(f"{key} must be a safe name, got {value!r}")
    return value
