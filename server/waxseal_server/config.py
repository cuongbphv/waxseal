"""Deployment settings, read from the environment.

Every setting is an environment variable and none is a command-line argument,
for the same reason `WAXSEAL_API_KEY` is (REMOTE.md section 5): an argument is
visible in a process listing.

`Settings` is a frozen dataclass rather than a module of globals so a test can
stand up two servers with different credentials in one process, and so the
wiring in `app.py` has exactly one thing to pass down.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final

DEFAULT_DATA_DIR: Final = Path("/var/lib/waxseal")

#: Where the Vite build lands. Inside the package, so the Docker image carries
#: the UI without a second copy step.
PACKAGED_STATIC_DIR: Final = Path(__file__).resolve().parent / "static"

#: Environment variable names, named once so a rename is one edit and a typo is
#: a NameError rather than a silently unset credential.
ENV_DATA_DIR: Final = "WAXSEAL_SERVER_DATA_DIR"
ENV_API_KEY: Final = "WAXSEAL_API_KEY"
ENV_WITNESS_API_KEY: Final = "WAXSEAL_WITNESS_API_KEY"
ENV_DATABASE_URL: Final = "WAXSEAL_SERVER_DATABASE_URL"

DEFAULT_PAGE_SIZE: Final = 500


@dataclass(frozen=True, slots=True)
class Settings:
    data_dir: Path
    api_key: str | None = None
    witness_api_key: str | None = None
    page_size: int = DEFAULT_PAGE_SIZE
    # Overridable so a test can exercise both the built and unbuilt shapes
    # without moving files around inside the installed package.
    static_dir: Path = PACKAGED_STATIC_DIR
    #: PostgreSQL for the SERVER's own records — operators and their API keys.
    #: Never for trails: a trail stays a file the stock `waxseal verify` reads,
    #: and the library knows nothing about a database. None means the in-memory
    #: operator store, which forgets everything on restart and says so.
    database_url: str | None = None

    @property
    def chains_dir(self) -> Path:
        return self.data_dir / "chains"

    @property
    def witness_dir(self) -> Path:
        return self.data_dir / "witness"

    @property
    def imports_dir(self) -> Path:
        return self.data_dir / "imports"

    @property
    def web_ui_state(self) -> str:
        """`served` or `not_built` — a fact about this deployment, not an error."""
        return "served" if (self.static_dir / "index.html").is_file() else "not_built"

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Settings:
        source = os.environ if env is None else env
        raw_dir = source.get(ENV_DATA_DIR)
        return cls(
            data_dir=Path(raw_dir) if raw_dir else DEFAULT_DATA_DIR,
            # An unset credential is None, never "": empty-string equality would
            # make `Authorization: Bearer ` a valid token.
            api_key=source.get(ENV_API_KEY) or None,
            witness_api_key=source.get(ENV_WITNESS_API_KEY) or None,
            database_url=source.get(ENV_DATABASE_URL) or None,
        )
