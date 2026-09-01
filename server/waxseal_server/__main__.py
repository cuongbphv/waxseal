"""`python -m waxseal_server` — the process the container runs.

Configuration comes from the environment, never from the command line, for the
same reason `WAXSEAL_API_KEY` does (REMOTE.md section 5): an argument is visible
in a process listing. `--host` and `--port` are the exception because neither is
a secret and a container needs to publish somewhere.
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Callable, Mapping
from typing import Any

import uvicorn
from fastapi import FastAPI

from waxseal_server.app import create_app
from waxseal_server.config import Settings


def build() -> FastAPI:
    """An app built from the environment — the `uvicorn --factory` entry point.

    Exists so a local run can use `--reload`, which needs uvicorn to import and
    re-import the app itself rather than be handed an instance. `main` below
    goes through it too, so the reloading path and the container path build the
    same object from the same environment and cannot drift.
    """
    settings = Settings.from_env()
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    return create_app(settings)


def main(
    argv: list[str] | None = None,
    *,
    env: Mapping[str, str] | None = None,
    run: Callable[..., Any] = uvicorn.run,
) -> int:
    parser = argparse.ArgumentParser(prog="waxseal-server", description=__doc__)
    # 0.0.0.0 by default: a container that bound loopback would publish a port
    # answering nothing. Put it behind the reverse proxy the deployment doc
    # describes, which is where TLS terminates.
    parser.add_argument("--host", default="0.0.0.0")  # noqa: S104
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args(argv)

    settings = Settings.from_env(os.environ if env is None else env)
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    run(create_app(settings), host=args.host, port=args.port)
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised as a subprocess, not imported
    sys.exit(main())
