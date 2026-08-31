"""waxseal-server — a self-hosted chain server, witness, and read-only portal.

Layered the way the library it serves is layered (CLAUDE.md's architecture
section), with a one-way dependency arrow:

    api/       FastAPI routers. The only layer that knows about HTTP.
    runtime/   adapters to things outside the process: the waxseal CLI, the
               built web bundle, reading a trail for display.
    storage/   persistence. Knows about files and locks, not about requests.
    domain/    pure logic: envelope and checkpoint parsing, identifier shapes,
               the receipt chain, and the result types. No I/O at all.
    config.py  settings, read from the environment and passed down explicitly.

Nothing below `api/` imports FastAPI, and nothing in `domain/` touches the
filesystem — which is what makes the rules readable and testable without
standing a server up.
"""

from waxseal_server.app import create_app
from waxseal_server.config import Settings

__all__ = ["Settings", "create_app"]
