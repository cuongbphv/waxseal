"""The web console's package.json carries the same version as the server it
is built into.

The 0.1.6 bump moved pyproject, server/pyproject, __version__, CHANGELOG,
compose, install.sh and both Helm appVersions - and missed
server/web/package.json, because nothing pinned it. The console is served by
the server, so `npm pkg get version` claiming the previous release for a
build the server reports as the current one is the two-versions-at-once drift
server/tests/test_version_sync.py exists to refuse on the Python side.
"""

from __future__ import annotations

import json
import tomllib
from pathlib import Path

REPO = Path(__file__).parent.parent.parent


def test_web_package_version_matches_server_pyproject() -> None:
    server = tomllib.loads((REPO / "server" / "pyproject.toml").read_text())
    package = json.loads((REPO / "server" / "web" / "package.json").read_text())
    lock = json.loads((REPO / "server" / "web" / "package-lock.json").read_text())
    declared = server["project"]["version"]
    assert package["version"] == declared
    assert lock["version"] == declared
    assert lock["packages"][""]["version"] == declared
