"""The server version is one number, read from the installed package.

The library already refuses a hand-edited __version__ that drifted from
pyproject (tests/architecture/test_invariants.py). The server used to
carry the same number in three places - pyproject, API_VERSION, and the
/v1/meta JSON literal - so a bump that missed one shipped two versions
at once. importlib.metadata.version is the single source; this file is
the ratchet.
"""

from __future__ import annotations

import importlib
import importlib.metadata
import tomllib
from importlib.metadata import PackageNotFoundError
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from waxseal_server import _version
from waxseal_server.app import API_VERSION, Settings, create_app

SERVER_ROOT = Path(__file__).resolve().parents[1]


def test_api_version_matches_pyproject_and_the_installed_package() -> None:
    declared = tomllib.loads((SERVER_ROOT / "pyproject.toml").read_text())[
        "project"
    ]["version"]
    assert declared == API_VERSION


def test_meta_reports_the_same_version(tmp_path: Path) -> None:
    client = TestClient(create_app(Settings(data_dir=tmp_path / "data")))
    assert client.get("/v1/meta").json()["version"] == API_VERSION


def test_a_source_checkout_without_the_dist_still_imports(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # `version()` raises when waxseal-server is not installed as a
    # distribution (a bare checkout on sys.path). Letting that propagate
    # takes `import waxseal_server` down with it. The fallback is a value
    # no release could carry, so it labels itself (CLAUDE.md rule 6)
    # rather than impersonating a shipped number.
    def missing(name: str) -> str:
        raise PackageNotFoundError(name)

    monkeypatch.setattr(importlib.metadata, "version", missing)
    try:
        reloaded = importlib.reload(_version)
        assert reloaded.API_VERSION == "0+unknown"
    finally:
        monkeypatch.undo()
        importlib.reload(_version)
    assert _version.API_VERSION == API_VERSION
