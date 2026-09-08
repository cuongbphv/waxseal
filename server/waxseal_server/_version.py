"""Installed package version. One number; callers import API_VERSION."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

try:
    API_VERSION = version("waxseal-server")
except PackageNotFoundError:
    # A checkout on sys.path with no dist-info. The number is unknown,
    # and it says so: a fallback that looked like a release would be a
    # fail-open nobody could see (CLAUDE.md rule 6). tests/test_version_sync.py
    # is the ratchet that keeps the installed value equal to pyproject.
    API_VERSION = "0+unknown"
