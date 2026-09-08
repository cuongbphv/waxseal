"""Installed package version. One number; callers import API_VERSION."""

from __future__ import annotations

from importlib.metadata import version

API_VERSION = version("waxseal-server")
