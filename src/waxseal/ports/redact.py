"""Redaction protocol. Runs BEFORE payload_hash (SPEC.md section 6),
the hash commits to the redacted payload, so cleartext never reaches storage
and verification stays consistent."""

from __future__ import annotations

from typing import Any, Protocol


class Redactor(Protocol):
    def redact(self, payload: dict[str, Any]) -> dict[str, Any]: ...
