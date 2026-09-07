"""Default regex-based redactor.

Runs BEFORE payload_hash (SPEC section 6): the hash commits to the redacted
payload, so a miss here is unrecoverable by design: patterns err toward
matching. Value patterns catch secrets embedded in strings; key-based
redaction catches structured fields regardless of value shape.
"""

from __future__ import annotations

import re
from typing import Any, Final

REDACTED: Final = "***REDACTED***"

# Each pattern notes the secret family it targets. Word-ish left boundaries
# avoid eating identifiers that merely contain a prefix (e.g. "risk-...").
SECRET_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    # OpenAI/Anthropic-style keys: sk-... (20+ chars of key body)
    re.compile(r"(?<![A-Za-z0-9])sk-[A-Za-z0-9_-]{16,}"),
    # AWS access key id
    re.compile(r"(?<![A-Za-z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}"),
    # GitHub tokens (classic + fine-grained)
    re.compile(r"(?<![A-Za-z0-9])(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{16,}"),
    # Bearer tokens in headers
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    # Private key blocks
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
    # Slack tokens
    re.compile(r"(?<![A-Za-z0-9])xox[baprs]-[A-Za-z0-9-]{10,}"),
    # GitLab personal access tokens
    re.compile(r"(?<![A-Za-z0-9])glpat-[A-Za-z0-9_-]{20,}"),
    # Bare JWTs (header is base64 of '{"' so always eyJ). The Bearer pattern
    # misses JWTs pasted into command bodies / env dumps, the exact leak the
    # AI-agent transcripts this library audits are full of.
    re.compile(r"(?<![A-Za-z0-9])eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}"),
    # npm automation/publish tokens
    re.compile(r"(?<![A-Za-z0-9])npm_[A-Za-z0-9]{30,}"),
    # Google API keys
    re.compile(r"(?<![A-Za-z0-9])AIza[0-9A-Za-z_-]{35}"),
)

# Key names whose values are redacted wholesale, whatever their shape.
# Exact-name matching only: substring rules would eat "tokenizer"/"authors"
# and destroy audit value (over-redaction is its own failure mode).
SENSITIVE_KEYS: Final = frozenset(
    {"password", "passwd", "secret", "token", "api_key", "apikey", "access_key",
     "private_key", "credentials", "authorization", "auth",
     # OAuth/OIDC and cloud-SDK field names seen in agent tool args
     "access_token", "refresh_token", "id_token", "session_token",
     "client_secret", "aws_secret_access_key", "aws_session_token"}
)


class RegexRedactor:
    def redact(self, payload: dict[str, Any]) -> dict[str, Any]:
        return {k: self._value(k, v) for k, v in payload.items()}

    def redact_text(self, text: str) -> str:
        """Value-pattern redaction for a bare string. Exists so callers that
        bound/clip text (the integration hooks) can redact FIRST: a clip can
        split a secret across the boundary (a PEM losing its END marker no
        longer matches the private-key pattern) and land it on disk."""
        for pattern in SECRET_PATTERNS:
            text = pattern.sub(REDACTED, text)
        return text

    def _value(self, key: str, value: Any) -> Any:
        if key.lower() in SENSITIVE_KEYS:
            return REDACTED
        return self._walk(value)

    def _walk(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.redact_text(value)
        if isinstance(value, dict):
            return {k: self._value(k, v) for k, v in value.items()}
        if isinstance(value, list):
            return [self._walk(v) for v in value]
        if isinstance(value, tuple):
            # json encodes a tuple as an array; walking it is the same leak
            # class as a list. A set has no canonical order, so converting
            # it to a list would invent one - refuse instead.
            return tuple(self._walk(v) for v in value)
        if isinstance(value, (set, frozenset)):
            raise TypeError(
                f"{type(value).__name__} values have no canonical order; "
                "refuse rather than convert to a list"
            )
        return value
