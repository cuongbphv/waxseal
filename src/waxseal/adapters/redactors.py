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
    # Stripe secret/restricted keys and webhook secrets (underscore, not hyphen)
    re.compile(r"(?<![A-Za-z0-9])(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}"),
    re.compile(r"(?<![A-Za-z0-9])whsec_[A-Za-z0-9]+"),
    # AWS access key id (Gitleaks/OpenRouter also name ABIA/ACCA/A3T)
    re.compile(r"(?<![A-Za-z0-9])(?:AKIA|ASIA|ABIA|ACCA|A3T[A-Z0-9])[0-9A-Z]{16}"),
    # HuggingFace
    re.compile(r"(?<![A-Za-z0-9])hf_[A-Za-z0-9]{34,}"),
    # GitHub tokens (classic + fine-grained)
    re.compile(r"(?<![A-Za-z0-9])(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{16,}"),
    # Bearer tokens in headers
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    # Private key blocks
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
    # PGP private key blocks (the PEM pattern above requires "PRIVATE KEY-----"
    # flush against the delimiter, which this form does not)
    re.compile(
        r"-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]*?-----END PGP PRIVATE KEY BLOCK-----"
    ),
    # Slack tokens, app tokens, and incoming webhooks
    re.compile(r"(?<![A-Za-z0-9])xox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"(?<![A-Za-z0-9])xoxe-[A-Za-z0-9-]+"),
    re.compile(r"(?<![A-Za-z0-9])xapp-[A-Za-z0-9-]+"),
    re.compile(
        r"https://hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9/_+]+"
    ),
    # GitLab personal access tokens and the 2026 deploy/runner/project/CI prefixes
    re.compile(r"(?<![A-Za-z0-9])glpat-[A-Za-z0-9_-]{20,}"),
    re.compile(r"(?<![A-Za-z0-9])gl(?:dt|rt|ptt|cbt)-[A-Za-z0-9_-]{16,}"),
    # Google API keys and OAuth client secrets
    re.compile(r"(?<![A-Za-z0-9])AIza[0-9A-Za-z_-]{35}"),
    re.compile(r"(?<![A-Za-z0-9])GOCSPX-[A-Za-z0-9_-]+"),
    # Bare JWTs (header is base64 of '{"' so always eyJ). The Bearer pattern
    # misses JWTs pasted into command bodies / env dumps, the exact leak the
    # AI-agent transcripts this library audits are full of.
    re.compile(r"(?<![A-Za-z0-9])eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}"),
    # npm automation/publish tokens
    re.compile(r"(?<![A-Za-z0-9])npm_[A-Za-z0-9]{30,}"),
    # PyPI, SendGrid, DigitalOcean
    re.compile(r"(?<![A-Za-z0-9])pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{20,}"),
    re.compile(r"(?<![A-Za-z0-9])SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}"),
    re.compile(r"(?<![A-Za-z0-9])do[prso]_v1_[a-f0-9]{64}"),
    # HTTP Basic in a header dump — not the English word "basic"
    re.compile(r"(?i)Authorization\s*[:=]\s*Basic\s+[A-Za-z0-9+/=]+"),
    # Connection-string userinfo (host-only URIs must not match)
    re.compile(
        r"(?i)(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://"
        r"[^\s:/@]+:[^\s@/]+@"
    ),
    # Header dump Anthropic-style
    re.compile(r"(?i)x-api-key\s*[:=]\s*[A-Za-z0-9._~+/-]{8,}"),
)

# Key names whose values are redacted wholesale, whatever their shape.
# Exact-name matching only: substring rules would eat "tokenizer"/"authors"
# and destroy audit value (over-redaction is its own failure mode).
SENSITIVE_KEYS: Final = frozenset(
    {"password", "passwd", "secret", "token", "api_key", "apikey", "access_key",
     "private_key", "credentials", "authorization", "auth",
     # OAuth/OIDC and cloud-SDK field names seen in agent tool args
     "access_token", "refresh_token", "id_token", "session_token",
     "client_secret", "aws_secret_access_key", "aws_session_token",
     "x-api-key", "api-key", "secret_key", "auth_token", "bearer_token",
     "database_url", "db_url", "mongodb_uri", "postgres_url", "redis_url",
     "aws_access_key_id", "private-key"}
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
            # it to a list would invent one — refuse instead.
            return tuple(self._walk(v) for v in value)
        if isinstance(value, (set, frozenset)):
            raise TypeError(
                f"{type(value).__name__} values have no canonical order; "
                "refuse rather than convert to a list"
            )
        return value
