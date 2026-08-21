"""Redact-before-clip, across every integration's _sanitize.

The clip used to run BEFORE the redactor (which only runs inside AuditLog):
a PEM longer than MAX_FIELD_CHARS lost its END marker to the clip, the
private-key pattern no longer matched, and the key body reached disk in
cleartext. Redaction must happen on the UNCLIPPED text (CLAUDE.md:
redact-before-hash is the locked design; the clip is part of "before")."""

import importlib

import pytest

from waxseal.adapters.redactors import REDACTED

STDLIB_ONLY_MODULES = [
    "waxseal.integrations.claude_code",
    "waxseal.integrations.codex",
    "waxseal.integrations.cursor",
    "waxseal.integrations.hermes",
]


def oversized_pem() -> str:
    return (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        + ("A" * 64 + "\n") * 80
        + "-----END RSA PRIVATE KEY-----"
    )


@pytest.mark.parametrize("module_name", STDLIB_ONLY_MODULES)
class TestRedactBeforeClip:
    def test_oversized_pem_never_survives_sanitize(self, module_name: str) -> None:
        mod = importlib.import_module(module_name)
        pem = oversized_pem()
        assert len(pem) > mod.MAX_FIELD_CHARS  # the clip WOULD split it
        out = mod._sanitize({"tool_output": f"$ cat id_rsa\n{pem}"})
        text = str(out)
        assert "AAAA" not in text
        assert "BEGIN RSA PRIVATE KEY" not in text
        assert REDACTED in text

    def test_token_split_at_clip_boundary_never_survives(self, module_name: str) -> None:
        mod = importlib.import_module(module_name)
        # The token starts just before the clip boundary and ends past it: a
        # clip-first order leaves a partial "sk-BB…" fragment that no pattern
        # matches anymore.
        text = "x" * (mod.MAX_FIELD_CHARS - 7) + " sk-" + "B" * 40
        out = mod._sanitize(text)
        # The security property is "no key material on disk" — the clip may
        # legitimately cut into the ***REDACTED*** marker itself.
        assert "sk-B" not in out
        assert "BBBB" not in out

    def test_oversized_nonsecret_text_is_still_clipped(self, module_name: str) -> None:
        mod = importlib.import_module(module_name)
        out = mod._sanitize("y" * (mod.MAX_FIELD_CHARS + 500))
        assert len(out) <= mod.MAX_FIELD_CHARS + 64  # clip marker allowance
        assert "truncated" in out
