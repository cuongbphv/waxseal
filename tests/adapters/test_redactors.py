"""Tests for RegexRedactor and the redact-before-hash pipeline (SPEC section 6)."""

from pathlib import Path

from waxseal import AuditLog
from waxseal.adapters.redactors import REDACTED, RegexRedactor

PT = "application/vnd.test.event+json"


class TestValueRedaction:
    def test_openai_style_key_is_redacted(self) -> None:
        out = RegexRedactor().redact({"cmd": "export KEY=sk-abc123def456ghi789jkl012"})
        assert "sk-abc123def456ghi789jkl012" not in str(out)
        assert REDACTED in out["cmd"]

    def test_aws_access_key_id_is_redacted(self) -> None:
        out = RegexRedactor().redact({"env": "AKIAIOSFODNN7EXAMPLE"})
        assert "AKIAIOSFODNN7EXAMPLE" not in str(out)

    def test_bearer_token_is_redacted(self) -> None:
        out = RegexRedactor().redact({"h": "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.x.y"})
        assert "eyJhbGciOiJIUzI1NiJ9" not in str(out)

    def test_github_token_is_redacted(self) -> None:
        out = RegexRedactor().redact({"t": "ghp_16C7e42F292c6912E7710c838347Ae178B4a"})
        assert "ghp_16C7e42F292c6912E7710c838347Ae178B4a" not in str(out)

    def test_gitlab_pat_is_redacted(self) -> None:
        # Literal split: GitHub push protection blocks the contiguous glpat- fixture.
        pat = "glpat-" + "Xk2fjPq81mNbV4wZs7Ay"
        out = RegexRedactor().redact({"cmd": f"git push https://oauth2:{pat}@gitlab.example/repo"})
        assert pat not in str(out)

    def test_bare_jwt_is_redacted(self) -> None:
        # A JWT pasted outside an Authorization header (e.g. in a curl body or
        # an agent's echoed env dump) — the Bearer pattern does not see it.
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.SflKxwRJSMeKKF2QT4fwpM"
        out = RegexRedactor().redact({"body": f"curl -d 'jwt={jwt}'"})
        assert jwt not in str(out)

    def test_npm_token_is_redacted(self) -> None:
        tok = "npm_Xk2fjPq81mNbV4wZs7AyQm3RtU8vLc5dEn"
        out = RegexRedactor().redact({"npmrc": f"//registry.npmjs.org/:_authToken={tok}"})
        assert tok not in str(out)

    def test_google_api_key_is_redacted(self) -> None:
        out = RegexRedactor().redact({"url": "https://maps.example/api?key=AIzaSyD4W9bZq1xK7mPv2nR8tYc3LfQj5hGa0eU"})
        assert "AIzaSyD4W9bZq1xK7mPv2nR8tYc3LfQj5hGa0eU" not in str(out)

    def test_plain_text_passes_through_unchanged(self) -> None:
        payload = {"msg": "hello world", "n": 42, "ok": True, "none": None}
        assert RegexRedactor().redact(payload) == payload

    def test_identifier_merely_containing_a_prefix_is_not_eaten(self) -> None:
        # Left-boundary rule: "task-sk-like" ids or words containing "eyJ"
        # mid-token must survive; over-redaction destroys audit value.
        payload = {"id": "risk-sk-not-a-key", "word": "monkeyJumps.over.fences"}
        assert RegexRedactor().redact(payload) == payload


class TestKeyRedaction:
    def test_sensitive_key_names_redact_their_values(self) -> None:
        out = RegexRedactor().redact(
            {"password": "hunter2", "api_key": "xyz", "token": "abc", "secret": "s"}
        )
        assert out == {
            "password": REDACTED,
            "api_key": REDACTED,
            "token": REDACTED,
            "secret": REDACTED,
        }

    def test_common_key_name_variants_are_redacted(self) -> None:
        # OAuth/OIDC and cloud-SDK field names that leak in agent tool args;
        # exact-name matching only ("tokenizer" must NOT match, tested below).
        out = RegexRedactor().redact(
            {
                "access_token": "a",
                "refresh_token": "b",
                "id_token": "c",
                "session_token": "d",
                "client_secret": "e",
                "aws_secret_access_key": "f",
            }
        )
        assert set(out.values()) == {REDACTED}

    def test_non_secret_keys_containing_secret_words_pass_through(self) -> None:
        payload = {"tokenizer": "bpe", "authors": ["a"], "secrets_scanned": 0}
        assert RegexRedactor().redact(payload) == payload

    def test_nested_structures_are_redacted(self) -> None:
        out = RegexRedactor().redact(
            {"outer": {"password": "hunter2"}, "list": [{"token": "abc"}, "AKIAIOSFODNN7EXAMPLE"]}
        )
        assert out["outer"]["password"] == REDACTED
        assert out["list"][0]["token"] == REDACTED
        assert "AKIAIOSFODNN7EXAMPLE" not in str(out)


class TestRedactBeforeHash:
    def test_secret_never_reaches_disk(self, tmp_path: Path) -> None:
        # The whole point of redact-before-hash: cleartext must not appear
        # anywhere in the stored file, and verify must still pass because the
        # hash was computed on the redacted payload.
        path = tmp_path / "trail.jsonl"
        log = AuditLog.open(path, redactor=RegexRedactor())
        log.append(
            payload={"cmd": "curl -H 'Authorization: Bearer sk-verysecretkey12345678'"},
            payload_type=PT,
        )
        raw = path.read_bytes()
        assert b"sk-verysecretkey12345678" not in raw
        assert log.verify().ok


class TestRedactText:
    """redact_text exists so integration hooks can redact BEFORE clipping.
    Clipping first destroys the match: a PEM whose END marker falls past the
    clip boundary stops matching the private-key pattern, and its body lands
    on disk in cleartext — the exact invariant this library sells."""

    def test_pem_block_is_fully_redacted(self) -> None:
        from waxseal.adapters.redactors import REDACTED, RegexRedactor

        pem = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            + ("A" * 64 + "\n") * 80
            + "-----END RSA PRIVATE KEY-----"
        )
        out = RegexRedactor().redact_text(f"key file contents: {pem}")
        assert REDACTED in out
        assert "AAAA" not in out
        assert "BEGIN RSA PRIVATE KEY" not in out

    def test_api_key_token_is_redacted(self) -> None:
        from waxseal.adapters.redactors import REDACTED, RegexRedactor

        out = RegexRedactor().redact_text("run with sk-" + "B" * 40)
        assert REDACTED in out
        assert "sk-B" not in out

    def test_clean_text_is_unchanged(self) -> None:
        from waxseal.adapters.redactors import RegexRedactor

        assert RegexRedactor().redact_text("nothing secret here") == "nothing secret here"
