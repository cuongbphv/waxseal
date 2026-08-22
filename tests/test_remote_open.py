"""AuditLog.open's URL dispatch (M7): a string path is checked against
http(s):// BEFORE Path() construction — Path() would otherwise mangle a URL
(collapsing "//" and stripping the scheme) and never even reach a backend
choice, the same class of bug M0's suffix-dispatch guards against."""

from __future__ import annotations

import pytest

from waxseal import AuditLog
from waxseal.adapters.remote import RemoteBackend


class TestURLDispatch:
    def test_http_url_dispatches_to_remote_backend(self) -> None:
        log = AuditLog.open("http://example.com/v1/chains/default")
        assert isinstance(log._backend, RemoteBackend)

    def test_https_url_dispatches_to_remote_backend(self) -> None:
        log = AuditLog.open("https://example.com/v1/chains/default")
        assert isinstance(log._backend, RemoteBackend)

    def test_local_jsonl_path_is_unaffected(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        from waxseal.adapters.jsonl import JSONLBackend

        log = AuditLog.open(tmp_path / "trail.jsonl")
        assert isinstance(log._backend, JSONLBackend)


class TestAPIKeyFromEnv:
    def test_waxseal_api_key_env_var_is_used_as_bearer_auth(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("WAXSEAL_API_KEY", "tok-from-env")
        log = AuditLog.open("http://example.com/v1/chains/default")
        assert log._backend._api_key == "tok-from-env"

    def test_no_env_var_means_no_api_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("WAXSEAL_API_KEY", raising=False)
        log = AuditLog.open("http://example.com/v1/chains/default")
        assert log._backend._api_key is None


class TestRecordDropsRejectedForURLs:
    def test_record_drops_with_a_url_target_raises(self) -> None:
        with pytest.raises(ValueError, match="record_drops"):
            AuditLog.open("http://example.com/v1/chains/default", record_drops=True)
