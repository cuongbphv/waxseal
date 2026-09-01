"""Serving the built UI, and saying so plainly when it has not been built.

A server whose UI assets are missing must not answer with a bare 404. "This
image was built without the web UI" and "that page does not exist" are different
facts, and an operator who cannot tell them apart will go looking for the wrong
bug (CLAUDE.md rule 6: a degradation is labelled, never swallowed).
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from waxseal_server.app import Settings, create_app


def _built(tmp_path: Path) -> Path:
    static = tmp_path / "static"
    (static / "assets").mkdir(parents=True)
    (static / "index.html").write_text("<!doctype html><title>Waxseal Portal</title>")
    (static / "assets" / "app.js").write_text("console.log('portal')")
    return static


@pytest.fixture
def built(tmp_path: Path) -> TestClient:
    return TestClient(
        create_app(Settings(data_dir=tmp_path / "data", static_dir=_built(tmp_path)))
    )


@pytest.fixture
def unbuilt(tmp_path: Path) -> TestClient:
    return TestClient(
        create_app(Settings(data_dir=tmp_path / "data", static_dir=tmp_path / "absent"))
    )


class TestUnbuilt:
    def test_the_root_says_the_ui_was_not_built(self, unbuilt: TestClient) -> None:
        resp = unbuilt.get("/")
        assert resp.status_code == 200
        assert "not built" in resp.text.lower()

    def test_it_names_the_command_that_builds_it(self, unbuilt: TestClient) -> None:
        assert "npm run build" in unbuilt.get("/").text

    def test_the_api_is_unaffected(self, unbuilt: TestClient) -> None:
        assert unbuilt.get("/health").json() == {"status": "ok"}

    def test_meta_reports_the_ui_as_absent(self, unbuilt: TestClient) -> None:
        assert unbuilt.get("/v1/meta").json()["web_ui"] == "not_built"


class TestBuilt:
    def test_the_root_serves_the_app_shell(self, built: TestClient) -> None:
        assert "Waxseal Portal" in built.get("/").text

    def test_an_asset_is_served(self, built: TestClient) -> None:
        assert built.get("/assets/app.js").text == "console.log('portal')"

    def test_a_client_route_falls_back_to_the_shell(self, built: TestClient) -> None:
        # The router owns /chains/default; the server must hand back index.html
        # rather than 404, or a refresh on any deep link breaks.
        assert "Waxseal Portal" in built.get("/chains/default").text

    def test_the_api_still_wins_over_the_fallback(self, built: TestClient) -> None:
        # A 404 from the API must stay a 404 from the API. Falling back to the
        # shell here would answer a data question with a web page.
        assert built.get("/v1/chains/default/head").status_code == 404

    def test_a_public_api_miss_stays_a_public_api_miss(self, built: TestClient) -> None:
        assert built.get("/public/v1/chains/default/receipts").status_code == 404

    def test_an_unknown_asset_path_does_not_escape_the_static_root(
        self, built: TestClient, tmp_path: Path
    ) -> None:
        (tmp_path / "secret.txt").write_text("do not serve me")
        resp = built.get("/assets/../../secret.txt")
        assert "do not serve me" not in resp.text

    def test_meta_reports_the_ui_as_served(self, built: TestClient) -> None:
        assert built.get("/v1/meta").json()["web_ui"] == "served"


class TestDefaultStaticLocation:
    def test_the_default_is_the_packaged_static_directory(self, tmp_path: Path) -> None:
        # The Vite build writes into the package so the Docker image carries the
        # UI without a second copy step.
        settings = Settings(data_dir=tmp_path)
        assert settings.static_dir.name == "static"
        assert settings.static_dir.parent.name == "waxseal_server"


class TestTheFallbackNeverSwallowsAnApiMiss:
    def test_an_unmatched_api_path_stays_a_404(self, built: TestClient) -> None:
        # Handing index.html back to a caller that asked for JSON turns "no such
        # endpoint" into a parse error three layers away.
        resp = built.get("/v1/definitely-not-a-route")
        assert resp.status_code == 404
        assert "Waxseal Portal" not in resp.text

    def test_an_unmatched_public_path_stays_a_404(self, built: TestClient) -> None:
        assert built.get("/public/nope").status_code == 404
