"""`python -m waxseal_server` — the entrypoint the Docker image runs.

Condition R, the repository's reachability rule, applies to a container command
too: an entrypoint nothing exercises is an entrypoint nobody has run.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from waxseal_server.__main__ import build, main


class _Recorder:
    def __init__(self) -> None:
        self.app: Any = None
        self.kwargs: dict[str, Any] = {}

    def __call__(self, app: Any, **kwargs: Any) -> None:
        self.app = app
        self.kwargs = kwargs


class TestMain:
    def test_it_serves_on_all_interfaces_by_default(self, tmp_path: Path) -> None:
        # Inside a container, binding loopback would make the published port
        # answer nothing at all.
        run = _Recorder()
        main([], env={"WAXSEAL_SERVER_DATA_DIR": str(tmp_path)}, run=run)
        assert run.kwargs["host"] == "0.0.0.0"  # noqa: S104 - containers publish a port
        assert run.kwargs["port"] == 8000

    def test_host_and_port_are_overridable(self, tmp_path: Path) -> None:
        run = _Recorder()
        main(
            ["--host", "127.0.0.1", "--port", "9001"],
            env={"WAXSEAL_SERVER_DATA_DIR": str(tmp_path)},
            run=run,
        )
        assert run.kwargs["host"] == "127.0.0.1"
        assert run.kwargs["port"] == 9001

    def test_it_builds_an_app_from_the_environment(self, tmp_path: Path) -> None:
        run = _Recorder()
        main(
            [],
            env={"WAXSEAL_SERVER_DATA_DIR": str(tmp_path), "WAXSEAL_API_KEY": "k"},
            run=run,
        )
        assert run.app.state.settings.data_dir == tmp_path
        assert run.app.state.settings.api_key == "k"

    def test_it_returns_zero(self, tmp_path: Path) -> None:
        assert main([], env={"WAXSEAL_SERVER_DATA_DIR": str(tmp_path)}, run=_Recorder()) == 0

    def test_the_data_directory_is_created_if_absent(self, tmp_path: Path) -> None:
        target = tmp_path / "fresh" / "store"
        main([], env={"WAXSEAL_SERVER_DATA_DIR": str(target)}, run=_Recorder())
        assert target.is_dir()


class TestTheAppFactory:
    """`build()` — what `uvicorn --factory` calls for a reloading local run.

    It reads the real process environment, so these tests monkeypatch it rather
    than passing a mapping: the point of the factory is that uvicorn can call it
    with no arguments at all.
    """

    def test_it_builds_an_app_from_the_process_environment(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("WAXSEAL_SERVER_DATA_DIR", str(tmp_path / "data"))
        app = build()
        assert app.state.settings.data_dir == tmp_path / "data"

    def test_it_creates_the_data_directory(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        target = tmp_path / "not-yet"
        monkeypatch.setenv("WAXSEAL_SERVER_DATA_DIR", str(target))
        build()
        assert target.is_dir()

    def test_the_reloading_path_and_the_container_path_agree(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Both must build from the same environment, or a local run would be
        # exercising a different app from the one deployed.
        monkeypatch.setenv("WAXSEAL_SERVER_DATA_DIR", str(tmp_path / "data"))
        built: list[object] = []
        main([], env={"WAXSEAL_SERVER_DATA_DIR": str(tmp_path / "data")},
             run=lambda app, **_: built.append(app))
        assert built[0].state.settings.data_dir == build().state.settings.data_dir
