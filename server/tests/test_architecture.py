"""The layer DAG, enforced rather than described.

The library this server wraps keeps its own layering honest with
`tests/architecture/` instead of a paragraph in a README, because a documented
architecture decays at the speed of the next hurried import. This is the same
check for the server:

    api/       may import anything below it
    runtime/   may import domain/ and config
    storage/   may import domain/ and config
    domain/    may import nothing from this package but itself

Plus the rule that gives `domain/` its value: it performs no I/O, so the rules
can be read and tested without standing a server up.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

PACKAGE = Path(__file__).resolve().parents[1] / "waxseal_server"
SELF = "waxseal_server"

#: layer -> the sibling layers it may import. `config` is a leaf everyone may
#: read; `app` is the composition root and is imported only by the entrypoint.
ALLOWED: dict[str, set[str]] = {
    "domain": set(),
    "ports": {"domain"},
    "storage": {"domain"},
    "runtime": {"domain"},
    "api": {"domain", "ports", "storage", "runtime"},
}

#: Modules that may not appear anywhere under `domain/`. A domain that opens a
#: file is a domain you need a temp directory to test.
IO_MODULES = {"os", "pathlib", "shutil", "tempfile", "socket", "subprocess", "sqlite3"}

WEB_MODULES = {"fastapi", "starlette", "uvicorn"}


def _modules(layer: str) -> list[Path]:
    return sorted((PACKAGE / layer).rglob("*.py"))


def _imported_names(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module)
    return names


def _own_layer_of(module: str) -> str | None:
    """The layer a `waxseal_server.<layer>.<mod>` import names, if any."""
    parts = module.split(".")
    if len(parts) >= 2 and parts[0] == SELF and parts[1] in ALLOWED:
        return parts[1]
    return None


@pytest.mark.parametrize("layer", sorted(ALLOWED))
class TestLayerDag:
    def test_a_layer_imports_only_what_it_is_allowed_to(self, layer: str) -> None:
        for path in _modules(layer):
            for module in _imported_names(path):
                other = _own_layer_of(module)
                if other is None or other == layer:
                    continue
                assert other in ALLOWED[layer], (
                    f"{path.name} is in {layer}/ and imports {module}; "
                    f"{layer}/ may only import {sorted(ALLOWED[layer]) or 'nothing'}"
                )

    def test_no_layer_imports_the_composition_root(self, layer: str) -> None:
        # `app.py` wires everything together. Anything importing it has made a
        # cycle, and the next person to add a router will find it.
        for path in _modules(layer):
            assert f"{SELF}.app" not in _imported_names(path), path.name


class TestDomainIsPure:
    def test_domain_touches_no_io(self) -> None:
        for path in _modules("domain"):
            offending = _imported_names(path) & IO_MODULES
            assert not offending, f"{path.name} imports {sorted(offending)}"

    def test_domain_never_opens_a_file(self) -> None:
        for path in _modules("domain"):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            calls = {
                node.func.id
                for node in ast.walk(tree)
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            }
            assert "open" not in calls, path.name


class TestOnlyTheApiLayerKnowsAboutHttp:
    @pytest.mark.parametrize("layer", ["domain", "ports", "storage", "runtime"])
    def test_no_web_framework_below_the_api_layer(self, layer: str) -> None:
        # `runtime/spa.py` is the deliberate exception: serving the built bundle
        # IS a web concern, and it is an adapter to one specific outside thing.
        for path in _modules(layer):
            if path.name == "spa.py":
                continue
            offending = {
                name for name in _imported_names(path) if name.split(".")[0] in WEB_MODULES
            }
            assert not offending, f"{path.name} imports {sorted(offending)}"


class TestTheCheckItselfWorks:
    """A conformance test that cannot fail is not a check.

    These prove the parser sees what it claims to: without them, a typo in the
    layer names above would make every assertion above pass vacuously.
    """

    def test_it_reads_imports_out_of_a_real_module(self, tmp_path: Path) -> None:
        module = tmp_path / "sample.py"
        module.write_text(
            "import os\nfrom waxseal_server.api.deps import Services\n", encoding="utf-8"
        )
        assert _imported_names(module) == {"os", "waxseal_server.api.deps"}

    def test_it_resolves_a_layer_from_a_module_path(self) -> None:
        assert _own_layer_of("waxseal_server.storage.chains") == "storage"
        assert _own_layer_of("waxseal_server.config") is None
        assert _own_layer_of("json") is None

    def test_every_layer_actually_has_modules_to_check(self) -> None:
        for layer in ALLOWED:
            assert _modules(layer), f"{layer}/ has no modules; the DAG check is vacuous"
