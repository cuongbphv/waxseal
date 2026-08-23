"""Every ports/ module is an importable Protocol declaration and nothing else.

Ports are the seams the layer DAG is defined in terms of, but nothing imports
most of them at runtime — a port that stopped importing (a stale type, a
circular import introduced by a later refactor) would go unnoticed until
somebody tried to write an adapter against it. This walks the package and
imports each one.

It also pins the shape: a port declares a Protocol, so a third-party adapter
can satisfy it structurally without inheriting anything from waxseal. That is
what lets an integrator hand in their own backend or sink.
"""

from __future__ import annotations

import importlib
import pkgutil
from typing import Protocol, get_type_hints, runtime_checkable

import pytest

import waxseal.ports

PORT_MODULES = sorted(
    module.name for module in pkgutil.iter_modules(waxseal.ports.__path__)
)


def test_the_package_actually_has_ports() -> None:
    # Guards the walk below: an empty iteration would pass every test in this
    # file while checking nothing.
    assert len(PORT_MODULES) >= 5


@pytest.mark.parametrize("name", PORT_MODULES)
class TestEveryPort:
    def module(self, name: str) -> object:
        return importlib.import_module(f"waxseal.ports.{name}")

    def test_imports(self, name: str) -> None:
        assert self.module(name) is not None

    def test_declares_at_least_one_protocol(self, name: str) -> None:
        module = self.module(name)
        protocols = [
            obj
            for obj in vars(module).values()
            if isinstance(obj, type) and Protocol in getattr(obj, "__bases__", ())
        ]
        assert protocols, f"waxseal.ports.{name} declares no Protocol"

    def test_annotations_resolve(self, name: str) -> None:
        # `from __future__ import annotations` hides an unresolvable type until
        # something calls get_type_hints — which is exactly what a typed
        # adapter's tooling does.
        module = self.module(name)
        for obj in vars(module).values():
            if isinstance(obj, type) and Protocol in getattr(obj, "__bases__", ()):
                get_type_hints(obj)


class TestProtocolsAreStructural:
    def test_an_outside_class_satisfies_a_port_without_inheriting(self) -> None:
        from waxseal.domain.checkpoint import Checkpoint
        from waxseal.ports.anchor import AnchorSink

        @runtime_checkable
        class Checkable(AnchorSink, Protocol): ...

        class Foreign:
            name = "foreign"

            def anchor(self, checkpoint: Checkpoint) -> str | None:
                return None

        assert isinstance(Foreign(), Checkable)
