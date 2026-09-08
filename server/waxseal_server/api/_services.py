"""The process-wide service container, constructed once in `app.py`.

Explicit injection rather than module-level globals is what lets a test stand up
two servers with different credentials in one process, and what keeps a router
honest about its dependencies — a module that needs the CLI has to say so.
"""

from __future__ import annotations

from dataclasses import dataclass

from waxseal_server.config import Settings
from waxseal_server.ports.operators import OperatorStore
from waxseal_server.ports.settings import SettingsStore
from waxseal_server.runtime.cli import WaxsealCli
from waxseal_server.storage.chains import ChainStore
from waxseal_server.storage.imports import ImportStore
from waxseal_server.storage.witness import WitnessStore


@dataclass(frozen=True, slots=True)
class Services:
    #: The frozen environment this process started with. Read-only everywhere.
    settings: Settings
    chains: ChainStore
    imports: ImportStore
    witnesses: WitnessStore
    operators: OperatorStore
    #: Operator-changeable configuration. Deliberately a DIFFERENT field from
    #: `settings`: one is the environment and cannot be written, the other is
    #: the store and holds no credential.
    config: SettingsStore
    cli: WaxsealCli
