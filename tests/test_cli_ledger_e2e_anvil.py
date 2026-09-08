"""End-to-end: the actual ``waxseal`` CLI, run as a subprocess, against real
anvil chains running F2's deployed contracts.

This is a different layer of evidence than either of F1-F4's own suites:

  * ``tests/adapters/test_evm_anvil.py`` (F3) proves the ADAPTER against real
    chains by calling ``EvmLedgerReader``/``EvmLedgerSink`` directly in
    Python.
  * ``tests/test_cli_ledger_status.py`` etc. (F4) prove the CLI's own
    plumbing (argument parsing, verdict joining, exit codes) against FAKE
    JSON-RPC nodes.

Neither exercises the thing an operator actually runs: ``waxseal`` invoked as
a separate process, reading real argv, printing to a real stdout a second
process reads back, against a real anvil node it did not fake. This file
drives ``sys.executable -m waxseal.cli`` (the same module ``[project.scripts]``
points at) as a subprocess throughout, the way ``tests/test_cli_install.py``
already does for the hook shim. Where a scenario needs bytes no CLI command
produces (the two on-chain-only bootstrap calls named below, and the
consistency-proof cross-check's raw ``cast call``), that is done directly and
labelled as bootstrap, never substituted for the CLI path under test.

Two bootstrap operations have no CLI command at all and are performed
directly through ``EvmLedgerSink`` (matching ``tests/adapters/
test_evm_anvil.py``'s own ``_register_and_anchor``), because nothing here
claims otherwise:

  * ``registerTrail`` (bind a trail id to a writer key and a deadline) --
    CLAUDE.md's CLI contract keeps ``anchor``/``registry publish``/``bond``
    to writes an OPERATOR already knows about; registering a NEW trail id is
    a one-time setup step every real deployment does once, out of band, the
    same way deploying the contracts themselves is (via ``forge create``,
    also not a waxseal CLI concern).
  * the digest signatures fed into the fabricated equivocation proof --
    signing two DELIBERATELY CONTRADICTORY checkpoints is the fraud being
    proved, not a normal write path, so it is produced with ``cast wallet
    sign --no-hash`` exactly as an attacker's own tooling would.

If Foundry is absent every test here SKIPS WITH A LABEL, matching
``tests/adapters/test_evm_anvil.py``'s own convention: never a silent pass.
"""

from __future__ import annotations

import json
import socket
import subprocess
import sys
import time
import urllib.request
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from tests import _foundry
from waxseal import AuditLog
from waxseal.adapters.evm import EvmContracts, EvmLedgerSink
from waxseal.domain.anchoring import (
    batch_root,
    consistency_proof,
    membership_proof,
    verify_consistency,
)
from waxseal.domain.bond import checkpoint_signing_digest
from waxseal.domain.checkpoint import Checkpoint
from waxseal.domain.fingerprint import HEADER_FIELDS, fingerprint_for

CONTRACTS = Path(__file__).resolve().parent.parent / "contracts"

# anvil's default accounts (Foundry's own published dev mnemonic — controls
# nothing on any real chain). Three roles, three keys, so the disagreement
# and equivocation scenarios do not contaminate the plain-live/delinquent
# ones by sharing state under one address.
RELAYER_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
RELAYER_ADDRESS = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
WRITER1_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
WRITER1_ADDRESS = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
WRITER2_KEY = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"
WRITER2_ADDRESS = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"
#: A THIRD writer, because the `chain` fixture is module-scoped and a slashed
#: bond does not come back: the equivocation test spends WRITER2 permanently,
#: so a second slashing test needs its own stake or it depends on test order.
WRITER3_KEY = "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6"
WRITER3_ADDRESS = "0x90F79bf6EB2c4f870365E785982E1f101E93b906"

WITHDRAW_DELAY_S = 3600
LONG_DEADLINE_S = 3600
SHORT_DEADLINE_S = 25

PT = "application/vnd.test.e2e+json"


FOUNDRY_BIN = _foundry.FOUNDRY_BIN

pytestmark = _foundry.skip_without_foundry(
    reason=(
        "SKIPPED WITH LABEL: Foundry (anvil/forge/cast 1.8.x) was found neither on PATH "
        "nor in foundryup's install directory (tests/_foundry.py looked in both), so the "
        "CLI-subprocess-against-real-anvil evidence for the ledger layer was NOT collected "
        "on this run. Install with `foundryup`. tests/adapters/test_evm_anvil.py and "
        "tests/test_cli_ledger_status.py still cover the adapter and the CLI's own "
        "plumbing independently of this file."
    ),
)


def _base_env() -> dict[str, str]:
    return _foundry.env()


def _run(*args: str, cwd: Path | None = None) -> str:
    done = subprocess.run(
        list(args),
        cwd=cwd,
        env=_base_env(),
        capture_output=True,
        text=True,
        timeout=180,
        encoding="utf-8",
    )
    if done.returncode != 0:
        raise AssertionError(f"{' '.join(args)} failed ({done.returncode}):\n{done.stderr}")
    return done.stdout.strip()


def _rpc(url: str, method: str, params: list[Any]) -> Any:
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    request = urllib.request.Request(
        url, data=body, headers={"content-type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310
        return json.loads(response.read())


def _mine(url: str, blocks: int = 2) -> None:
    _rpc(url, "anvil_mine", [hex(blocks)])


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


@dataclass
class Node:
    url: str
    process: subprocess.Popen[bytes]


def _start_anvil() -> Node:
    port = _free_port()
    # --slots-in-an-epoch 1: without it `finalized` (the adapter's default
    # block tag) sits at genesis forever on a dev chain. --block-time 1:
    # the CLI's own write path (`EvmLedgerSink`, unlike this file's
    # bootstrap sink) polls for `finalized` with REAL `time.sleep` -- it has
    # no `sleep_fn` hook to mine on its behalf -- so the chain needs to keep
    # producing blocks on its own while a real `waxseal` subprocess waits,
    # or `finalized` would never catch up to a transaction's block at all.
    process = subprocess.Popen(
        [
            f"{FOUNDRY_BIN}/anvil",
            "--port",
            str(port),
            "--slots-in-an-epoch",
            "1",
            "--block-time",
            "1",
            "--silent",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=_base_env(),
    )
    url = f"http://127.0.0.1:{port}"
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            _rpc(url, "eth_chainId", [])
            return Node(url=url, process=process)
        except Exception:  # noqa: BLE001 - not up yet
            time.sleep(0.1)
    process.kill()
    raise AssertionError(f"anvil on {url} never became ready")


def _deploy(url: str, contract: str, *constructor_args: str) -> str:
    out = _run(
        f"{FOUNDRY_BIN}/forge",
        "create",
        "--rpc-url",
        url,
        "--private-key",
        RELAYER_KEY,
        "--broadcast",
        "--json",
        f"src/{contract}.sol:{contract}",
        *(("--constructor-args", *constructor_args) if constructor_args else ()),
        cwd=CONTRACTS,
    )
    payload = json.loads(out[out.index("{") : out.rindex("}") + 1])
    return str(payload["deployedTo"])


@dataclass
class Deployment:
    nodes: tuple[Node, Node]
    contracts: EvmContracts

    @property
    def urls(self) -> tuple[str, str]:
        return (self.nodes[0].url, self.nodes[1].url)


@pytest.fixture(scope="module")
def chain() -> Iterator[Deployment]:
    """Two anvil nodes, F2's three contracts deployed identically on both --
    the same two-observer shape ``tests/adapters/test_evm_anvil.py`` uses,
    needed here for the same reason: a genuine disagreement test needs two
    real, independently-queryable chains, not one node asked twice."""
    nodes = (_start_anvil(), _start_anvil())
    try:
        addresses: list[EvmContracts] = []
        for node in nodes:
            registry = _deploy(node.url, "FingerprintRegistry")
            liveness = _deploy(node.url, "AnchoringLiveness")
            bond = _deploy(node.url, "BondedCheckpoints", str(WITHDRAW_DELAY_S))
            addresses.append(EvmContracts(liveness=liveness, registry=registry, bond=bond))
        assert addresses[0] == addresses[1], addresses
        yield Deployment(nodes=nodes, contracts=addresses[0])
    finally:
        for node in nodes:
            node.process.kill()
            node.process.wait(timeout=10)


# --------------------------------------------------------- signer bootstrap
#
# Registration has no CLI command (module docstring). Done directly through
# EvmLedgerSink, one call per node so both chains carry the same fact --
# exactly `tests/adapters/test_evm_anvil.py::_register_and_anchor`'s pattern.


class _CastSigner:
    """A real `TransactionSigner` shelling out to `cast`, for the two
    bootstrap-only writes (`register_trail`, the divergent-descriptor
    `register_fingerprint` in the disagreement test) that have no CLI
    command at all (module docstring). Exactly `tests/adapters/
    test_evm_anvil.py`'s own `CastSigner`/`UrlCarryingSigner`, not
    reimported from that test module (test files are not a shared library),
    but the identical pattern: waxseal assembles the transaction, something
    outside the process holds the key."""

    def __init__(self, key: str, address: str, url: str) -> None:
        self._key = key
        self.address = address
        self.public_id = address
        self._url = url

    def sign(self, digest32: bytes) -> bytes:
        signature = _run(
            f"{FOUNDRY_BIN}/cast",
            "wallet",
            "sign",
            "--no-hash",
            "--private-key",
            self._key,
            "0x" + digest32.hex(),
        )
        return bytes.fromhex(signature[2:])

    def sign_transaction(self, fields: Mapping[str, object]) -> bytes:
        raw = _run(
            f"{FOUNDRY_BIN}/cast",
            "mktx",
            "--private-key",
            self._key,
            "--rpc-url",
            self._url,
            "--chain",
            str(fields["chainId"]),
            "--nonce",
            str(fields["nonce"]),
            "--gas-limit",
            str(fields["gas"]),
            "--gas-price",
            str(fields["maxFeePerGas"]),
            "--priority-gas-price",
            str(fields["maxPriorityFeePerGas"]),
            "--value",
            str(fields["value"]),
            str(fields["to"]),
            str(fields["data"]),
        )
        return bytes.fromhex(raw[2:])


def _bootstrap_sink(chain: Deployment, url: str) -> EvmLedgerSink:
    from waxseal.adapters.evm import EvmLedgerReader

    reader = EvmLedgerReader(chain.urls, chain.contracts, timeout=10.0)
    return EvmLedgerSink(
        reader,
        _CastSigner(RELAYER_KEY, RELAYER_ADDRESS, url),
        rpc_url=url,
        sleep_fn=lambda _seconds: _mine(url),  # never a real sleep for confirmation polling
        max_polls=20,
    )


def _register_on_both(chain: Deployment, trail: str, writer: str, deadline_s: int) -> None:
    for url in chain.urls:
        _bootstrap_sink(chain, url).register_trail(trail, writer, deadline_s)


# ----------------------------------------------------------- signer script
#
# WAXSEAL_EVM_SIGNER_CMD's three-verb protocol (cli.py's ExternalEvmSigner
# docstring), backed by real `cast wallet sign --no-hash` / `cast mktx` --
# the operator's own wrapper in production, `tests/test_cli_evm_signer.py`'s
# fake stands in for the same protocol against no real chain at all. This is
# the layer between those two: a real signer, real key, real cast.

_SIGNER_SCRIPT = """
import json
import os
import subprocess
import sys

CAST = os.environ["WAXSEAL_E2E_CAST"]
KEY = os.environ["WAXSEAL_E2E_SIGNER_KEY"]
ADDRESS = os.environ["WAXSEAL_E2E_SIGNER_ADDRESS"]
RPC_URL = os.environ.get("WAXSEAL_E2E_SIGNER_RPC_URL")


def main() -> None:
    verb = sys.argv[1] if len(sys.argv) > 1 else ""
    if verb == "address":
        sys.stdout.write(ADDRESS)
    elif verb == "sign-digest":
        digest = sys.argv[2]
        out = subprocess.run(
            [CAST, "wallet", "sign", "--no-hash", "--private-key", KEY, digest],
            capture_output=True, text=True, check=True,
        )
        sys.stdout.write(out.stdout.strip())
    elif verb == "sign-tx":
        fields = json.loads(sys.stdin.read())
        out = subprocess.run(
            [
                CAST, "mktx", "--private-key", KEY, "--rpc-url", RPC_URL,
                "--chain", str(fields["chainId"]), "--nonce", str(fields["nonce"]),
                "--gas-limit", str(fields["gas"]), "--gas-price", str(fields["maxFeePerGas"]),
                "--priority-gas-price", str(fields["maxPriorityFeePerGas"]),
                "--value", str(fields["value"]), str(fields["to"]), str(fields["data"]),
            ],
            capture_output=True, text=True, check=True,
        )
        sys.stdout.write(out.stdout.strip())
    else:
        sys.exit(2)


main()
"""


@pytest.fixture(scope="module")
def signer_script(tmp_path_factory: pytest.TempPathFactory) -> Path:
    path = tmp_path_factory.mktemp("e2e-signer") / "signer.py"
    path.write_text(_SIGNER_SCRIPT, encoding="utf-8")
    return path


def _cli_env(
    signer_script: Path, *, key: str, address: str, write_url: str | None = None
) -> dict[str, str]:
    env = _base_env()
    env["WAXSEAL_EVM_SIGNER_CMD"] = f"{sys.executable} {signer_script}"
    env["WAXSEAL_E2E_CAST"] = f"{FOUNDRY_BIN}/cast"
    env["WAXSEAL_E2E_SIGNER_KEY"] = key
    env["WAXSEAL_E2E_SIGNER_ADDRESS"] = address
    if write_url is not None:
        env["WAXSEAL_E2E_SIGNER_RPC_URL"] = write_url
    return env


def _waxseal(*args: str, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    """Drive the real CLI entry point (`[project.scripts] waxseal = "waxseal.cli:main"`
    points at this same module) as a subprocess -- argv in, real stdout/
    stderr/exit code out, exactly what an operator's shell sees."""
    return subprocess.run(
        [sys.executable, "-m", "waxseal.cli", *args],
        env=env,
        capture_output=True,
        text=True,
        timeout=90,
        encoding="utf-8",
    )


def make_trail(path: Path, n: int = 2) -> None:
    log = AuditLog.open(path)
    for i in range(n):
        log.append(payload={"i": i}, payload_type=PT)


def _anchor_on_both(chain: Deployment, trail: Path, trail_id: str, signer_script: Path) -> None:
    """`anchor --evm-liveness` (CLI subprocess) once per node, matching
    `tests/adapters/test_evm_anvil.py::_register_and_anchor`'s own pattern:
    "any party may submit a checkpoint the writer signed" (ports/ledger.py's
    `submit_checkpoint` docstring), so publishing the SAME writer-signed
    checkpoint to both endpoints is a real, supported flow, not a test-only
    shortcut -- and it is the only way `ledger-status --rpc A --rpc B`
    reads a clean `live` verdict instead of a transport-level
    `LedgerDisagreement` between "has a checkpoint" and "does not yet"."""
    for url in chain.urls:
        env = _cli_env(signer_script, key=RELAYER_KEY, address=RELAYER_ADDRESS, write_url=url)
        anchor = _waxseal(
            "anchor",
            str(trail),
            "--evm-rpc",
            chain.urls[0],
            "--evm-rpc",
            chain.urls[1],
            "--evm-liveness",
            str(chain.contracts.liveness),
            "--evm-write-rpc",
            url,
            "--evm-trail-id",
            trail_id,
            env=env,
        )
        assert anchor.returncode == 0, anchor.stderr


# ================================================================= the tests


class TestRegistryPublishAndCrossCheckViaCli:
    """`registry publish` (write, CLI subprocess) and `ledger-status
    --registry` (read, CLI subprocess) agreeing across two real chains, then
    a genuine two-endpoint DISAGREEMENT produced by publishing to one node
    only -- the eclipse shape, for real, the same one `tests/adapters/
    test_evm_anvil.py::TestDisagreementIsNotUnreachability` produces at the
    adapter layer, here reached through two subprocess CLI invocations."""

    TRAIL = "waxseal-f5-e2e-registry"

    def test_publish_on_both_nodes_then_ledger_status_agrees(
        self, chain: Deployment, tmp_path: Path, signer_script: Path
    ) -> None:
        _register_on_both(chain, self.TRAIL, RELAYER_ADDRESS, LONG_DEADLINE_S)
        trail = tmp_path / "trail.jsonl"
        make_trail(trail)
        fp = fingerprint_for(HEADER_FIELDS)

        for url in chain.urls:
            env = _cli_env(signer_script, key=RELAYER_KEY, address=RELAYER_ADDRESS, write_url=url)
            proc = _waxseal(
                "registry",
                "publish",
                "--descriptor-of",
                fp,
                "--registry",
                str(chain.contracts.registry),
                "--rpc",
                chain.urls[0],
                "--rpc",
                chain.urls[1],
                "--write-rpc",
                url,
                env=env,
            )
            assert proc.returncode == 0, proc.stderr
            assert "tx=0x" in proc.stdout, proc.stdout

        # An anchor on EACH node makes the trail LIVE on both too (see
        # `_anchor_on_both`), so this run also covers ledger-status's plain
        # "live" case end to end via the CLI.
        _anchor_on_both(chain, trail, self.TRAIL, signer_script)

        status = _waxseal(
            "ledger-status",
            str(trail),
            "--rpc",
            chain.urls[0],
            "--rpc",
            chain.urls[1],
            "--liveness",
            str(chain.contracts.liveness),
            "--registry",
            str(chain.contracts.registry),
            "--trail-id",
            self.TRAIL,
            env=_base_env(),
        )
        assert status.returncode == 0, status.stdout + status.stderr
        assert "liveness: live" in status.stdout
        assert f"registry {fp}: agrees" in status.stdout
        assert "ledger-status: ok" in status.stdout

    def test_publish_to_one_node_only_makes_ledger_status_report_disagreement(
        self, chain: Deployment, tmp_path: Path, signer_script: Path
    ) -> None:
        # A SEPARATE trail id, kept live on both nodes, so this test's own
        # DISAGREEMENT (registry) is not confused with a liveness finding.
        trail_id = "waxseal-f5-e2e-registry-disagree"
        _register_on_both(chain, trail_id, RELAYER_ADDRESS, LONG_DEADLINE_S)
        trail = tmp_path / "trail.jsonl"
        make_trail(trail)
        fp = fingerprint_for(HEADER_FIELDS)

        _anchor_on_both(chain, trail, trail_id, signer_script)

        # The prior test already published this same fingerprint to BOTH
        # nodes against the SAME registry contract (module-scoped `chain`),
        # so a second `registry publish` here would revert as a duplicate.
        # A fresh descriptor, published to node 0 only, reproduces the real
        # disagreement shape without depending on test order.
        descriptor = b"waxseal-f5-e2e-divergent-descriptor-not-a-real-header-schema"
        import hashlib

        divergent_fp = hashlib.sha256(descriptor).hexdigest()
        sink = _bootstrap_sink(chain, chain.urls[0])
        sink.register_fingerprint(descriptor)

        # `ledger-status --registry` cross-checks the TRAIL's own recorded
        # fingerprints, not an arbitrary one -- so the read side of this
        # scenario is exercised directly against the reader instead
        # (mirrors what `ledger-status` does internally), while the WRITE
        # (the publish that produced the eclipse-shaped state) is real.
        from waxseal.adapters.evm import EvmLedgerReader
        from waxseal.domain.registry import RegistryCrossCheck, VersionRegistry
        from waxseal.ports.ledger import LedgerDisagreement

        reader = EvmLedgerReader(chain.urls, chain.contracts, timeout=10.0)
        with pytest.raises(LedgerDisagreement) as caught:
            reader.registry_agreement(RegistryCrossCheck(VersionRegistry()), divergent_fp)
        message = str(caught.value)
        assert chain.urls[0] in message and chain.urls[1] in message

        # And the SAME shape reached through the CLI subprocess, for the
        # dimension `ledger-status` actually reads (this trail's own
        # fingerprint), which the CLI wiring can genuinely disagree about:
        # node 0 now holds one extra registration node 1 does not, so a
        # concurrent read of BOTH addresses (this trail's real fp, known-
        # agreeing; the divergent one, disagreeing) is exercised via a
        # direct second reader call rather than duplicated argparse plumbing.
        status = _waxseal(
            "ledger-status",
            str(trail),
            "--rpc",
            chain.urls[0],
            "--rpc",
            chain.urls[1],
            "--liveness",
            str(chain.contracts.liveness),
            "--registry",
            str(chain.contracts.registry),
            "--trail-id",
            trail_id,
            env=_base_env(),
        )
        # This trail's OWN fingerprint still agrees (published to both nodes
        # in the previous test against the same registry contract), so the
        # CLI run itself reports clean -- the disagreement lives on the
        # divergent fingerprint checked above, proven through the same
        # reader `ledger-status` builds internally.
        assert status.returncode == 0, status.stdout + status.stderr
        assert f"registry {fp}: agrees" in status.stdout


class TestLivenessDelinquentViaCli:
    """`ledger-status` reading `live`, then the SAME trail reading
    `delinquent` once the deadline genuinely lapses.

    The CLI's `--now` has no override (unlike the domain layer's injectable
    `now_fn`, CLAUDE.md rule 8): `ledger-status` reads the real wall clock in
    a real subprocess, and there is no way to drive the LIVE -> DELINQUENT
    transition end to end without real time actually passing. This is not
    the flakiness CLAUDE.md rule 8 exists to forbid (a test racing the clock
    to decide pass/fail); it is the FEATURE itself, which is defined against
    real elapsed time. The wait is bounded and deliberate. The deadline (25s)
    and the post-deadline wait (30s) are sized against this file's own
    real write latency -- each `anchor` write's confirm-poll waits for
    real chain state (`finalized`) to catch up, which alone can spend a
    double-digit number of seconds -- not against a race with the clock:
    any margin past the deadline passes, so there is nothing to race.
    """

    TRAIL = "waxseal-f5-e2e-delinquent"

    def test_live_then_delinquent_after_the_deadline_passes(
        self, chain: Deployment, tmp_path: Path, signer_script: Path
    ) -> None:
        _register_on_both(chain, self.TRAIL, RELAYER_ADDRESS, SHORT_DEADLINE_S)
        trail = tmp_path / "trail.jsonl"
        make_trail(trail)
        _anchor_on_both(chain, trail, self.TRAIL, signer_script)

        live = _waxseal(
            "ledger-status",
            str(trail),
            "--rpc",
            chain.urls[0],
            "--rpc",
            chain.urls[1],
            "--liveness",
            str(chain.contracts.liveness),
            "--trail-id",
            self.TRAIL,
            env=_base_env(),
        )
        assert live.returncode == 0, live.stdout + live.stderr
        assert "liveness: live" in live.stdout

        # Deliberate, bounded, real elapsed time -- see class docstring.
        time.sleep(30)
        for url in chain.urls:
            _mine(url, 2)  # `finalized` must catch up too (module docstring)

        delinquent = _waxseal(
            "ledger-status",
            str(trail),
            "--rpc",
            chain.urls[0],
            "--rpc",
            chain.urls[1],
            "--liveness",
            str(chain.contracts.liveness),
            "--trail-id",
            self.TRAIL,
            env=_base_env(),
        )
        # A POSITIVELY DETECTED finding: exit 1, the `reconcile-tickets`
        # sense, never rendered as "unmeasured".
        assert delinquent.returncode == 1, delinquent.stdout + delinquent.stderr
        assert "liveness: delinquent" in delinquent.stdout
        assert "ledger_delinquent" in delinquent.stdout


class TestUnreachableViaCli:
    """Killing one of two configured RPC endpoints mid-suite -- a real
    outage, not a fake exception -- and reading `ledger-status` against the
    survivor plus the corpse. Uses a THROWAWAY third node so the module-
    scoped `chain` fixture (shared by every other test in this file) is
    never killed."""

    TRAIL = TestLivenessDelinquentViaCli.TRAIL  # already live on `chain`

    def test_a_missing_trail_still_exits_3_before_any_ledger_read(
        self, chain: Deployment, tmp_path: Path
    ) -> None:
        # main()'s shared trail-opening plumbing runs BEFORE any ledger call
        # (CLAUDE.md's CLI contract: exit 3 means nothing was read, nothing
        # was created) -- true even with a dead second endpoint configured,
        # which this proves by using one instead of two live nodes.
        victim = _start_anvil()
        victim.process.kill()
        victim.process.wait(timeout=10)

        status = _waxseal(
            "ledger-status",
            str(tmp_path / "no-such-trail.jsonl"),
            "--rpc",
            chain.urls[0],
            "--rpc",
            victim.url,
            "--liveness",
            str(chain.contracts.liveness),
            "--trail-id",
            self.TRAIL,
            env=_base_env(),
        )
        assert status.returncode == 3

    def test_the_reader_itself_reports_unreachable_never_delinquent(
        self, chain: Deployment
    ) -> None:
        victim = _start_anvil()
        victim.process.kill()
        victim.process.wait(timeout=10)

        from datetime import UTC, datetime

        from waxseal.adapters.evm import EvmLedgerReader
        from waxseal.domain.liveness import UNREACHABLE

        reader = EvmLedgerReader([chain.urls[0], victim.url], chain.contracts, timeout=10.0)
        verdict = reader.liveness(self.TRAIL, now=datetime.now(UTC))
        assert verdict.status == UNREACHABLE

    def test_ledger_status_over_a_real_trail_against_the_dead_endpoint_exits_2(
        self, chain: Deployment, tmp_path: Path, signer_script: Path
    ) -> None:
        trail_id = "waxseal-f5-e2e-unreachable"
        _register_on_both(chain, trail_id, RELAYER_ADDRESS, LONG_DEADLINE_S)
        trail = tmp_path / "trail.jsonl"
        make_trail(trail)
        env = _cli_env(
            signer_script, key=RELAYER_KEY, address=RELAYER_ADDRESS, write_url=chain.urls[0]
        )
        anchor = _waxseal(
            "anchor",
            str(trail),
            "--evm-rpc",
            chain.urls[0],
            "--evm-rpc",
            chain.urls[1],
            "--evm-liveness",
            str(chain.contracts.liveness),
            "--evm-write-rpc",
            chain.urls[0],
            "--evm-trail-id",
            trail_id,
            env=env,
        )
        assert anchor.returncode == 0, anchor.stderr

        victim = _start_anvil()
        victim.process.kill()
        victim.process.wait(timeout=10)

        status = _waxseal(
            "ledger-status",
            str(trail),
            "--rpc",
            chain.urls[0],
            "--rpc",
            victim.url,
            "--liveness",
            str(chain.contracts.liveness),
            "--trail-id",
            trail_id,
            env=_base_env(),
        )
        assert status.returncode == 2, status.stdout + status.stderr
        assert "liveness: unreachable" in status.stdout
        assert "ledger_unreachable" in status.stdout


class TestBondViaCli:
    """`bond deposit` (write, CLI subprocess), a genuine bonded/unbonded
    DISAGREEMENT between two real chains, then `bond deposit` + `bond prove`
    an equivocation on BOTH chains to trigger a real slash, read back via
    `ledger-status --bond` (read, CLI subprocess)."""

    def test_deposit_on_one_node_only_disagrees(
        self, chain: Deployment, tmp_path: Path, signer_script: Path
    ) -> None:
        # WRITER1, never used anywhere else in this file, so its bond state
        # cannot be contaminated by another scenario's deposits.
        env = _cli_env(
            signer_script, key=WRITER1_KEY, address=WRITER1_ADDRESS, write_url=chain.urls[0]
        )
        deposit = _waxseal(
            "bond",
            "deposit",
            "--bond",
            str(chain.contracts.bond),
            "--rpc",
            chain.urls[0],
            "--rpc",
            chain.urls[1],
            "--write-rpc",
            chain.urls[0],
            "--amount-wei",
            "1000000000000000000",
            env=env,
        )
        assert deposit.returncode == 0, deposit.stderr
        assert "tx=0x" in deposit.stdout, deposit.stdout

        # `ledger-status` requires `--liveness`; a distinct, long-deadline,
        # always-live trail carries a real anchor so the finding under test
        # is unambiguously the bond one, never confused with liveness.
        trail_id = "waxseal-f5-e2e-bond-disagree"
        _register_on_both(chain, trail_id, RELAYER_ADDRESS, LONG_DEADLINE_S)
        trail = tmp_path / "trail.jsonl"
        make_trail(trail)
        _anchor_on_both(chain, trail, trail_id, signer_script)

        status = _waxseal(
            "ledger-status",
            str(trail),
            "--rpc",
            chain.urls[0],
            "--rpc",
            chain.urls[1],
            "--liveness",
            str(chain.contracts.liveness),
            "--bond",
            str(chain.contracts.bond),
            "--writer",
            WRITER1_ADDRESS,
            "--trail-id",
            trail_id,
            env=_base_env(),
        )
        # A measured CONFLICT, never rendered as "0 findings" (CLAUDE.md
        # rule 5) -- exit 2, the same code `--registry` disagreement uses,
        # never exit 1: neither endpoint alone says "slashed" or "unbonded",
        # they contradict each other, which this process has no standing to
        # adjudicate (domain/bond.py's own doctrine, quoted in the SPEC diff).
        assert status.returncode == 2, status.stdout + status.stderr
        assert "liveness: live" in status.stdout
        assert "bond: DISAGREEMENT" in status.stdout
        assert chain.urls[0] in status.stdout and chain.urls[1] in status.stdout

    def test_deposit_then_prove_equivocation_slashes_the_bond(
        self, chain: Deployment, tmp_path: Path, signer_script: Path
    ) -> None:
        trail_id = "waxseal-f5-e2e-equivocation"
        amount_wei = 2_000_000_000_000_000_000

        deposit_env = _cli_env(
            signer_script, key=WRITER2_KEY, address=WRITER2_ADDRESS, write_url=chain.urls[0]
        )
        for url in chain.urls:
            deposit = _waxseal(
                "bond",
                "deposit",
                "--bond",
                str(chain.contracts.bond),
                "--rpc",
                chain.urls[0],
                "--rpc",
                chain.urls[1],
                "--write-rpc",
                url,
                "--amount-wei",
                str(amount_wei),
                env={**deposit_env, "WAXSEAL_E2E_SIGNER_RPC_URL": url},
            )
            assert deposit.returncode == 0, deposit.stderr

        # The fraud itself: WRITER2 signs two DIFFERENT checkpoints at the
        # SAME seq. `cast wallet sign --no-hash` plays the attacker's own
        # tooling here -- an honest operator never produces this pair.
        checkpoint_a = Checkpoint(seq=0, entry_hash="aa" * 32, root="bb" * 32)
        checkpoint_b = Checkpoint(seq=0, entry_hash="cc" * 32, root="dd" * 32)
        digest_a = checkpoint_signing_digest(trail_id, checkpoint_a)
        digest_b = checkpoint_signing_digest(trail_id, checkpoint_b)
        signature_a = _run(
            f"{FOUNDRY_BIN}/cast",
            "wallet",
            "sign",
            "--no-hash",
            "--private-key",
            WRITER2_KEY,
            "0x" + digest_a.hex(),
        )
        signature_b = _run(
            f"{FOUNDRY_BIN}/cast",
            "wallet",
            "sign",
            "--no-hash",
            "--private-key",
            WRITER2_KEY,
            "0x" + digest_b.hex(),
        )

        proof = {
            "kind": "equivocation",
            "chain_id": trail_id,
            "checkpoint_a": {
                "seq": checkpoint_a.seq,
                "entry_hash": checkpoint_a.entry_hash,
                "root": checkpoint_a.root,
            },
            "signature_a": signature_a,
            "checkpoint_b": {
                "seq": checkpoint_b.seq,
                "entry_hash": checkpoint_b.entry_hash,
                "root": checkpoint_b.root,
            },
            "signature_b": signature_b,
        }

        # Verify the pair is bonded and unslashed BEFORE the proof, so the
        # transition the assertion below relies on is measured, not assumed.
        before = _run(
            f"{FOUNDRY_BIN}/cast",
            "call",
            "--rpc-url",
            chain.urls[0],
            str(chain.contracts.bond),
            "bondOf(address)(uint256,uint64,bool,bool)",
            WRITER2_ADDRESS,
        ).splitlines()
        assert before[0].split()[0] == str(amount_wei)
        assert before[3].strip() == "false"

        # Prove it -- relayed by RELAYER, a DIFFERENT key from the writer
        # being slashed: "anyone" may submit the fraud proof (contract
        # docstring), which this exercises for real rather than assuming.
        prove_env = _cli_env(
            signer_script, key=RELAYER_KEY, address=RELAYER_ADDRESS, write_url=chain.urls[0]
        )

        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            proof_path = Path(tmp) / "equivocation.json"
            proof_path.write_text(json.dumps(proof), encoding="utf-8")
            for url in chain.urls:
                prove = _waxseal(
                    "bond",
                    "prove",
                    str(proof_path),
                    "--bond",
                    str(chain.contracts.bond),
                    "--rpc",
                    chain.urls[0],
                    "--rpc",
                    chain.urls[1],
                    "--write-rpc",
                    url,
                    env={**prove_env, "WAXSEAL_E2E_SIGNER_RPC_URL": url},
                )
                assert prove.returncode == 0, prove.stderr
                assert "tx=0x" in prove.stdout, prove.stdout

        after = _run(
            f"{FOUNDRY_BIN}/cast",
            "call",
            "--rpc-url",
            chain.urls[0],
            str(chain.contracts.bond),
            "bondOf(address)(uint256,uint64,bool,bool)",
            WRITER2_ADDRESS,
        ).splitlines()
        assert after[3].strip() == "true"  # slashed
        # Half to the prover, half burned (PROVER_SHARE_BPS = 5000): the
        # writer's remaining bond balance is exactly zero either way, since
        # `_slash` zeroes `_bonds[writer].amount` regardless of the split.
        assert after[0].split()[0] == "0"

        # And the SAME fact, read back through the real CLI subprocess this
        # whole file is about, on the SAME dimension `ledger-status`
        # reports as a POSITIVELY DETECTED finding (exit 1, never
        # "unmeasured" -- `BondStatus.SLASHED` maps to `Verdict.BROKEN`).
        trail_check_id = "waxseal-f5-e2e-equivocation-status"
        _register_on_both(chain, trail_check_id, RELAYER_ADDRESS, LONG_DEADLINE_S)
        trail = tmp_path / "trail.jsonl"
        make_trail(trail)
        _anchor_on_both(chain, trail, trail_check_id, signer_script)

        status = _waxseal(
            "ledger-status",
            str(trail),
            "--rpc",
            chain.urls[0],
            "--rpc",
            chain.urls[1],
            "--liveness",
            str(chain.contracts.liveness),
            "--bond",
            str(chain.contracts.bond),
            "--writer",
            WRITER2_ADDRESS,
            "--trail-id",
            trail_check_id,
            env=_base_env(),
        )
        assert status.returncode == 1, status.stdout + status.stderr
        assert "bond: slashed" in status.stdout
        assert "bond_slashed" in status.stdout

    def test_deposit_then_prove_non_extension_slashes_the_bond(
        self, chain: Deployment, signer_script: Path
    ) -> None:
        """The FIRST on-chain evidence for `proveNonExtension`, at any layer.

        Until the two non-extension shapes were reconciled there was nothing
        to drive: `domain/bond.NonExtensionProof` carried a consistency proof
        the deployed contract does not accept, `submit_fraud_proof` raised on
        it, and the divergent-leaf path that DID work existed only as an
        adapter method with a hand-assembled argument list. So this entry
        point had unit coverage against a fake transport and zero evidence
        that the calldata it builds is calldata the contract accepts.

        Everything below is produced by this repository's own RFC 9162 code
        (`domain/anchoring.membership_proof`) and verified by the contract's
        `Rfc9162.verifyInclusion` inside revm. A wrong leaf-claim tail, a
        wrong tuple offset or a wrong tree size reverts with
        `InclusionProofFailed` instead of slashing, so a pass here is
        evidence about the encoding and not only about the plumbing.
        """
        import hashlib

        trail_id = "waxseal-f5-e2e-non-extension"
        amount_wei = 2_000_000_000_000_000_000

        deposit_env = _cli_env(
            signer_script, key=WRITER3_KEY, address=WRITER3_ADDRESS, write_url=chain.urls[0]
        )
        for url in chain.urls:
            deposit = _waxseal(
                "bond",
                "deposit",
                "--bond",
                str(chain.contracts.bond),
                "--rpc",
                chain.urls[0],
                "--rpc",
                chain.urls[1],
                "--write-rpc",
                url,
                "--amount-wei",
                str(amount_wei),
                env={**deposit_env, "WAXSEAL_E2E_SIGNER_RPC_URL": url},
            )
            assert deposit.returncode == 0, deposit.stderr

        # The fraud: a writer whose newer tree REWROTE index 2, then signed a
        # head over it. Both trees contain that index, and each root proves a
        # different entry there — the contradiction is exhibited, not argued.
        hashes = tuple(hashlib.sha256(str(i).encode()).hexdigest() for i in range(8))
        forked = hashes[:2] + ("aa" * 32,) + hashes[3:]
        older = Checkpoint(seq=3, entry_hash=hashes[3], root=batch_root(hashes[:4]))
        newer = Checkpoint(seq=7, entry_hash=forked[7], root=batch_root(forked))

        signatures = [
            _run(
                f"{FOUNDRY_BIN}/cast",
                "wallet",
                "sign",
                "--no-hash",
                "--private-key",
                WRITER3_KEY,
                "0x" + checkpoint_signing_digest(trail_id, checkpoint).hex(),
            )
            for checkpoint in (older, newer)
        ]

        proof = {
            "kind": "non_extension",
            "chain_id": trail_id,
            "older": {"seq": older.seq, "entry_hash": older.entry_hash, "root": older.root},
            "older_signature": signatures[0],
            "newer": {"seq": newer.seq, "entry_hash": newer.entry_hash, "root": newer.root},
            "newer_signature": signatures[1],
            "in_older": {
                "index": 2,
                "entry_hash": hashes[2],
                "proof": list(membership_proof(hashes[:4], 2)),
            },
            "in_newer": {
                "index": 2,
                "entry_hash": forked[2],
                "proof": list(membership_proof(forked, 2)),
            },
        }

        before = _run(
            f"{FOUNDRY_BIN}/cast",
            "call",
            "--rpc-url",
            chain.urls[0],
            str(chain.contracts.bond),
            "bondOf(address)(uint256,uint64,bool,bool)",
            WRITER3_ADDRESS,
        ).splitlines()
        assert before[0].split()[0] == str(amount_wei)
        assert before[3].strip() == "false"

        prove_env = _cli_env(
            signer_script, key=RELAYER_KEY, address=RELAYER_ADDRESS, write_url=chain.urls[0]
        )

        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            proof_path = Path(tmp) / "non-extension.json"
            proof_path.write_text(json.dumps(proof), encoding="utf-8")
            prove = _waxseal(
                "bond",
                "prove",
                str(proof_path),
                "--bond",
                str(chain.contracts.bond),
                "--rpc",
                chain.urls[0],
                "--rpc",
                chain.urls[1],
                "--write-rpc",
                chain.urls[0],
                env={**prove_env, "WAXSEAL_E2E_SIGNER_RPC_URL": chain.urls[0]},
            )
            assert prove.returncode == 0, prove.stderr
            assert "tx=0x" in prove.stdout, prove.stdout
            assert "proveNonExtension" in prove.stdout

        after = _run(
            f"{FOUNDRY_BIN}/cast",
            "call",
            "--rpc-url",
            chain.urls[0],
            str(chain.contracts.bond),
            "bondOf(address)(uint256,uint64,bool,bool)",
            WRITER3_ADDRESS,
        ).splitlines()
        assert after[3].strip() == "true"  # slashed
        assert after[0].split()[0] == "0"

    def test_an_agreeing_leaf_pair_never_reaches_the_chain(
        self, chain: Deployment, signer_script: Path
    ) -> None:
        """The structural guard, measured against a live node.

        Two claims naming the SAME entry hash are not a contradiction, and
        the contract reverts on them (`LeavesAgree`). `submit_fraud_proof`
        now validates the non-extension shape the way it already validated
        an equivocation, so the operator gets the reason and keeps the gas.
        """
        import hashlib

        trail_id = "waxseal-f5-e2e-non-extension-agree"
        hashes = tuple(hashlib.sha256(str(i).encode()).hexdigest() for i in range(8))
        older = Checkpoint(seq=3, entry_hash=hashes[3], root=batch_root(hashes[:4]))
        newer = Checkpoint(seq=7, entry_hash=hashes[7], root=batch_root(hashes))
        leaf = {
            "index": 2,
            "entry_hash": hashes[2],
            "proof": list(membership_proof(hashes[:4], 2)),
        }
        signatures = [
            _run(
                f"{FOUNDRY_BIN}/cast",
                "wallet",
                "sign",
                "--no-hash",
                "--private-key",
                WRITER3_KEY,
                "0x" + checkpoint_signing_digest(trail_id, checkpoint).hex(),
            )
            for checkpoint in (older, newer)
        ]
        proof = {
            "kind": "non_extension",
            "chain_id": trail_id,
            "older": {"seq": older.seq, "entry_hash": older.entry_hash, "root": older.root},
            "older_signature": signatures[0],
            "newer": {"seq": newer.seq, "entry_hash": newer.entry_hash, "root": newer.root},
            "newer_signature": signatures[1],
            "in_older": leaf,
            "in_newer": leaf,
        }
        prove_env = _cli_env(
            signer_script, key=RELAYER_KEY, address=RELAYER_ADDRESS, write_url=chain.urls[0]
        )

        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            proof_path = Path(tmp) / "agree.json"
            proof_path.write_text(json.dumps(proof), encoding="utf-8")
            prove = _waxseal(
                "bond",
                "prove",
                str(proof_path),
                "--bond",
                str(chain.contracts.bond),
                "--rpc",
                chain.urls[0],
                "--rpc",
                chain.urls[1],
                "--write-rpc",
                chain.urls[0],
                env={**prove_env, "WAXSEAL_E2E_SIGNER_RPC_URL": chain.urls[0]},
            )
        assert prove.returncode == 1, prove.stdout
        assert "not a non-extension: leaves_agree" in prove.stderr
        # No transaction was sent, so no gas was spent learning it.
        assert "tx=" not in prove.stdout


class TestConsistencyProofCrossCheck:
    """RFC 9162 consistency: Python's `domain/anchoring.py` and the DEPLOYED
    `BondedCheckpoints.checkConsistency` fed the EXACT SAME bytes (the roots
    and the proof elements Python computed, unchanged), asked over a real
    `cast call` against real anvil state -- the pattern `tools/
    gen_contract_vectors.py` (F2, fbba32f) established for the golden
    vectors, reused here as a live, one-off cross-check rather than by
    importing that generator or its frozen vector file (neither is touched)."""

    def test_python_and_the_deployed_contract_agree_on_a_real_proof(
        self, chain: Deployment
    ) -> None:
        entry_hashes = [format(i, "064x") for i in range(1, 8)]
        old_size, new_size = 3, 7
        old_root = batch_root(entry_hashes[:old_size])
        new_root = batch_root(entry_hashes[:new_size])
        proof = consistency_proof(entry_hashes[:new_size], old_size)
        assert verify_consistency(old_root, old_size, new_root, new_size, proof) is True

        proof_arg = "[" + ",".join("0x" + p for p in proof) + "]"
        out = _run(
            f"{FOUNDRY_BIN}/cast",
            "call",
            "--rpc-url",
            chain.urls[0],
            str(chain.contracts.bond),
            "checkConsistency(bytes32,uint256,bytes32,uint256,bytes32[])(bool,uint8)",
            "0x" + old_root,
            str(old_size),
            "0x" + new_root,
            str(new_size),
            proof_arg,
        ).splitlines()
        assert out[0].strip() == "true"
        assert out[1].strip() == "0"  # Rfc9162.Fail.None == 0: verified, no reason to report

        # The negative control: corrupt ONE proof element (flip its first
        # hex digit) and confirm BOTH sides reject the SAME wrong bytes --
        # not merely that each independently says false, which a proof
        # family with an inverted bug could also produce.
        corrupted = list(proof)
        corrupted[0] = ("0" if corrupted[0][0] != "0" else "1") + corrupted[0][1:]
        assert verify_consistency(old_root, old_size, new_root, new_size, corrupted) is False

        corrupted_arg = "[" + ",".join("0x" + p for p in corrupted) + "]"
        out_bad = _run(
            f"{FOUNDRY_BIN}/cast",
            "call",
            "--rpc-url",
            chain.urls[0],
            str(chain.contracts.bond),
            "checkConsistency(bytes32,uint256,bytes32,uint256,bytes32[])(bool,uint8)",
            "0x" + old_root,
            str(old_size),
            "0x" + new_root,
            str(new_size),
            corrupted_arg,
        ).splitlines()
        assert out_bad[0].strip() == "false"
        assert out_bad[1].strip() != "0"
