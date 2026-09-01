"""End-to-end: the EVM adapter against F2's contracts on two real anvil chains.

This is the strongest evidence available for this adapter, and it only became
possible when F1 and F2 both landed. Everything the fake-transport suite
asserts about decoding, it asserts against bytes this repository wrote. Here
the bytes come from `solc`-compiled Solidity executing in revm, so the things
that cannot be faked are the ones under test:

  * the `TrailNotRegistered` revert is the CONTRACT's, four bytes this file
    never spells — if `ERROR_TRAIL_NOT_REGISTERED` were wrong, the read would
    degrade to `unreachable` instead of reporting absence;
  * the checkpoint signing digest is recomputed IN SOLIDITY
    (`CheckpointCodec.signingDigest`) and `ecrecover`ed against the
    registered writer, so a submit that lands proves Python's
    `checkpoint_signing_digest` and the contract agree byte for byte;
  * every selector is exercised by a node that would revert on a wrong one.

TWO CHAINS, NOT ONE. Both anvils run the default mnemonic and receive the
same deployment transactions in the same order, so the three contracts get
identical addresses on both — which makes a genuine two-endpoint cross-check
possible rather than the same node asked twice. Divergence is then produced
on purpose (a descriptor registered on one chain only) and the reader is
required to refuse to pick a winner.

If Foundry is absent every test here SKIPS WITH A LABEL naming what is
missing. It never silently passes, and it is never the coverage: the
fake-transport suite covers adapters/evm.py on its own.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import time
import urllib.request
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from waxseal.adapters.evm import (
    SELECTOR_REGISTER_TRAIL,
    EvmAnchorSink,
    EvmContracts,
    EvmLedgerReader,
    EvmLedgerSink,
)
from waxseal.domain.abi import encode_address, encode_bytes32, encode_call, encode_uint
from waxseal.domain.bond import (
    BONDED,
    UNBONDED,
    Checkpoint,
    checkpoint_signing_digest,
    trail_id_for,
)
from waxseal.domain.fingerprint import HEADER_FIELDS, fingerprint_for
from waxseal.domain.liveness import DELINQUENT, LIVE, NO_CHECKPOINT_ON_LEDGER, UNREACHABLE
from waxseal.domain.registry import (
    REGISTRY_AGREES,
    RegistryCrossCheck,
    VersionRegistry,
    descriptor_frame,
)
from waxseal.ports.ledger import LedgerDisagreement, LedgerError, LedgerUnreachable

CONTRACTS = Path(__file__).resolve().parents[2] / "contracts"

# anvil's first default account. A publicly documented dev key on a throwaway
# chain: it is in every Foundry tutorial and controls nothing.
DEV_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
DEV_ADDRESS = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

DEADLINE_S = 3600
TRAIL = "waxseal-f3-e2e"


def _foundry_bin() -> str | None:
    """Foundry's directory, from PATH or from its default install location.

    The installer does not always edit the shell profile, so `shutil.which`
    alone reports Foundry missing on a machine that has it — and this file
    would skip while the evidence it exists to collect was available.
    """
    if shutil.which("anvil") and shutil.which("forge") and shutil.which("cast"):
        return os.path.dirname(str(shutil.which("anvil")))
    default = Path.home() / ".foundry" / "bin"
    if all((default / tool).exists() for tool in ("anvil", "forge", "cast")):
        return str(default)
    return None


FOUNDRY_BIN = _foundry_bin()

pytestmark = pytest.mark.skipif(
    FOUNDRY_BIN is None,
    reason=(
        "SKIPPED WITH LABEL: Foundry (anvil/forge/cast 1.8.x) is not on PATH and not in "
        "~/.foundry/bin, so the on-chain end-to-end evidence for adapters/evm.py was NOT "
        "collected on this run. Install with `foundryup`. The fake-transport suite in "
        "tests/adapters/test_evm.py still ran and still covers the adapter."
    ),
)


def _env() -> dict[str, str]:
    env = dict(os.environ)
    env["PATH"] = f"{env.get('PATH', '')}:{FOUNDRY_BIN}"
    return env


def _run(*args: str, cwd: Path | None = None) -> str:
    done = subprocess.run(
        list(args), cwd=cwd, env=_env(), capture_output=True, text=True, timeout=180
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


def _mine(url: str, blocks: int = 1) -> None:
    _rpc(url, "anvil_mine", [hex(blocks)])


def _cast_send(url: str, to: str, calldata: bytes) -> None:
    """Send one transaction WITHOUT the adapter, and wait for it as `cast`
    does. Used only where the sink's own finality wait would perturb what the
    test is measuring — mining blocks to reach `finalized` is exactly what the
    block-tag test needs not to happen."""
    _run(
        f"{FOUNDRY_BIN}/cast",
        "send",
        "--rpc-url",
        url,
        "--private-key",
        DEV_KEY,
        to,
        "0x" + calldata.hex(),
    )


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
    # --slots-in-an-epoch 1 is what makes `finalized` advance at all on a dev
    # chain; without it the tag sits at genesis and every read at the adapter's
    # default block tag would report an empty world.
    process = subprocess.Popen(
        [
            f"{FOUNDRY_BIN}/anvil",
            "--port",
            str(port),
            "--slots-in-an-epoch",
            "1",
            "--silent",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=_env(),
    )
    url = f"http://127.0.0.1:{port}"
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            _rpc(url, "eth_chainId", [])
            return Node(url=url, process=process)
        except Exception:  # noqa: BLE001 - the node is simply not up yet
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
        DEV_KEY,
        "--broadcast",
        "--json",
        f"src/{contract}.sol:{contract}",
        *(("--constructor-args", *constructor_args) if constructor_args else ()),
        cwd=CONTRACTS,
    )
    # forge prints compiler chatter before the JSON on a cold build, and
    # pretty-prints the object across several lines, so neither "the last
    # line" nor "the line starting with {" finds it.
    payload = json.loads(out[out.index("{") : out.rindex("}") + 1])
    return str(payload["deployedTo"])


class CastSigner:
    """A `TransactionSigner` that shells out to `cast`.

    Exactly the shape the design intends an operator to supply: waxseal
    assembles the transaction fields and the digest, and something outside
    the process holds the key. Nothing in `src/waxseal` imports a crypto
    library, and `cast` here stands in for `eth-account`, an HSM or a remote
    signing service without changing a line of the adapter.
    """

    address = DEV_ADDRESS
    public_id = DEV_ADDRESS

    def sign(self, digest32: bytes) -> bytes:
        # --no-hash: the contract recomputes a RAW sha256 digest, so a wallet
        # that prefixed "\\x19Ethereum Signed Message" would not recover.
        signature = _run(
            f"{FOUNDRY_BIN}/cast",
            "wallet",
            "sign",
            "--no-hash",
            "--private-key",
            DEV_KEY,
            "0x" + digest32.hex(),
        )
        return bytes.fromhex(signature[2:])

    def sign_transaction(self, fields: Mapping[str, object]) -> bytes:
        raw = _run(
            f"{FOUNDRY_BIN}/cast",
            "mktx",
            "--private-key",
            DEV_KEY,
            "--rpc-url",
            str(fields["_rpc_url"]),
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


class UrlCarryingSigner(CastSigner):
    """`cast mktx` wants an RPC URL; the adapter's field dict does not carry
    one, and it should not — a transaction's fields are chain state, not a
    transport detail. The test signer knows its own endpoint instead."""

    def __init__(self, url: str) -> None:
        self._url = url

    def sign_transaction(self, fields: Mapping[str, object]) -> bytes:
        return super().sign_transaction({**fields, "_rpc_url": self._url})


@dataclass
class Deployment:
    nodes: tuple[Node, Node]
    contracts: EvmContracts

    @property
    def urls(self) -> tuple[str, str]:
        return (self.nodes[0].url, self.nodes[1].url)


@pytest.fixture(scope="module")
def chain() -> Iterator[Deployment]:
    nodes = (_start_anvil(), _start_anvil())
    try:
        addresses: list[EvmContracts] = []
        for node in nodes:
            registry = _deploy(node.url, "FingerprintRegistry")
            liveness = _deploy(node.url, "AnchoringLiveness")
            bond = _deploy(node.url, "BondedCheckpoints", str(DEADLINE_S))
            addresses.append(EvmContracts(liveness=liveness, registry=registry, bond=bond))
        # Determinism is the whole basis of the cross-check: same key, same
        # nonce order, same CREATE addresses. If this ever failed, the two
        # endpoints would be reading different contracts and "agreement"
        # would mean nothing.
        assert addresses[0] == addresses[1], addresses
        yield Deployment(nodes=nodes, contracts=addresses[0])
    finally:
        for node in nodes:
            node.process.kill()
            node.process.wait(timeout=10)


def _reader(chain: Deployment, *, block_tag: str = "finalized") -> EvmLedgerReader:
    return EvmLedgerReader(chain.urls, chain.contracts, block_tag=block_tag, timeout=10.0)


def _sink(chain: Deployment, url: str) -> EvmLedgerSink:
    return EvmLedgerSink(
        _reader(chain),
        UrlCarryingSigner(url),
        rpc_url=url,
        # The injected sleep MINES rather than waits: on a dev chain nothing
        # else produces the blocks `finalized` needs to catch up, and
        # CLAUDE.md rule 8 says a test must never pass by sleeping.
        sleep_fn=lambda _seconds: _mine(url),
        max_polls=20,
    )


def _register_and_anchor(chain: Deployment, trail: str, checkpoint: Checkpoint) -> list[str]:
    receipts = []
    for url in chain.urls:
        sink = _sink(chain, url)
        sink.register_trail(trail, DEV_ADDRESS, DEADLINE_S)
        receipts.append(EvmAnchorSink(sink, trail, UrlCarryingSigner(url)).anchor(checkpoint))
    return receipts


# ================================================================= the tests


class TestAgreementAcrossTwoRealChains:
    def test_a_head_written_through_the_sink_is_read_back_from_both_nodes(
        self, chain: Deployment
    ) -> None:
        checkpoint = Checkpoint(seq=7, entry_hash="ab" * 32, root="cd" * 32)
        receipts = _register_and_anchor(chain, TRAIL, checkpoint)

        # The receipt locates the transaction without a lookup table.
        for receipt in receipts:
            kind, chain_id, block, tx_hash = receipt.split(":")
            assert (kind, chain_id) == ("evm", "31337")
            assert int(block) > 0 and len(tx_hash) == 66

        found = _reader(chain).latest_checkpoint(TRAIL)
        assert found is not None
        assert (found.seq, found.entry_hash, found.root) == (7, "ab" * 32, "cd" * 32)
        assert found.block_time > 0

    def test_the_submit_landing_proves_python_and_solidity_sign_the_same_bytes(
        self, chain: Deployment
    ) -> None:
        # AnchoringLiveness.submit ecrecovers CheckpointCodec.signingDigest
        # and reverts BadWriterSignature unless it equals the registered
        # writer. The head above therefore could not exist if
        # checkpoint_signing_digest disagreed with the Solidity by one byte.
        checkpoint = Checkpoint(seq=7, entry_hash="ab" * 32, root="cd" * 32)
        digest = checkpoint_signing_digest(TRAIL, checkpoint)
        assert len(digest) == 32
        assert _reader(chain).latest_checkpoint(TRAIL) is not None
        # And the trail id the contract keys by is the pinned reduction.
        seq = _run(
            f"{FOUNDRY_BIN}/cast",
            "call",
            "--rpc-url",
            chain.urls[0],
            str(chain.contracts.liveness),
            "lastSeen(bytes32)(uint64,bytes32,bytes32,uint64)",
            "0x" + trail_id_for(TRAIL).hex(),
        ).splitlines()[0]
        assert seq.strip() == "7"

    def test_the_deadline_agrees(self, chain: Deployment) -> None:
        assert _reader(chain).deadline_s(TRAIL) == DEADLINE_S

    def test_a_fresh_head_is_live(self, chain: Deployment) -> None:
        verdict = _reader(chain).liveness(TRAIL, now=datetime.now(UTC))
        assert verdict.status == LIVE
        assert verdict.deadline_s == DEADLINE_S

    def test_the_chains_own_verdict_agrees_that_the_trail_is_live(
        self, chain: Deployment
    ) -> None:
        assert _reader(chain).on_chain_delinquency(TRAIL) is False


class TestTheRevertIsAnAnswer:
    def test_an_unregistered_trail_reverts_and_is_read_as_absence(
        self, chain: Deployment
    ) -> None:
        # The four bytes come from the compiled contract, not from this file.
        # A wrong ERROR_TRAIL_NOT_REGISTERED would make this `unreachable`.
        assert _reader(chain).latest_checkpoint("no-such-trail") is None
        assert _reader(chain).deadline_s("no-such-trail") is None

    def test_is_delinquent_reverts_rather_than_lying_false(self, chain: Deployment) -> None:
        # bool is two-valued and the honest answer is three-valued: the
        # contract refuses to answer, and the adapter reports the third value.
        assert _reader(chain).on_chain_delinquency("no-such-trail") is None

    def test_an_unregistered_trail_has_nothing_to_be_late_against(
        self, chain: Deployment
    ) -> None:
        verdict = _reader(chain).liveness("no-such-trail", now=datetime.now(UTC))
        assert verdict.status == UNREACHABLE

    def test_registered_but_never_anchored_is_delinquent_not_unreachable(
        self, chain: Deployment
    ) -> None:
        trail = "registered-never-anchored"
        for url in chain.urls:
            _sink(chain, url).register_trail(trail, DEV_ADDRESS, DEADLINE_S)
        for url in chain.urls:
            _mine(url, 2)
        verdict = _reader(chain).liveness(trail, now=datetime.now(UTC))
        # lastSeen reverts (nothing recorded) while deadlineOf answers 3600:
        # a registered trail that has never anchored IS late, and the domain
        # says so from the measured absence the adapter reported.
        assert (verdict.status, verdict.reason) == (DELINQUENT, NO_CHECKPOINT_ON_LEDGER)


class TestTheRegistry:
    def test_a_real_descriptor_round_trips_and_the_cross_check_agrees(
        self, chain: Deployment
    ) -> None:
        descriptor = descriptor_frame(HEADER_FIELDS)
        for url in chain.urls:
            _sink(chain, url).register_fingerprint(descriptor)
        reader = _reader(chain)
        assert reader.registry_lookup(fingerprint_for(HEADER_FIELDS)) == descriptor
        finding = reader.registry_agreement(
            RegistryCrossCheck(VersionRegistry()), fingerprint_for(HEADER_FIELDS)
        )
        # The contract computed sha256(descriptor) itself; agreement here is
        # two independent SHA-256s over the same preimage matching.
        assert finding.status == REGISTRY_AGREES

    def test_an_unknown_fingerprint_is_absent_not_a_failure(self, chain: Deployment) -> None:
        assert _reader(chain).registry_lookup("ff" * 32) is None

    def test_a_duplicate_registration_is_rejected_by_the_contract(
        self, chain: Deployment
    ) -> None:
        # Append-only is the feature. On the WRITE path a revert is the
        # contract saying no — a positive rejection, not unreachability.
        with pytest.raises(LedgerError, match="the contract rejected this call"):
            _sink(chain, chain.urls[0]).register_fingerprint(descriptor_frame(HEADER_FIELDS))


class TestTheBond:
    def test_a_writer_that_never_deposited_is_unbonded(self, chain: Deployment) -> None:
        assert _reader(chain).bond(DEV_ADDRESS).status == UNBONDED

    def test_a_deposit_makes_the_writer_bonded(self, chain: Deployment) -> None:
        for url in chain.urls:
            _sink(chain, url).deposit_bond(10**16)
        found = _reader(chain).bond(DEV_ADDRESS)
        assert found.status == BONDED
        assert found.amount_wei == 10**16


class TestDisagreementIsNotUnreachability:
    def test_a_descriptor_on_one_chain_only_makes_the_reader_refuse_to_choose(
        self, chain: Deployment
    ) -> None:
        # The eclipse shape, produced for real: one endpoint has seen a
        # registration the other has not. A client that picked a winner here
        # is a client an adversary only has to be louder than.
        descriptor = b"waxseal-descriptor-v1\ndivergent-on-one-chain-only"
        _sink(chain, chain.urls[0]).register_fingerprint(descriptor)
        _mine(chain.urls[0], 2)
        import hashlib

        with pytest.raises(LedgerDisagreement) as caught:
            _reader(chain).registry_lookup(hashlib.sha256(descriptor).hexdigest())
        message = str(caught.value)
        assert chain.urls[0] in message and chain.urls[1] in message
        assert "None" in message  # the endpoint that has not seen it says so

    def test_a_disagreement_is_not_an_unreachable(self, chain: Deployment) -> None:
        import hashlib

        descriptor = b"waxseal-descriptor-v1\ndivergent-on-one-chain-only"
        with pytest.raises(LedgerDisagreement) as caught:
            _reader(chain).registry_lookup(hashlib.sha256(descriptor).hexdigest())
        assert not isinstance(caught.value, LedgerUnreachable)


class TestQuorumAgainstRealOutages:
    def test_one_node_down_is_below_quorum(self, chain: Deployment) -> None:
        # A real killed process, not a fake exception: this is the only way to
        # see the transport's own failure mode reach the adapter.
        victim = _start_anvil()
        reader = EvmLedgerReader(
            [chain.urls[0], victim.url], chain.contracts, block_tag="finalized"
        )
        victim.process.kill()
        victim.process.wait(timeout=10)
        with pytest.raises(LedgerUnreachable, match="1 of 2 endpoints answered"):
            reader.latest_checkpoint(TRAIL)

    def test_a_down_ledger_is_unreachable_never_delinquent(self, chain: Deployment) -> None:
        victim = _start_anvil()
        reader = EvmLedgerReader([chain.urls[0], victim.url], chain.contracts)
        victim.process.kill()
        victim.process.wait(timeout=10)
        verdict = reader.liveness(TRAIL, now=datetime.now(UTC))
        # An outage must never be rendered as a writer that stopped anchoring.
        assert verdict.status == UNREACHABLE


class TestTheBlockTagIsLoadBearing:
    def test_not_yet_final_is_unmeasured_not_absent(self, chain: Deployment) -> None:
        # anvil's `finalized` trails `latest`. A trail registered but not yet
        # finalized reads as absent at `finalized` and present at `latest` —
        # which is the trade the default tag makes on purpose: a value a
        # reorg could withdraw is not a measurement.
        trail = "not-yet-final"
        calldata = encode_call(
            SELECTOR_REGISTER_TRAIL,
            [
                encode_bytes32(trail_id_for(trail)),
                encode_address(DEV_ADDRESS),
                encode_uint(DEADLINE_S, bits=64),
            ],
        )
        for url in chain.urls:
            _cast_send(url, str(chain.contracts.liveness), calldata)
        assert _reader(chain, block_tag="latest").deadline_s(trail) == DEADLINE_S
        assert _reader(chain, block_tag="finalized").deadline_s(trail) is None
        for url in chain.urls:
            _mine(url, 2)
        assert _reader(chain, block_tag="finalized").deadline_s(trail) == DEADLINE_S
