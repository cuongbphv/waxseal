"""The ledger port, exercised through fakes that speak ABI, not mocks.

A mock that asserts `latest_checkpoint` was called once proves the test knows
what it wrote. These fakes return ABI-ENCODED BYTES and the reader decodes
them, so the same path an `eth_call` adapter will take — build calldata,
decode a return, decide a ternary — is the path under test. When
`adapters/evm.py` lands (F3), the only thing that changes is where the bytes
come from.

The fakes are also the port's own usability check: if writing one here were
awkward, writing one in a downstream project's test suite would be worse.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Protocol, runtime_checkable

import pytest

from waxseal.domain import abi
from waxseal.domain.bond import (
    BONDED,
    SLASHED,
    UNBONDED,
    BondStatus,
    DivergentLeaf,
    EquivocationProof,
    NonExtensionProof,
    bond_status_for,
    checkpoint_signing_digest,
    unreachable_bond,
)
from waxseal.domain.checkpoint import Checkpoint, checkpoint_for
from waxseal.domain.liveness import (
    DELINQUENT,
    LIVE,
    UNREACHABLE,
    OnChainCheckpoint,
    delinquency,
    unreachable_ledger,
)
from waxseal.domain.registry import RegistryCrossCheck, VersionRegistry, descriptor_frame
from waxseal.ports.ledger import (
    LedgerDisagreement,
    LedgerReader,
    LedgerSink,
    LedgerUnreachable,
    Signer,
    TransactionSigner,
)

CHAIN_ID = "0x" + "11" * 32
WRITER = "0x" + "ab" * 20
HASHES = tuple(hashlib.sha256(str(i).encode()).hexdigest() for i in range(8))

# This fake never claimed byte-accuracy with the deployed contracts -- that
# fidelity is `adapters/evm.py`'s job, checked in tests/adapters/test_evm.py
# against `contracts/abi/selectors.json`. It only needs a 4-byte identifier
# that matches calldata it built itself against a response dict it built
# itself, so these two are locally-scoped rather than borrowed from
# `domain/abi.py`'s frozen (necessarily real) selector table. waxseal-fg4.40
# removed `abi.SELECTOR_LATEST`/`abi.SELECTOR_IS_SLASHED` because neither
# `latest(bytes32)` nor `isSlashed(address)` exists on any deployed
# contract -- `latest_checkpoint` here models a lookup no real ledger
# exposes this way, and `bond_status` below models `.slashed` as its own
# call rather than as a field of the real `bondOf` tuple return.
_FAKE_LATEST_SELECTOR = bytes.fromhex("00000001")
_FAKE_IS_SLASHED_SELECTOR = bytes.fromhex("00000002")


def word(value: int) -> bytes:
    return abi.encode_uint(value)


class FakeChain:
    """`eth_call` reduced to what it is: calldata in, ABI bytes out."""

    def __init__(self, responses: dict[bytes, bytes], *, down: bool = False) -> None:
        self._responses = responses
        self._down = down

    def call(self, calldata: bytes) -> bytes:
        if self._down:
            raise LedgerUnreachable("connection refused")
        return self._responses[calldata]


class FakeLedgerReader:
    """A LedgerReader over one FakeChain, decoding exactly as an EVM adapter
    would. Absence is ENCODED (a zero block time, an empty descriptor), never
    signalled by a missing response: a contract that answers always answers."""

    name = "fake"

    def __init__(self, chain: FakeChain) -> None:
        self._chain = chain

    def latest_checkpoint(self, chain_id: str) -> OnChainCheckpoint | None:
        data = self._chain.call(
            abi.encode_call(_FAKE_LATEST_SELECTOR, [abi.encode_bytes32(chain_id)])
        )
        seq, entry_hash, root, block_time = abi.decode_words(data)
        if abi.decode_uint(block_time) == 0:
            return None
        return OnChainCheckpoint(
            chain_id=chain_id,
            seq=abi.decode_uint(seq),
            entry_hash=abi.decode_bytes32(entry_hash),
            root=abi.decode_bytes32(root),
            block_time=abi.decode_uint(block_time),
        )

    def deadline_s(self, chain_id: str) -> int | None:
        raw = abi.decode_uint(
            self._chain.call(
                abi.encode_call(abi.SELECTOR_DEADLINE_OF, [abi.encode_bytes32(chain_id)])
            )
        )
        return raw or None

    def registry_lookup(self, fingerprint: str) -> bytes | None:
        data = self._chain.call(
            abi.encode_call(abi.SELECTOR_LOOKUP, [abi.encode_bytes32(fingerprint)])
        )
        return abi.decode_bytes(data) or None

    def bond_status(self, writer_id: str) -> BondStatus:
        arg = [abi.encode_address(writer_id)]
        amount = abi.decode_uint(self._chain.call(abi.encode_call(abi.SELECTOR_BOND_OF, arg)))
        slashed = abi.decode_bool(self._chain.call(abi.encode_call(_FAKE_IS_SLASHED_SELECTOR, arg)))
        return bond_status_for(writer_id, amount_wei=amount, slashed=slashed)


class FakeSigner:
    """Not a real signature scheme — a deterministic stand-in, so a test can
    check WHAT was signed without importing a crypto library the project
    refuses to depend on."""

    address = WRITER
    public_id = "fake-key-1"

    def sign(self, digest32: bytes) -> bytes:
        if len(digest32) != 32:
            raise ValueError("a ledger signature is over exactly 32 bytes")
        return hashlib.sha256(b"fake-signer\n" + digest32).digest()


class FakeTransactionSigner(FakeSigner):
    def sign_transaction(self, fields: object) -> bytes:
        return hashlib.sha256(repr(fields).encode()).digest()


class FakeLedgerSink:
    name = "fake"

    def __init__(self) -> None:
        self.submitted: list[tuple[str, Checkpoint, bytes]] = []
        self.registered: list[bytes] = []
        self.proofs: list[object] = []

    def submit_checkpoint(self, chain_id: str, checkpoint: Checkpoint, signature: bytes) -> str:
        self.submitted.append((chain_id, checkpoint, signature))
        return "0x" + hashlib.sha256(signature).hexdigest()

    def register_fingerprint(self, descriptor: bytes) -> str:
        if descriptor in self.registered:
            # Append-only: a duplicate reverts on chain, and a fake that
            # accepted one would let a test pass against a contract that
            # cannot exist.
            raise RuntimeError("execution reverted: already registered")
        self.registered.append(descriptor)
        return "0x" + hashlib.sha256(descriptor).hexdigest()

    def submit_fraud_proof(self, proof: EquivocationProof | NonExtensionProof) -> str:
        self.proofs.append(proof)
        return "0x" + hashlib.sha256(repr(proof).encode()).hexdigest()


def live_chain(*, block_time: int, deadline: int = 3600) -> FakeChain:
    latest_call = abi.encode_call(_FAKE_LATEST_SELECTOR, [abi.encode_bytes32(CHAIN_ID)])
    deadline_call = abi.encode_call(abi.SELECTOR_DEADLINE_OF, [abi.encode_bytes32(CHAIN_ID)])
    checkpoint = checkpoint_for(HASHES)
    return FakeChain(
        {
            latest_call: (
                word(checkpoint.seq)
                + abi.encode_bytes32(checkpoint.entry_hash)
                + abi.encode_bytes32(checkpoint.root)
                + word(block_time)
            ),
            deadline_call: word(deadline),
        }
    )


NOW_TS = 1_756_728_000


def now() -> datetime:
    return datetime.fromtimestamp(NOW_TS, tz=UTC)


class TestProtocolConformance:
    def test_the_fakes_satisfy_the_ports_without_inheriting(self) -> None:
        # Structural conformance is the whole reason these are Protocols: a
        # downstream adapter must never have to import a waxseal base class.
        @runtime_checkable
        class CheckableReader(LedgerReader, Protocol): ...

        @runtime_checkable
        class CheckableSink(LedgerSink, Protocol): ...

        @runtime_checkable
        class CheckableSigner(Signer, Protocol): ...

        @runtime_checkable
        class CheckableTxSigner(TransactionSigner, Protocol): ...

        assert isinstance(FakeLedgerReader(live_chain(block_time=NOW_TS)), CheckableReader)
        assert isinstance(FakeLedgerSink(), CheckableSink)
        assert isinstance(FakeSigner(), CheckableSigner)
        assert isinstance(FakeTransactionSigner(), CheckableTxSigner)
        assert not isinstance(FakeSigner(), CheckableTxSigner)


class TestLivenessThroughThePort:
    def test_a_punctual_writer_reads_live(self) -> None:
        reader = FakeLedgerReader(live_chain(block_time=NOW_TS - 600))
        cp = reader.latest_checkpoint(CHAIN_ID)
        assert cp is not None
        verdict = delinquency(cp.block_time, reader.deadline_s(CHAIN_ID), now=now())
        assert verdict.status == LIVE

    def test_an_overdue_writer_reads_delinquent(self) -> None:
        reader = FakeLedgerReader(live_chain(block_time=NOW_TS - 90_000))
        cp = reader.latest_checkpoint(CHAIN_ID)
        assert cp is not None
        assert delinquency(cp.block_time, 3600, now=now()).status == DELINQUENT

    def test_a_contract_holding_no_checkpoint_answers_none(self) -> None:
        # Encoded absence, not a missing response: `latest` on an unknown
        # chain id returns a zeroed struct.
        reader = FakeLedgerReader(live_chain(block_time=0))
        assert reader.latest_checkpoint(CHAIN_ID) is None

    def test_no_deadline_configured_answers_none_not_zero(self) -> None:
        reader = FakeLedgerReader(live_chain(block_time=NOW_TS, deadline=0))
        assert reader.deadline_s(CHAIN_ID) is None

    def test_a_reader_that_cannot_ask_raises_rather_than_answering_none(self) -> None:
        reader = FakeLedgerReader(FakeChain({}, down=True))
        with pytest.raises(LedgerUnreachable):
            reader.latest_checkpoint(CHAIN_ID)

    def test_the_caller_turns_that_raise_into_the_third_value(self) -> None:
        reader = FakeLedgerReader(FakeChain({}, down=True))
        try:
            reader.latest_checkpoint(CHAIN_ID)
        except LedgerUnreachable as exc:
            verdict = unreachable_ledger(str(exc))
        assert verdict.status == UNREACHABLE
        assert verdict.age_s is None


class TestRegistryThroughThePort:
    def registry_chain(self, fingerprint: str, descriptor: bytes) -> FakeChain:
        call = abi.encode_call(abi.SELECTOR_LOOKUP, [abi.encode_bytes32(fingerprint)])
        return FakeChain({call: abi.encode_uint(32) + abi.encode_bytes(descriptor)})

    def test_a_published_descriptor_round_trips_through_abi(self) -> None:
        from waxseal.domain.fingerprint import HEADER_FIELDS, fingerprint

        descriptor = descriptor_frame(HEADER_FIELDS)
        reader = FakeLedgerReader(self.registry_chain(fingerprint(), descriptor))
        finding = RegistryCrossCheck(VersionRegistry()).check(
            fingerprint(), reader.registry_lookup(fingerprint())
        )
        assert finding.status == "agrees"

    def test_an_empty_descriptor_reads_as_absence(self) -> None:
        from waxseal.domain.fingerprint import fingerprint

        reader = FakeLedgerReader(self.registry_chain(fingerprint(), b""))
        assert reader.registry_lookup(fingerprint()) is None


class TestBondThroughThePort:
    def bond_chain(self, amount: int, slashed: bool) -> FakeChain:
        arg = [abi.encode_address(WRITER)]
        return FakeChain(
            {
                abi.encode_call(abi.SELECTOR_BOND_OF, arg): word(amount),
                abi.encode_call(_FAKE_IS_SLASHED_SELECTOR, arg): abi.encode_bool(slashed),
            }
        )

    def test_a_funded_writer(self) -> None:
        reader = FakeLedgerReader(self.bond_chain(10**18, False))
        assert reader.bond_status(WRITER).status == BONDED

    def test_a_slashed_writer(self) -> None:
        reader = FakeLedgerReader(self.bond_chain(0, True))
        assert reader.bond_status(WRITER).status == SLASHED

    def test_a_writer_that_never_deposited(self) -> None:
        reader = FakeLedgerReader(self.bond_chain(0, False))
        assert reader.bond_status(WRITER).status == UNBONDED

    def test_an_unreachable_bond_contract_is_the_third_value(self) -> None:
        reader = FakeLedgerReader(FakeChain({}, down=True))
        try:
            reader.bond_status(WRITER)
        except LedgerUnreachable as exc:
            status = unreachable_bond(WRITER, reason=str(exc))
        assert status.status == "unreachable"
        assert status.amount_wei is None


class TestDisagreementIsNotUnreachability:
    def test_two_readers_that_answer_differently_raise_their_own_error(self) -> None:
        # An adapter reading two endpoints must not pick a winner: choosing
        # one is what an eclipsing adversary needs the client to do.
        a = FakeLedgerReader(live_chain(block_time=NOW_TS - 600))
        b = FakeLedgerReader(live_chain(block_time=NOW_TS - 90_000))
        answers = {r.latest_checkpoint(CHAIN_ID) for r in (a, b)}
        with pytest.raises(LedgerDisagreement, match="2 endpoints"):
            if len(answers) > 1:
                raise LedgerDisagreement(f"2 endpoints disagree on {CHAIN_ID}: {answers}")

    def test_disagreement_is_not_caught_as_unreachability_by_accident(self) -> None:
        # Both are LedgerError, but an adapter that caught LedgerUnreachable
        # broadly would silently swallow a disagreement. Siblings, not
        # ancestor and descendant.
        assert not issubclass(LedgerDisagreement, LedgerUnreachable)
        assert not issubclass(LedgerUnreachable, LedgerDisagreement)


class TestSinkAndSigner:
    def test_a_checkpoint_is_signed_over_the_domain_separated_digest(self) -> None:
        signer, sink = FakeSigner(), FakeLedgerSink()
        checkpoint = checkpoint_for(HASHES)
        digest = checkpoint_signing_digest(CHAIN_ID, checkpoint)
        receipt = sink.submit_checkpoint(CHAIN_ID, checkpoint, signer.sign(digest))
        assert receipt.startswith("0x")
        assert sink.submitted[0][2] == signer.sign(digest)

    def test_a_signer_refuses_anything_that_is_not_a_32_byte_digest(self) -> None:
        with pytest.raises(ValueError, match="32 bytes"):
            FakeSigner().sign(b"short")

    def test_registering_the_same_descriptor_twice_reverts(self) -> None:
        from waxseal.domain.fingerprint import HEADER_FIELDS

        sink = FakeLedgerSink()
        descriptor = descriptor_frame(HEADER_FIELDS)
        assert sink.register_fingerprint(descriptor).startswith("0x")
        with pytest.raises(RuntimeError, match="already registered"):
            sink.register_fingerprint(descriptor)

    def test_both_proof_shapes_go_to_one_entry_point(self) -> None:
        sink = FakeLedgerSink()
        a = checkpoint_for(HASHES[:4])
        b = Checkpoint(seq=a.seq, entry_hash="ff" * 32, root=a.root)
        equivocation = EquivocationProof(
            chain_id=CHAIN_ID,
            checkpoint_a=a,
            signature_a=b"\x01",
            checkpoint_b=b,
            signature_b=b"\x02",
        )
        # The second shape used to be a consistency-proof CHALLENGE that the
        # deployed contract could not accept, so the "one entry point" this
        # test names was one the adapter raised from. It is now the
        # divergent-leaf evidence `proveNonExtension` takes.
        divergence = NonExtensionProof(
            chain_id=CHAIN_ID,
            older=a,
            newer=checkpoint_for(HASHES),
            older_signature=b"\x01",
            newer_signature=b"\x02",
            in_older=DivergentLeaf(index=1, entry_hash=HASHES[1]),
            in_newer=DivergentLeaf(index=1, entry_hash="ee" * 32),
        )
        sink.submit_fraud_proof(equivocation)
        sink.submit_fraud_proof(divergence)
        assert sink.proofs == [equivocation, divergence]

    def test_a_transaction_signer_is_also_a_digest_signer(self) -> None:
        signer = FakeTransactionSigner()
        assert len(signer.sign(b"\x00" * 32)) == 32
        assert len(signer.sign_transaction({"to": WRITER})) == 32
