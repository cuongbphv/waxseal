"""EvmLedgerReader / EvmLedgerSink / EvmAnchorSink against fake endpoints.

The fakes here are NODES, not mocks: each one answers JSON-RPC with bytes
this file ABI-encodes by hand, and every assertion is about the value the
adapter derived from those bytes. Nothing counts calls. A mock that asserted
"eth_call was invoked once with this selector" would pass just as happily
against an adapter that decoded the answer wrongly, which is the only failure
mode worth testing here.

The anvil end-to-end run lives in test_evm_anvil.py and is additional
evidence, never the coverage: these tests must exercise every branch on their
own, because a suite whose completeness depends on a skippable integration
test is a suite that silently loses coverage the day Foundry is absent.

FALSIFIABILITY RECEIPTS. Each ternary predicate has a test that goes RED when
the third value's branch is deleted from adapters/evm/reader.py. MEASURED 01/09/2026
on this worktree, one deletion at a time, against this file alone (baseline:
99 tests, 0 failed):

  1. `EvmLedgerReader.liveness` — delete `except LedgerUnreachable: return
     unreachable_ledger(...)` -> 1 failed, 98 passed.
     test_liveness_is_unreachable_when_no_quorum_answers: the outage escapes
     as an exception instead of becoming a verdict.
  2. `EvmLedgerReader.bond` — delete its `except LedgerUnreachable` ->
     1 failed, 98 passed (test_bond_is_unreachable_when_no_quorum_answers).
  3. `EvmLedgerReader.registry_agreement` — delete its `except
     LedgerUnreachable` -> 1 failed, 98 passed
     (test_registry_agreement_is_unreachable_when_the_node_is_down).
  4. `_agree` — delete the `raise LedgerDisagreement` loop -> 8 failed, 91
     passed: every disagreement test, each one now silently handed the first
     endpoint's answer. That is the eclipse failure mode in one diff — a
     client that picks a winner.
  5. `latest_checkpoint` / `on_chain_delinquency` — delete `if
     revert.selector() == ERROR_TRAIL_NOT_REGISTERED: return None` -> 5
     failed, 94 passed. The revert degrades to `unreachable`, and
     test_registered_but_never_anchored_is_delinquent_not_unreachable shows
     what that costs: a trail that never anchored stops being reported
     delinquent and starts being reported as a network problem.

Each deletion is caught by a named test and by nothing else — not by the type
checker, not by ruff, not by a coverage floor.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from waxseal.adapters.evm import (
    ERROR_TRAIL_NOT_REGISTERED,
    MIN_ENDPOINTS,
    SELECTOR_SUBMIT_HEAD,
    EvmAnchorSink,
    EvmContracts,
    EvmLedgerReader,
    EvmLedgerSink,
    EvmTxReceipt,
    leaf_claim,
)
from waxseal.adapters.remote import RemoteRequest, RemoteResponse
from waxseal.domain import abi
from waxseal.domain.abi import (
    SELECTOR_DEADLINE_OF,
    SELECTOR_PROVE_EQUIVOCATION,
    SELECTOR_PROVE_NON_EXTENSION,
    SELECTOR_REGISTER_TRAIL,
)
from waxseal.domain.bond import (
    BONDED,
    SLASHED,
    UNBONDED,
    DivergentLeaf,
    EquivocationProof,
    NonExtensionProof,
    trail_id_for,
)
from waxseal.domain.checkpoint import Checkpoint
from waxseal.domain.fingerprint import HEADER_FIELDS, fingerprint_for
from waxseal.domain.liveness import (
    DEADLINE_UNAVAILABLE,
    DELINQUENT,
    LEDGER_DELINQUENT,
    LEDGER_UNREACHABLE,
    LIVE,
    NO_CHECKPOINT_ON_LEDGER,
    UNREACHABLE,
)
from waxseal.domain.registry import (
    REGISTRY_ABSENT,
    REGISTRY_AGREES,
    REGISTRY_DISAGREES,
    REGISTRY_UNREACHABLE,
    RegistryCrossCheck,
    VersionRegistry,
    descriptor_frame,
)
from waxseal.ports.ledger import LedgerDisagreement, LedgerError, LedgerUnreachable

REPO = Path(__file__).resolve().parents[2]

LIVENESS_ADDRESS = "0x" + "11" * 20
REGISTRY_ADDRESS = "0x" + "22" * 20
BOND_ADDRESS = "0x" + "33" * 20
WRITER = "0x" + "44" * 20

URL_A = "http://node-a.example/rpc"
URL_B = "http://node-b.example/rpc"

ENTRY_HASH = "ab" * 32
ROOT = "cd" * 32

NOW = datetime(2026, 9, 1, 12, 0, 0, tzinfo=UTC)


# --------------------------------------------------------------- ABI helpers
#
# Hand-built returns. `domain/abi.py` is the decoder under test on the other
# side of the wire, so these use int.to_bytes/hex directly rather than the
# encoder, and a bug shared between encoder and decoder cannot hide here.


def word(value: int) -> bytes:
    return value.to_bytes(32, "big")


def hex32(text: str) -> bytes:
    return bytes.fromhex(text)


def hexdata(*chunks: bytes) -> str:
    return "0x" + b"".join(chunks).hex()


def dynamic_bytes(raw: bytes) -> str:
    """A `returns (bytes)` payload: offset 0x20, length, right-padded data."""
    pad = (-len(raw)) % 32
    return hexdata(word(32), word(len(raw)), raw + b"\x00" * pad)


def ok(value: object) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": 1, "result": value}


def revert(selector: str = "45ed42e1", *, data: str | None = None, code: int = 3) -> dict[str, Any]:
    payload = f"0x{selector}{'11' * 32}" if data is None else data
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "error": {
            "code": code,
            "message": f"execution reverted: custom error 0x{selector}",
            "data": payload,
        },
    }


# ---------------------------------------------------------------- fake nodes

Handler = Callable[[str, list[Any]], dict[str, Any]]


class Down(Exception):
    """What a transport raises when a node cannot be reached at all."""


def cluster(handlers: Mapping[str, Handler | Exception | int]) -> Callable[..., RemoteResponse]:
    """A Transport routing by URL.

    A handler value may be a callable (answer normally), an Exception (the
    transport raises, i.e. the node is unreachable) or an int (an HTTP status
    with an empty body, i.e. a proxy answering instead of a node).
    """

    def transport(request: RemoteRequest) -> RemoteResponse:
        entry = handlers[request.url]
        if isinstance(entry, Exception):
            raise entry
        if isinstance(entry, int):
            return RemoteResponse(status=entry, body=b"")
        payload = json.loads(request.body or b"{}")
        answer = entry(payload["method"], payload["params"])
        return RemoteResponse(status=200, body=json.dumps(answer).encode())

    return transport


def calls(table: Mapping[str, dict[str, Any]], *, default: dict[str, Any] | None = None) -> Handler:
    """An `eth_call`-only node keyed by the calldata's four-byte selector."""

    def handler(method: str, params: list[Any]) -> dict[str, Any]:
        assert method == "eth_call"
        selector = params[0]["data"][2:10]
        answer = table.get(selector, default)
        assert answer is not None, f"fake node has no answer for selector {selector}"
        return answer

    return handler


LAST_SEEN = abi.SELECTOR_LAST_SEEN.hex()
DEADLINE_OF = SELECTOR_DEADLINE_OF.hex()
IS_DELINQUENT = abi.SELECTOR_IS_DELINQUENT.hex()
LOOKUP = abi.SELECTOR_LOOKUP.hex()
BOND_OF = abi.SELECTOR_BOND_OF.hex()

HEAD_RETURN = ok(hexdata(word(41), hex32(ENTRY_HASH), hex32(ROOT), word(1_756_000_000)))
BOND_RETURN_BONDED = ok(hexdata(word(10**18), word(0), word(0), word(0)))
BOND_RETURN_SLASHED = ok(hexdata(word(0), word(0), word(0), word(1)))
BOND_RETURN_UNBONDED = ok(hexdata(word(0), word(0), word(0), word(0)))


def liveness_node(
    *, head: dict[str, Any] | None = None, deadline: int = 3600, delinquent: bool = False
) -> Handler:
    return calls(
        {
            LAST_SEEN: head if head is not None else HEAD_RETURN,
            DEADLINE_OF: ok(hexdata(word(deadline))),
            IS_DELINQUENT: ok(hexdata(word(1 if delinquent else 0))),
        }
    )


def reader(
    handlers: Mapping[str, Handler | Exception | int],
    *,
    contracts: EvmContracts | None = None,
    urls: Sequence[str] = (URL_A, URL_B),
    block_tag: str = "finalized",
) -> EvmLedgerReader:
    return EvmLedgerReader(
        urls,
        contracts
        or EvmContracts(liveness=LIVENESS_ADDRESS, registry=REGISTRY_ADDRESS, bond=BOND_ADDRESS),
        transport=cluster(handlers),
        block_tag=block_tag,
    )


def both(handler: Handler) -> dict[str, Handler]:
    return {URL_A: handler, URL_B: handler}


# ================================================================ construction


class TestConstruction:
    def test_one_endpoint_is_refused(self) -> None:
        # One endpoint cannot disagree with itself, so a reader built on one
        # would report agreement it never measured.
        with pytest.raises(ValueError, match="at least 2 RPC endpoints"):
            EvmLedgerReader([URL_A], EvmContracts(liveness=LIVENESS_ADDRESS))

    def test_the_same_endpoint_twice_is_refused(self) -> None:
        with pytest.raises(ValueError, match="one observer counted twice"):
            EvmLedgerReader([URL_A, URL_A], EvmContracts(liveness=LIVENESS_ADDRESS))

    def test_the_default_transport_is_the_stdlib_one(self) -> None:
        # Constructed, not called: this asserts the adapter needs no injected
        # transport to exist, which is what keeps the read path dependency-free.
        built = EvmLedgerReader([URL_A, URL_B], EvmContracts(), timeout=0.1)
        assert built.name == "evm"

    def test_an_unconfigured_contract_is_unmeasured_not_a_crash(self) -> None:
        # `ledger-status --liveness` without `--registry` must read as
        # "nothing was measured", never as agreement.
        with pytest.raises(LedgerUnreachable, match="no registry contract address"):
            reader(
                both(liveness_node()), contracts=EvmContracts(liveness=LIVENESS_ADDRESS)
            ).registry_lookup("00" * 32)


# ============================================================= the read path


class TestLatestCheckpoint:
    def test_two_agreeing_endpoints_give_the_head(self) -> None:
        found = reader(both(liveness_node())).latest_checkpoint("trail")
        assert found is not None
        assert (found.seq, found.entry_hash, found.root, found.block_time) == (
            41,
            ENTRY_HASH,
            ROOT,
            1_756_000_000,
        )

    def test_the_trail_id_sent_is_the_pinned_sha256_of_the_name(self) -> None:
        # F1 pinned trail_id_for(); an adapter that invented its own reduction
        # would key a different mapping slot and read an empty one forever.
        seen: list[str] = []

        def handler(method: str, params: list[Any]) -> dict[str, Any]:
            seen.append(params[0]["data"])
            return HEAD_RETURN

        reader(both(handler)).latest_checkpoint("trail")
        assert seen[0] == "0x" + abi.SELECTOR_LAST_SEEN.hex() + trail_id_for("trail").hex()

    def test_the_block_tag_travels_with_every_call(self) -> None:
        tags: list[str] = []

        def handler(method: str, params: list[Any]) -> dict[str, Any]:
            tags.append(params[1])
            return HEAD_RETURN

        reader(both(handler)).latest_checkpoint("trail")
        assert tags == ["finalized", "finalized"]

    def test_trail_not_registered_is_a_measured_absence_not_unreachability(self) -> None:
        # THE handover decision. The node answered, from state, and would
        # answer the same again: that is None ("holds nothing"), not silence.
        assert reader(both(calls({LAST_SEEN: revert()}))).latest_checkpoint("trail") is None

    def test_an_unrecognised_revert_degrades_to_unmeasured_with_its_selector(self) -> None:
        # We asked and got an answer this build cannot read. Nothing was
        # measured — and the four bytes are in the message so an operator can
        # look them up (rule 6: labelled, never swallowed).
        with pytest.raises(LedgerUnreachable, match="custom error 0xdeadbeef"):
            reader(both(calls({LAST_SEEN: revert("deadbeef")}))).latest_checkpoint("trail")

    def test_a_revert_with_no_data_is_still_a_revert(self) -> None:
        with pytest.raises(LedgerUnreachable, match="no revert data"):
            reader(both(calls({LAST_SEEN: revert(data="not-hex")}))).latest_checkpoint("trail")

    def test_a_revert_whose_data_is_bad_hex_is_still_a_revert(self) -> None:
        with pytest.raises(LedgerUnreachable, match="no revert data"):
            reader(both(calls({LAST_SEEN: revert(data="0xzz")}))).latest_checkpoint("trail")

    def test_a_revert_reported_without_the_geth_code_is_still_a_revert(self) -> None:
        # Not every node populates `code: 3`; the message text is the
        # fallback. Misread as a plain RPC error, an unrecognised revert would
        # be indistinguishable from a rate limit.
        with pytest.raises(LedgerUnreachable, match="custom error 0xdeadbeef"):
            reader(both(calls({LAST_SEEN: revert("deadbeef", code=-32000)}))).latest_checkpoint(
                "trail"
            )

    def test_a_recognised_revert_is_absence_however_the_node_codes_it(self) -> None:
        node = calls({LAST_SEEN: revert(code=-32000)})
        assert reader(both(node)).latest_checkpoint("trail") is None

    def test_an_address_holding_no_code_is_not_an_empty_head(self) -> None:
        # eth_call against a codeless address SUCCEEDS with "0x". Reading
        # that as "the trail holds nothing" would report a typo in --liveness
        # as a measured fact about the writer.
        with pytest.raises(LedgerUnreachable, match="no contract at that address"):
            reader(both(calls({LAST_SEEN: ok("0x")}))).latest_checkpoint("trail")

    def test_a_return_of_the_wrong_shape_is_unmeasured(self) -> None:
        with pytest.raises(LedgerUnreachable, match="expected 4 words back, got 2"):
            reader(both(calls({LAST_SEEN: ok(hexdata(word(1), word(2)))}))).latest_checkpoint("t")

    def test_a_return_that_is_not_whole_words_is_unmeasured(self) -> None:
        with pytest.raises(LedgerUnreachable, match="not a multiple of 32"):
            reader(both(calls({LAST_SEEN: ok("0xabcd")}))).latest_checkpoint("trail")

    def test_a_return_that_is_not_hex_is_unmeasured(self) -> None:
        with pytest.raises(LedgerUnreachable, match="not 0x-hex"):
            reader(both(calls({LAST_SEEN: ok(41)}))).latest_checkpoint("trail")

    def test_a_return_that_is_hex_shaped_but_not_hex_is_unmeasured(self) -> None:
        with pytest.raises(LedgerUnreachable, match="not hex"):
            reader(both(calls({LAST_SEEN: ok("0xzz")}))).latest_checkpoint("trail")


class TestDisagreement:
    """A measured conflict, distinct in type and in message from a silence."""

    def test_two_heads_disagreeing_raise_and_name_the_pair(self) -> None:
        other = ok(hexdata(word(9), hex32(ENTRY_HASH), hex32(ROOT), word(1_756_000_000)))
        with pytest.raises(LedgerDisagreement) as caught:
            reader({URL_A: liveness_node(), URL_B: calls({LAST_SEEN: other})}).latest_checkpoint(
                "trail"
            )
        message = str(caught.value)
        assert URL_A in message and URL_B in message
        assert "seq=41" in message and "seq=9" in message

    def test_a_disagreement_is_not_an_unreachability(self) -> None:
        # Type, not just wording: F4 must be able to branch on it. Neither
        # class is a subclass of the other.
        assert not issubclass(LedgerDisagreement, LedgerUnreachable)
        assert not issubclass(LedgerUnreachable, LedgerDisagreement)

    def test_a_conflict_outranks_a_third_endpoint_s_silence(self) -> None:
        # Two endpoints contradicting each other is a finding even when a
        # third was down; reporting the outage instead would lose it.
        other = ok(hexdata(word(9), hex32(ENTRY_HASH), hex32(ROOT), word(7)))
        third = "http://node-c.example/rpc"
        with pytest.raises(LedgerDisagreement):
            EvmLedgerReader(
                [URL_A, URL_B, third],
                EvmContracts(liveness=LIVENESS_ADDRESS),
                transport=cluster(
                    {
                        URL_A: liveness_node(),
                        URL_B: calls({LAST_SEEN: other}),
                        third: Down("connection refused"),
                    }
                ),
            ).latest_checkpoint("trail")

    def test_disagreeing_deadlines_raise(self) -> None:
        with pytest.raises(LedgerDisagreement, match="deadline_s"):
            reader(
                {URL_A: liveness_node(deadline=3600), URL_B: liveness_node(deadline=60)}
            ).deadline_s("trail")

    def test_disagreeing_registries_raise(self) -> None:
        with pytest.raises(LedgerDisagreement, match="registry_lookup"):
            reader(
                {
                    URL_A: calls({LOOKUP: ok(dynamic_bytes(b"one"))}),
                    URL_B: calls({LOOKUP: ok(dynamic_bytes(b"two"))}),
                }
            ).registry_lookup("00" * 32)

    def test_disagreeing_bonds_raise(self) -> None:
        with pytest.raises(LedgerDisagreement, match="bond_status"):
            reader(
                {
                    URL_A: calls({BOND_OF: BOND_RETURN_BONDED}),
                    URL_B: calls({BOND_OF: BOND_RETURN_SLASHED}),
                }
            ).bond_status(WRITER)


class TestQuorum:
    def test_one_answer_out_of_two_is_below_quorum(self) -> None:
        # An adversary that silences every endpoint but its own must not get
        # a confident answer out of this client.
        with pytest.raises(LedgerUnreachable, match="1 of 2 endpoints answered"):
            reader({URL_A: liveness_node(), URL_B: Down("refused")}).latest_checkpoint("trail")

    def test_no_answers_names_every_silence(self) -> None:
        with pytest.raises(LedgerUnreachable) as caught:
            reader({URL_A: Down("refused"), URL_B: 503}).latest_checkpoint("trail")
        assert "refused" in str(caught.value)
        assert "HTTP 503" in str(caught.value)

    def test_two_of_three_answering_and_agreeing_is_enough(self) -> None:
        third = "http://node-c.example/rpc"
        found = EvmLedgerReader(
            [URL_A, URL_B, third],
            EvmContracts(liveness=LIVENESS_ADDRESS),
            transport=cluster(
                {URL_A: liveness_node(), URL_B: liveness_node(), third: Down("refused")}
            ),
        ).latest_checkpoint("trail")
        assert found is not None and found.seq == 41

    def test_the_quorum_is_two(self) -> None:
        assert MIN_ENDPOINTS == 2


class TestMalformedNodes:
    def test_a_body_that_is_not_json_is_a_silence(self) -> None:
        def transport(request: RemoteRequest) -> RemoteResponse:
            return RemoteResponse(status=200, body=b"<html>rate limited</html>")

        with pytest.raises(LedgerUnreachable, match="not JSON"):
            EvmLedgerReader(
                [URL_A, URL_B], EvmContracts(liveness=LIVENESS_ADDRESS), transport=transport
            ).latest_checkpoint("trail")

    def test_a_json_body_that_is_not_an_object_is_a_silence(self) -> None:
        def transport(request: RemoteRequest) -> RemoteResponse:
            return RemoteResponse(status=200, body=b"[1, 2, 3]")

        with pytest.raises(LedgerUnreachable, match="not a JSON-RPC object"):
            EvmLedgerReader(
                [URL_A, URL_B], EvmContracts(liveness=LIVENESS_ADDRESS), transport=transport
            ).latest_checkpoint("trail")

    def test_neither_result_nor_error_is_a_silence(self) -> None:
        with pytest.raises(LedgerUnreachable, match="neither result nor error"):
            reader(both(calls({LAST_SEEN: {"jsonrpc": "2.0", "id": 1}}))).latest_checkpoint("t")

    def test_a_malformed_error_member_is_a_silence(self) -> None:
        answer = {"jsonrpc": "2.0", "id": 1, "error": "everything is fine"}
        with pytest.raises(LedgerUnreachable, match="malformed error member"):
            reader(both(calls({LAST_SEEN: answer}))).latest_checkpoint("trail")

    def test_a_non_revert_rpc_error_is_a_silence(self) -> None:
        answer = {"jsonrpc": "2.0", "id": 1, "error": {"code": -32005, "message": "rate limited"}}
        with pytest.raises(LedgerUnreachable, match="rate limited"):
            reader(both(calls({LAST_SEEN: answer}))).latest_checkpoint("trail")


class TestDeadline:
    def test_a_configured_deadline_comes_back(self) -> None:
        assert reader(both(liveness_node(deadline=3600))).deadline_s("trail") == 3600

    def test_zero_is_no_deadline_configured_not_a_deadline_of_zero(self) -> None:
        # registerTrail reverts on a zero deadline, so zero can only mean
        # "unregistered". Reported as None; a zero would make every trail late.
        assert reader(both(liveness_node(deadline=0))).deadline_s("trail") is None


class TestRegistryLookup:
    def test_a_published_descriptor_comes_back_as_bytes(self) -> None:
        assert (
            reader(both(calls({LOOKUP: ok(dynamic_bytes(b"descriptor bytes"))}))).registry_lookup(
                "00" * 32
            )
            == b"descriptor bytes"
        )

    def test_an_empty_descriptor_is_absence(self) -> None:
        node = both(calls({LOOKUP: ok(dynamic_bytes(b""))}))
        assert reader(node).registry_lookup("0" * 64) is None

    def test_a_descriptor_with_a_bogus_offset_is_unmeasured(self) -> None:
        bogus = hexdata(word(4096), word(0))
        with pytest.raises(LedgerUnreachable, match="not a usable position"):
            reader(both(calls({LOOKUP: ok(bogus)}))).registry_lookup("0" * 64)


class TestBondStatus:
    def test_a_funded_writer_is_bonded(self) -> None:
        found = reader(both(calls({BOND_OF: BOND_RETURN_BONDED}))).bond_status(WRITER)
        assert found.status == BONDED

    def test_a_slashed_writer_is_slashed(self) -> None:
        found = reader(both(calls({BOND_OF: BOND_RETURN_SLASHED}))).bond_status(WRITER)
        assert found.status == SLASHED

    def test_a_writer_that_never_deposited_is_unbonded_not_slashed(self) -> None:
        # Folding these two would assert an adjudication from an absence.
        found = reader(both(calls({BOND_OF: BOND_RETURN_UNBONDED}))).bond_status(WRITER)
        assert found.status == UNBONDED

    def test_a_bool_word_that_is_neither_0_nor_1_is_unmeasured(self) -> None:
        dirty = ok(hexdata(word(1), word(0), word(0), word(2)))
        with pytest.raises(LedgerUnreachable, match="neither 0 nor 1"):
            reader(both(calls({BOND_OF: dirty}))).bond_status(WRITER)

    def test_a_writer_id_that_is_not_an_address_is_a_caller_error(self) -> None:
        # Local input, not remote: this is a bug in the caller, and turning it
        # into "unreachable" would hide it behind a network story.
        with pytest.raises(abi.AbiError, match="not a 20-byte hex address"):
            reader(both(calls({BOND_OF: BOND_RETURN_BONDED}))).bond_status("not-an-address")


class TestOnChainDelinquency:
    def test_the_chain_says_live(self) -> None:
        assert reader(both(liveness_node(delinquent=False))).on_chain_delinquency("t") is False

    def test_the_chain_says_delinquent(self) -> None:
        assert reader(both(liveness_node(delinquent=True))).on_chain_delinquency("t") is True

    def test_the_revert_is_the_third_value(self) -> None:
        # The contract reverts rather than returning false precisely so this
        # can be None. bool is two-valued; the honest answer is not.
        assert reader(both(calls({IS_DELINQUENT: revert()}))).on_chain_delinquency("t") is None

    def test_an_unrecognised_revert_is_unmeasured(self) -> None:
        with pytest.raises(LedgerUnreachable, match="custom error 0xfeedface"):
            reader(both(calls({IS_DELINQUENT: revert("feedface")}))).on_chain_delinquency("t")

    def test_a_dirty_bool_is_unmeasured(self) -> None:
        with pytest.raises(LedgerUnreachable, match="neither 0 nor 1"):
            reader(both(calls({IS_DELINQUENT: ok(hexdata(word(7)))}))).on_chain_delinquency("t")

    def test_the_error_selector_is_the_frozen_one(self) -> None:
        assert ERROR_TRAIL_NOT_REGISTERED.hex() == "45ed42e1"


# ============================================ the three ternary readings


class TestLivenessTernary:
    def test_a_recent_head_is_live(self) -> None:
        now = datetime.fromtimestamp(1_756_000_060, tz=UTC)
        verdict = reader(both(liveness_node())).liveness("trail", now=now)
        assert (verdict.status, verdict.age_s, verdict.deadline_s) == (LIVE, 60, 3600)

    def test_an_old_head_is_delinquent(self) -> None:
        now = datetime.fromtimestamp(1_756_000_000 + 7200, tz=UTC)
        verdict = reader(both(liveness_node())).liveness("trail", now=now)
        assert (verdict.status, verdict.reason) == (DELINQUENT, LEDGER_DELINQUENT)

    def test_registered_but_never_anchored_is_delinquent_not_unreachable(self) -> None:
        # The revert says "holds nothing"; a deadline exists, so the trail IS
        # late. This is the whole point of not calling the revert unreachable.
        node = calls({LAST_SEEN: revert(), DEADLINE_OF: ok(hexdata(word(3600)))})
        verdict = reader(both(node)).liveness("trail", now=NOW)
        assert (verdict.status, verdict.reason) == (DELINQUENT, NO_CHECKPOINT_ON_LEDGER)

    def test_an_unregistered_trail_has_nothing_to_be_late_against(self) -> None:
        # No deadline: comparing against a default would invent a policy the
        # operator never set and then report a writer delinquent under it.
        node = calls({LAST_SEEN: revert(), DEADLINE_OF: ok(hexdata(word(0)))})
        verdict = reader(both(node)).liveness("trail", now=NOW)
        assert (verdict.status, verdict.reason) == (UNREACHABLE, DEADLINE_UNAVAILABLE)

    def test_liveness_is_unreachable_when_no_quorum_answers(self) -> None:
        # FALSIFIABILITY RECEIPT 1: delete the `except LedgerUnreachable`
        # branch in EvmLedgerReader.liveness and this test goes red.
        verdict = reader({URL_A: Down("refused"), URL_B: Down("refused")}).liveness("t", now=NOW)
        assert (verdict.status, verdict.reason) == (UNREACHABLE, LEDGER_UNREACHABLE)

    def test_a_disagreement_is_not_flattened_into_unreachable(self) -> None:
        # Rule 6: the pair is the finding. Swallowing it into `unreachable`
        # would drop the only observation that separates an eclipse from an
        # outage, so `liveness` deliberately lets it through.
        with pytest.raises(LedgerDisagreement):
            reader(
                {URL_A: liveness_node(deadline=3600), URL_B: liveness_node(deadline=60)}
            ).liveness("trail", now=NOW)

    def test_liveness_never_reaches_verify_exit_1(self) -> None:
        now = datetime.fromtimestamp(1_756_000_000 + 7200, tz=UTC)
        verdict = reader(both(liveness_node())).liveness("trail", now=now)
        assert verdict.to_verify_verdict().to_exit_code() == 2


class TestBondTernary:
    def test_bonded(self) -> None:
        assert reader(both(calls({BOND_OF: BOND_RETURN_BONDED}))).bond(WRITER).status == BONDED

    def test_slashed(self) -> None:
        assert reader(both(calls({BOND_OF: BOND_RETURN_SLASHED}))).bond(WRITER).status == SLASHED

    def test_bond_is_unreachable_when_no_quorum_answers(self) -> None:
        # FALSIFIABILITY RECEIPT 2.
        found = reader({URL_A: Down("refused"), URL_B: Down("refused")}).bond(WRITER)
        assert found.status == UNREACHABLE
        assert found.amount_wei is None  # never 0: that would read as a measured absence of stake
        assert found.reason == LEDGER_UNREACHABLE

    def test_a_bond_disagreement_is_not_flattened(self) -> None:
        with pytest.raises(LedgerDisagreement):
            reader(
                {
                    URL_A: calls({BOND_OF: BOND_RETURN_BONDED}),
                    URL_B: calls({BOND_OF: BOND_RETURN_SLASHED}),
                }
            ).bond(WRITER)


class TestRegistryTernary:
    @staticmethod
    def known() -> tuple[RegistryCrossCheck, str, bytes]:
        return (
            RegistryCrossCheck(VersionRegistry()),
            fingerprint_for(HEADER_FIELDS),
            descriptor_frame(HEADER_FIELDS),
        )

    def test_agrees(self) -> None:
        cross, fp, raw = self.known()
        finding = reader(both(calls({LOOKUP: ok(dynamic_bytes(raw))}))).registry_agreement(
            cross, fp
        )
        assert finding.status == REGISTRY_AGREES

    def test_disagrees_is_unverifiable_never_broken(self) -> None:
        cross, fp, _ = self.known()
        finding = reader(
            both(calls({LOOKUP: ok(dynamic_bytes(b"a poisoned descriptor"))}))
        ).registry_agreement(cross, fp)
        assert finding.status == REGISTRY_DISAGREES
        assert finding.to_verdict().to_exit_code() == 2

    def test_registry_agreement_is_unreachable_when_the_node_is_down(self) -> None:
        # FALSIFIABILITY RECEIPT 3.
        cross, fp, _ = self.known()
        finding = reader({URL_A: Down("refused"), URL_B: Down("refused")}).registry_agreement(
            cross, fp
        )
        assert finding.status == REGISTRY_UNREACHABLE

    def test_registry_agreement_is_absent_when_the_fingerprint_is_not_registered(self) -> None:
        # waxseal-fg4.44: `FingerprintRegistry.lookup` never reverts -- an
        # unregistered fingerprint answers with EMPTY bytes, a real contract
        # answer this fake node reproduces exactly (contracts/src/
        # FingerprintRegistry.sol). Distinct from the killed-node test above:
        # both hand `registry_agreement` a `None` descriptor internally, but
        # one is a measured "no" and the other is nothing measured at all.
        cross, fp, _ = self.known()
        finding = reader(both(calls({LOOKUP: ok(dynamic_bytes(b""))}))).registry_agreement(
            cross, fp
        )
        assert finding.status == REGISTRY_ABSENT

    def test_absent_and_unreachable_render_as_different_states(self) -> None:
        cross, fp, _ = self.known()
        absent = reader(both(calls({LOOKUP: ok(dynamic_bytes(b""))}))).registry_agreement(cross, fp)
        unreachable = reader({URL_A: Down("refused"), URL_B: Down("refused")}).registry_agreement(
            cross, fp
        )
        assert absent.status != unreachable.status
        assert absent.reason != unreachable.reason
        # Both are still exit 2 -- never a break -- which is exactly why the
        # status string, not the exit code, is what has to carry the fact.
        assert absent.to_verdict().to_exit_code() == unreachable.to_verdict().to_exit_code() == 2

    def test_a_registry_disagreement_between_endpoints_is_not_flattened(self) -> None:
        cross, fp, raw = self.known()
        with pytest.raises(LedgerDisagreement):
            reader(
                {
                    URL_A: calls({LOOKUP: ok(dynamic_bytes(raw))}),
                    URL_B: calls({LOOKUP: ok(dynamic_bytes(b"other"))}),
                }
            ).registry_agreement(cross, fp)


# ============================================================ the write path


CHAIN_ID = 31337
BLOCK = 12
TX_HASH = "0x" + "ee" * 32


class FakeChain:
    """A node that accepts one transaction and mines it.

    Configurable failure points, one per branch the sink has to get right —
    each of them a thing a real node does, not an invented error.
    """

    def __init__(
        self,
        *,
        estimate: dict[str, Any] | None = None,
        send: dict[str, Any] | None = None,
        status: int = 1,
        receipt_after: int = 0,
        finalized_after: int = 0,
        block: dict[str, Any] | None = None,
    ) -> None:
        self.sent: list[str] = []
        self.calldata: list[str] = []
        self._estimate = estimate
        self._send = send
        self._status = status
        self._receipt_after = receipt_after
        self._finalized_after = finalized_after
        self._block = block
        self._receipt_asks = 0
        self._final_asks = 0

    def __call__(self, method: str, params: list[Any]) -> dict[str, Any]:
        if method == "eth_chainId":
            return ok(hex(CHAIN_ID))
        if method == "eth_getTransactionCount":
            return ok("0x7")
        if method == "eth_maxPriorityFeePerGas":
            return ok("0x3b9aca00")
        if method == "eth_getBlockByNumber":
            if params[0] == "latest":
                return ok(self._block if self._block is not None else {"baseFeePerGas": "0x7"})
            self._final_asks += 1
            height = BLOCK if self._final_asks > self._finalized_after else BLOCK - 1
            return ok({"number": hex(height)})
        if method == "eth_estimateGas":
            self.calldata.append(params[0]["data"])
            return self._estimate if self._estimate is not None else ok("0x186a0")
        if method == "eth_sendRawTransaction":
            self.sent.append(params[0])
            return self._send if self._send is not None else ok(TX_HASH)
        if method == "eth_getTransactionReceipt":
            self._receipt_asks += 1
            if self._receipt_asks <= self._receipt_after:
                return ok(None)
            return ok({"status": hex(self._status), "blockNumber": hex(BLOCK)})
        raise AssertionError(f"fake chain has no answer for {method}")


class FakeSigner:
    """A `TransactionSigner` that records the fields it was handed."""

    address = WRITER
    public_id = WRITER

    def __init__(self, *, raw: bytes = b"\x02\xf8signed", signature: bytes = b"\x01" * 65) -> None:
        self.fields: list[Mapping[str, object]] = []
        self.digests: list[bytes] = []
        self._raw = raw
        self._signature = signature

    def sign(self, digest32: bytes) -> bytes:
        self.digests.append(digest32)
        return self._signature

    def sign_transaction(self, fields: Mapping[str, object]) -> bytes:
        self.fields.append(dict(fields))
        return self._raw


def sink(chain: FakeChain, *, signer: FakeSigner | None = None, **kwargs: Any) -> EvmLedgerSink:
    built = EvmLedgerReader(
        [URL_A, URL_B],
        EvmContracts(liveness=LIVENESS_ADDRESS, registry=REGISTRY_ADDRESS, bond=BOND_ADDRESS),
        transport=cluster({URL_A: chain, URL_B: chain}),
    )
    return EvmLedgerSink(
        built,
        signer or FakeSigner(),
        sleep_fn=lambda _seconds: None,
        **kwargs,
    )


CHECKPOINT = Checkpoint(seq=41, entry_hash=ENTRY_HASH, root=ROOT)


class TestSinkConstruction:
    def test_zero_polls_is_refused(self) -> None:
        with pytest.raises(ValueError, match="max_polls must be at least 1"):
            sink(FakeChain(), max_polls=0)

    def test_writes_default_to_the_first_endpoint(self) -> None:
        # A transaction is submitted, not measured: there is no quorum to
        # take, so the sink names one endpoint rather than pretending.
        chain = FakeChain()
        seen: list[str] = []

        def transport(request: RemoteRequest) -> RemoteResponse:
            seen.append(request.url)
            payload = json.loads(request.body or b"{}")
            return RemoteResponse(
                status=200, body=json.dumps(chain(payload["method"], payload["params"])).encode()
            )

        built = EvmLedgerReader(
            [URL_A, URL_B], EvmContracts(registry=REGISTRY_ADDRESS), transport=transport
        )
        EvmLedgerSink(built, FakeSigner(), sleep_fn=lambda _s: None).register_fingerprint(b"d")
        assert set(seen) == {URL_A}

    def test_an_explicit_write_endpoint_wins(self) -> None:
        chain = FakeChain()
        built = EvmLedgerReader(
            [URL_A, URL_B],
            EvmContracts(registry=REGISTRY_ADDRESS),
            transport=cluster({URL_A: chain, URL_B: chain}),
        )
        written = EvmLedgerSink(
            built, FakeSigner(), rpc_url=URL_B, sleep_fn=lambda _s: None
        ).register_fingerprint(b"d")
        assert written == TX_HASH


class TestSinkTransactions:
    def test_register_fingerprint_sends_the_descriptor_only(self) -> None:
        chain = FakeChain()
        assert sink(chain).register_fingerprint(b"a descriptor") == TX_HASH
        # The contract computes sha256(descriptor) itself, so there is no
        # fingerprint argument that could disagree with the bytes beside it.
        expected = abi.encode_call(abi.SELECTOR_REGISTER, [abi.encode_bytes(b"a descriptor")])
        assert chain.calldata == ["0x" + expected.hex()]

    def test_the_signed_fields_are_eip_1559_and_carry_the_headroom(self) -> None:
        signer = FakeSigner()
        sink(FakeChain(), signer=signer).register_fingerprint(b"d")
        fields = signer.fields[0]
        assert fields["type"] == 2
        assert fields["chainId"] == CHAIN_ID
        assert fields["nonce"] == 7
        assert fields["maxPriorityFeePerGas"] == 0x3B9ACA00
        # 2 * baseFee + tip: a bare base+tip stops being includable after one
        # busy block, since the base fee can rise 12.5% per block.
        assert fields["maxFeePerGas"] == 2 * 7 + 0x3B9ACA00

    def test_the_signer_is_the_only_thing_that_ever_sees_a_key(self) -> None:
        signer = FakeSigner(raw=b"\x02raw-signed-bytes")
        chain = FakeChain()
        sink(chain, signer=signer).register_fingerprint(b"d")
        assert chain.sent == ["0x" + b"\x02raw-signed-bytes".hex()]

    def test_register_trail_uses_the_deployed_selector(self) -> None:
        chain = FakeChain()
        assert sink(chain).register_trail("trail", WRITER, 3600) == TX_HASH
        assert chain.calldata[0].startswith("0x" + SELECTOR_REGISTER_TRAIL.hex())

    def test_submit_checkpoint_carries_the_sixth_argument(self) -> None:
        chain = FakeChain()
        proof = ["11" * 32, "22" * 32]
        sink(chain).submit_checkpoint("trail", CHECKPOINT, b"\x01" * 65, consistency_proof=proof)
        expected = abi.encode_call(
            SELECTOR_SUBMIT_HEAD,
            [
                abi.encode_bytes32(trail_id_for("trail")),
                abi.encode_uint(41, bits=64),
                abi.encode_bytes32(ENTRY_HASH),
                abi.encode_bytes32(ROOT),
                abi.encode_bytes(b"\x01" * 65),
                abi.encode_bytes32_array(proof),
            ],
        )
        assert chain.calldata == ["0x" + expected.hex()]

    def test_deposit_bond_sends_value(self) -> None:
        signer = FakeSigner()
        assert sink(FakeChain(), signer=signer).deposit_bond(10**18) == TX_HASH
        assert signer.fields[0]["value"] == 10**18

    def test_a_receipt_that_arrives_late_is_waited_for(self) -> None:
        chain = FakeChain(receipt_after=2)
        assert sink(chain).register_fingerprint(b"d") == TX_HASH

    def test_finality_is_waited_for_not_assumed(self) -> None:
        chain = FakeChain(finalized_after=2)
        assert sink(chain).register_fingerprint(b"d") == TX_HASH

    def test_a_receipt_that_never_arrives_times_out_loudly(self) -> None:
        chain = FakeChain(receipt_after=99)
        with pytest.raises(LedgerUnreachable, match="still unresolved after 3 polls"):
            sink(chain, max_polls=3).register_fingerprint(b"d")

    def test_a_head_that_never_finalizes_times_out_loudly(self) -> None:
        # A dev node whose `finalized` never advances gets a message naming
        # both numbers, never a claim of finality it did not observe.
        chain = FakeChain(finalized_after=99)
        with pytest.raises(LedgerUnreachable, match=f"in block {BLOCK} reaching finalized"):
            sink(chain, max_polls=2).register_fingerprint(b"d")

    def test_a_confirm_tag_the_node_cannot_serve_times_out(self) -> None:
        chain = FakeChain()
        chain._block = {"baseFeePerGas": "0x7"}

        class NoTag(FakeChain):
            def __call__(self, method: str, params: list[Any]) -> dict[str, Any]:
                if method == "eth_getBlockByNumber" and params[0] == "finalized":
                    return ok(None)
                return super().__call__(method, params)

        with pytest.raises(LedgerUnreachable, match="reaching finalized"):
            sink(NoTag(), max_polls=2).register_fingerprint(b"d")


class TestSinkFailures:
    def test_a_revert_on_estimate_is_a_rejection_not_an_unreachability(self) -> None:
        # The read path reads an unrecognised revert as "unmeasured"; the
        # write path reads it as the contract SAYING NO. Sending anyway would
        # spend the operator's gas to learn what the estimate already said.
        chain = FakeChain(estimate=revert("b3d47474"))
        with pytest.raises(LedgerError, match="the contract rejected this call") as caught:
            sink(chain).register_fingerprint(b"d")
        assert not isinstance(caught.value, LedgerUnreachable)
        assert chain.sent == []

    def test_a_rejected_broadcast_is_a_ledger_error(self) -> None:
        chain = FakeChain(send=revert("deadbeef"))
        with pytest.raises(LedgerError, match="the node rejected the transaction"):
            sink(chain).register_fingerprint(b"d")

    def test_a_signer_returning_nothing_is_refused(self) -> None:
        with pytest.raises(LedgerError, match="no transaction bytes"):
            sink(FakeChain(), signer=FakeSigner(raw=b"")).register_fingerprint(b"d")

    def test_a_transaction_that_reverts_on_chain_is_a_failure_not_a_receipt(self) -> None:
        # LedgerSink's contract: raise on failure, never a quiet "no receipt"
        # a caller would read as a successful publish.
        with pytest.raises(LedgerError, match="reverted on chain"):
            sink(FakeChain(status=0)).register_fingerprint(b"d")

    def test_a_node_with_no_latest_block_is_unmeasured(self) -> None:
        chain = FakeChain()
        chain._block = None

        class NoBlock(FakeChain):
            def __call__(self, method: str, params: list[Any]) -> dict[str, Any]:
                if method == "eth_getBlockByNumber" and params[0] == "latest":
                    return ok("not a block")
                return super().__call__(method, params)

        with pytest.raises(LedgerUnreachable, match="no latest block"):
            sink(NoBlock()).register_fingerprint(b"d")

    def test_a_block_with_no_base_fee_is_unmeasured(self) -> None:
        with pytest.raises(LedgerUnreachable, match="not a quantity"):
            sink(FakeChain(block={})).register_fingerprint(b"d")

    def test_a_gas_estimate_that_is_not_a_quantity_is_unmeasured(self) -> None:
        with pytest.raises(LedgerUnreachable, match="not a hex quantity"):
            sink(FakeChain(estimate=ok("0xnope"))).register_fingerprint(b"d")


class TestFraudProofs:
    @staticmethod
    def pair(seq_b: int = 41, root_b: str = "ff" * 32) -> EquivocationProof:
        return EquivocationProof(
            chain_id="trail",
            checkpoint_a=CHECKPOINT,
            signature_a=b"\x01" * 65,
            checkpoint_b=Checkpoint(seq=seq_b, entry_hash=ENTRY_HASH, root=root_b),
            signature_b=b"\x02" * 65,
        )

    def test_an_equivocation_is_encoded_with_struct_arguments(self) -> None:
        chain = FakeChain()
        assert sink(chain).submit_fraud_proof(self.pair()) == TX_HASH
        calldata = bytes.fromhex(chain.calldata[0][2:])
        assert calldata[:4] == SELECTOR_PROVE_EQUIVOCATION
        # trailId, seq, then two offsets into the tail — the shape a dynamic
        # struct argument takes. A flattened encoding would put the entry hash
        # in word 3 instead of an offset.
        assert calldata[4:36] == trail_id_for("trail")
        assert int.from_bytes(calldata[36:68], "big") == 41
        assert int.from_bytes(calldata[68:100], "big") == 4 * 32

    def test_a_structurally_inadmissible_pair_is_refused_before_the_gas(self) -> None:
        chain = FakeChain()
        with pytest.raises(LedgerError, match="not an equivocation: seq_mismatch"):
            sink(chain).submit_fraud_proof(self.pair(seq_b=9))
        assert chain.calldata == []

    @staticmethod
    def divergence(index: int = 3, newer_hash: str = "cc" * 32) -> NonExtensionProof:
        return NonExtensionProof(
            chain_id="trail",
            older=CHECKPOINT,
            newer=Checkpoint(seq=99, entry_hash=ENTRY_HASH, root=ROOT),
            older_signature=b"\x01" * 65,
            newer_signature=b"\x02" * 65,
            in_older=DivergentLeaf(index=index, entry_hash="aa" * 32, proof=["bb" * 32]),
            in_newer=DivergentLeaf(index=index, entry_hash=newer_hash, proof=["dd" * 32]),
        )

    def test_a_non_extension_proof_goes_through_the_same_one_door(self) -> None:
        # Through 0.1.5 this raised: the domain type carried a consistency
        # proof the deployed contract does not accept, so `submit_fraud_proof`
        # refused its own argument type. The domain type is now the
        # divergent-leaf evidence the contract takes, and the door is one.
        chain = FakeChain()
        assert sink(chain).submit_fraud_proof(self.divergence()) == TX_HASH
        calldata = bytes.fromhex(chain.calldata[0][2:])
        assert calldata[:4] == SELECTOR_PROVE_NON_EXTENSION
        assert calldata[4:36] == trail_id_for("trail")
        assert bytes.fromhex("aa" * 32) in calldata and bytes.fromhex("cc" * 32) in calldata

    def test_a_structurally_inadmissible_divergence_is_refused_before_the_gas(self) -> None:
        # Two leaves that agree are not a contradiction; the contract reverts
        # on it (`LeavesAgree`), so sending it only buys the gas that paid for
        # the revert. Same guard `submit_fraud_proof` already had for an
        # equivocation, now on both branches instead of one.
        chain = FakeChain()
        with pytest.raises(LedgerError, match="not a non-extension: leaves_agree"):
            sink(chain).submit_fraud_proof(self.divergence(newer_hash="aa" * 32))
        assert chain.calldata == []

    def test_a_divergent_leaf_encodes_index_hash_and_proof(self) -> None:
        blob = bytes(leaf_claim(DivergentLeaf(index=3, entry_hash="aa" * 32, proof=["bb" * 32])))
        assert int.from_bytes(blob[:32], "big") == 3
        assert blob[32:64] == bytes.fromhex("aa" * 32)
        assert int.from_bytes(blob[64:96], "big") == 3 * 32
        assert int.from_bytes(blob[96:128], "big") == 1


# =========================================================== the anchor sink


class TestEvmAnchorSink:
    def test_it_signs_the_pinned_digest_and_returns_a_locatable_receipt(self) -> None:
        from waxseal.domain.bond import checkpoint_signing_digest

        chain = FakeChain()
        signer = FakeSigner()
        receipt = EvmAnchorSink(sink(chain), "trail", signer).anchor(CHECKPOINT)
        assert signer.digests == [checkpoint_signing_digest("trail", CHECKPOINT)]
        # evm:<chainid>:<block>:<txhash> — an operator can re-derive the
        # transaction from the receipt alone, with no lookup table.
        assert receipt == f"evm:{CHAIN_ID}:{BLOCK}:{TX_HASH}"

    def test_a_signature_of_the_wrong_length_is_caught_before_the_gas(self) -> None:
        # recoverSigner returns address(0) for anything but 65 bytes, which
        # the contract reports only after the transaction has been paid for.
        with pytest.raises(LedgerError, match="reads exactly 65"):
            EvmAnchorSink(sink(FakeChain()), "trail", FakeSigner(signature=b"\x01" * 64)).anchor(
                CHECKPOINT
            )

    def test_an_injected_proof_fn_supplies_the_consistency_proof(self) -> None:
        chain = FakeChain()
        proof = ["ab" * 32]
        EvmAnchorSink(sink(chain), "trail", FakeSigner(), proof_fn=lambda _cp: proof).anchor(
            CHECKPOINT
        )
        assert bytes.fromhex("ab" * 32) in bytes.fromhex(chain.calldata[0][2:])

    def test_the_sink_names_itself_evm(self) -> None:
        assert EvmAnchorSink(sink(FakeChain()), "trail", FakeSigner()).name == "evm"

    def test_the_receipt_dataclass_formats_its_own_string(self) -> None:
        assert EvmTxReceipt("0xab", 7, 1).anchor_receipt() == "evm:1:7:0xab"


# ================================================== selectors are not guessed


class TestSelectorsMatchTheCompiler:
    """Every four-byte constant this adapter sends, checked against the file
    `forge inspect` writes. Python cannot compute a selector (no keccak256 in
    the stdlib), so a constant nobody compares against the compiler is a
    constant that drifts — which is exactly what happened between F1's
    domain/abi.py and F2's deployed contracts."""

    @staticmethod
    def frozen() -> dict[str, dict[str, str]]:
        result: dict[str, dict[str, str]] = json.loads(
            (REPO / "contracts" / "abi" / "selectors.json").read_text(encoding="utf-8")
        )
        return result

    def test_every_selector_the_adapter_uses_is_the_compiled_one(self) -> None:
        compiled = self.frozen()
        used = {
            ("AnchoringLiveness", "lastSeen(bytes32)"): abi.SELECTOR_LAST_SEEN,
            ("AnchoringLiveness", "isDelinquent(bytes32)"): abi.SELECTOR_IS_DELINQUENT,
            ("AnchoringLiveness", "deadlineOf(bytes32)"): SELECTOR_DEADLINE_OF,
            ("AnchoringLiveness", "registerTrail(bytes32,address,uint64)"): SELECTOR_REGISTER_TRAIL,
            (
                "AnchoringLiveness",
                "submit(bytes32,uint64,bytes32,bytes32,bytes,bytes32[])",
            ): SELECTOR_SUBMIT_HEAD,
            ("FingerprintRegistry", "register(bytes)"): abi.SELECTOR_REGISTER,
            ("FingerprintRegistry", "lookup(bytes32)"): abi.SELECTOR_LOOKUP,
            ("BondedCheckpoints", "bondOf(address)"): abi.SELECTOR_BOND_OF,
            ("BondedCheckpoints", "deposit()"): abi.SELECTOR_DEPOSIT,
            (
                "BondedCheckpoints",
                "proveEquivocation(bytes32,uint64,(uint64,bytes32,bytes32,bytes),"
                "(uint64,bytes32,bytes32,bytes))",
            ): SELECTOR_PROVE_EQUIVOCATION,
            (
                "BondedCheckpoints",
                "proveNonExtension(bytes32,(uint64,bytes32,bytes32,bytes),"
                "(uint64,bytes32,bytes32,bytes),(uint256,bytes32,bytes32[]),"
                "(uint256,bytes32,bytes32[]))",
            ): SELECTOR_PROVE_NON_EXTENSION,
        }
        mismatched = [
            f"{contract}.{signature}: adapter {selector.hex()} != compiled "
            f"{compiled[contract].get(signature)}"
            for (contract, signature), selector in used.items()
            if compiled[contract].get(signature) != selector.hex()
        ]
        assert mismatched == []

    def test_the_domain_selectors_this_adapter_does_not_use_are_the_stale_ones(self) -> None:
        # Recorded, not fixed: domain/ belongs to F1 and is out of this bead's
        # scope. These four describe an earlier draft of the contracts, and an
        # adapter that consumed them would send calldata every deployed
        # AnchoringLiveness/BondedCheckpoints rejects.
        compiled = self.frozen()
        signatures = {
            "AnchoringLiveness": [
                "deadline(bytes32)",
                "submit(bytes32,uint64,bytes32,bytes32,bytes)",
            ],
            "BondedCheckpoints": ["isSlashed(address)"],
        }
        absent = [
            f"{contract}.{signature}"
            for contract, names in signatures.items()
            for signature in names
            if signature not in compiled[contract]
        ]
        assert sorted(absent) == [
            "AnchoringLiveness.deadline(bytes32)",
            "AnchoringLiveness.submit(bytes32,uint64,bytes32,bytes32,bytes)",
            "BondedCheckpoints.isSlashed(address)",
        ]


class TestTheCoreDoesNotImportTheExtra:
    def test_importing_waxseal_does_not_load_the_evm_adapter(self) -> None:
        # CLAUDE.md rule 1: the `evm` extra must not reach the core. Run in a
        # fresh interpreter, because this test module has already imported it.
        import subprocess
        import sys

        probe = "import sys, waxseal;loaded=[m for m in sys.modules if 'evm' in m];print(loaded)"
        out = subprocess.run(
            [sys.executable, "-c", probe],
            capture_output=True,
            text=True,
            check=True,
            encoding="utf-8",
        )
        assert out.stdout.strip() == "[]"

    def test_the_evm_extra_pulls_no_dependency(self) -> None:
        import tomllib

        data = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))
        assert data["project"]["optional-dependencies"]["evm"] == []
        assert data["project"]["dependencies"] == []
