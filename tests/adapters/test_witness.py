"""HTTPWitness: publish a checkpoint, read back what the witness saw.

Both halves matter and both are tested against the same injected transport the
rest of the HTTP adapters use. The read half's contract is the interesting one:

- 404 means "this witness holds nothing", which is a real answer;
- a body that is not a checkpoint list is a raise, not an empty answer. A
  captive portal, a proxy error page, or a witness that changed its API must
  never reach a verifier looking like "the witness saw nothing".
- individual records this build cannot read are counted, not dropped. Coverage
  that was not measured has to stay visible as unmeasured.
"""

from __future__ import annotations

import json

import pytest

from waxseal.adapters.remote import RemoteError, RemoteRequest, RemoteResponse
from waxseal.adapters.witness import HTTPWitness
from waxseal.domain.checkpoint import Checkpoint

CP = Checkpoint(seq=2, entry_hash="a" * 64, root="b" * 64)


def responder(status: int, body: bytes):  # type: ignore[no-untyped-def]
    sent: list[RemoteRequest] = []

    def transport(request: RemoteRequest) -> RemoteResponse:
        sent.append(request)
        return RemoteResponse(status=status, headers={}, body=body)

    return transport, sent


def checkpoints_body(*records: dict[str, object]) -> bytes:
    return json.dumps({"checkpoints": list(records)}).encode()


class TestPublish:
    def test_posts_the_checkpoint(self) -> None:
        transport, sent = responder(200, b"{}")
        HTTPWitness("http://witness/anchor", transport=transport).anchor(CP)
        assert sent[0].method == "POST"
        body = json.loads(sent[0].body)  # type: ignore[arg-type]
        assert body == {"seq": 2, "entry_hash": "a" * 64, "root": "b" * 64}

    def test_returns_the_receipt(self) -> None:
        transport, _ = responder(201, b'{"receipt": "r-1"}')
        assert HTTPWitness("http://w/a", transport=transport).anchor(CP) == "r-1"

    def test_non_2xx_raises(self) -> None:
        # AnchorSink's contract: never return as if it had succeeded.
        transport, _ = responder(503, b"")
        with pytest.raises(RuntimeError):
            HTTPWitness("http://w/a", transport=transport).anchor(CP)

    def test_bearer_token_is_a_header_never_the_url(self) -> None:
        transport, sent = responder(200, b"{}")
        HTTPWitness("http://w/a", transport=transport, api_key="s3cret").anchor(CP)
        assert sent[0].headers["Authorization"] == "Bearer s3cret"
        assert "s3cret" not in sent[0].url


class TestFetch:
    def test_reads_checkpoints_oldest_first(self) -> None:
        transport, sent = responder(
            200,
            checkpoints_body(
                {"seq": 0, "entry_hash": "1" * 64, "root": "2" * 64},
                {"seq": 1, "entry_hash": "3" * 64, "root": "4" * 64},
            ),
        )
        observation = HTTPWitness("http://w/a", transport=transport).fetch()
        assert sent[0].method == "GET"
        assert [cp.seq for cp in observation.checkpoints] == [0, 1]
        assert observation.unreadable == 0

    def test_404_is_an_empty_observation_not_an_error(self) -> None:
        transport, _ = responder(404, b"")
        assert HTTPWitness("http://w/a", transport=transport).fetch().checkpoints == ()

    def test_unknown_keys_are_ignored(self) -> None:
        transport, _ = responder(
            200,
            checkpoints_body(
                {
                    "seq": 0, "entry_hash": "1" * 64, "root": "2" * 64,
                    "witnessed_at": "2026-08-23", "signature": "...",
                }
            ),
        )
        assert len(HTTPWitness("http://w/a", transport=transport).fetch().checkpoints) == 1

    def test_reads_the_aggregate_binding_when_present(self) -> None:
        transport, _ = responder(
            200,
            checkpoints_body(
                {
                    "seq": 0, "entry_hash": "1" * 64, "root": "2" * 64,
                    "agg_commit": "3" * 64, "agg_epoch": 1,
                }
            ),
        )
        cp = HTTPWitness("http://w/a", transport=transport).fetch().checkpoints[0]
        assert cp.agg_commit == "3" * 64
        assert cp.agg_epoch == 1

    def test_records_missing_required_fields_are_counted_not_dropped(self) -> None:
        transport, _ = responder(
            200,
            checkpoints_body(
                {"seq": 0, "entry_hash": "1" * 64, "root": "2" * 64},
                {"seq": 1},
                {"nonsense": True},
            ),
        )
        observation = HTTPWitness("http://w/a", transport=transport).fetch()
        assert len(observation.checkpoints) == 1
        assert observation.unreadable == 2

    def test_non_object_records_are_counted_unreadable(self) -> None:
        transport, _ = responder(200, json.dumps({"checkpoints": ["nope", 7]}).encode())
        observation = HTTPWitness("http://w/a", transport=transport).fetch()
        assert observation.checkpoints == ()
        assert observation.unreadable == 2

    @pytest.mark.parametrize(
        "body",
        [b"", b"not json", b"[]", b'"text"', b"{}", b'{"checkpoints": "nope"}'],
    )
    def test_an_unusable_body_raises(self, body: bytes) -> None:
        transport, _ = responder(200, body)
        with pytest.raises(RemoteError):
            HTTPWitness("http://w/a", transport=transport).fetch()

    def test_a_non_protocol_status_raises(self) -> None:
        transport, _ = responder(500, b"upstream on fire")
        with pytest.raises(RemoteError):
            HTTPWitness("http://w/a", transport=transport).fetch()

    def test_auth_header_is_sent_on_reads_too(self) -> None:
        transport, sent = responder(200, checkpoints_body())
        HTTPWitness("http://w/a", transport=transport, api_key="k").fetch()
        assert sent[0].headers["Authorization"] == "Bearer k"


class TestIdentity:
    def test_name_defaults_to_the_url(self) -> None:
        # Verdicts are printed per witness; an operator with three of them
        # needs to know which one disagreed.
        assert HTTPWitness("http://notary.example/anchor").name == "http://notary.example/anchor"

    def test_name_can_be_given(self) -> None:
        assert HTTPWitness("http://w/a", name="notary-eu").name == "notary-eu"
