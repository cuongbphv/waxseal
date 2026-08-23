"""Tests for the S3 backend against a high-fidelity fake client.

The fake enforces the two S3 behaviors the backend's correctness rests on:
conditional PUT (`IfNoneMatch="*"` -> 412 PreconditionFailed when the key
exists) and key-ordered ListObjectsV2 pagination. The real client (boto3) is
injected by the caller — waxseal itself imports nothing non-stdlib.
"""

import json
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from tests.adapters.backend_contract import BackendContractTests
from tests.adapters.test_jsonl import build_entry
from waxseal import AuditLog, VersionRegistry, verify_chain
from waxseal.adapters.s3 import S3Backend
from waxseal.domain.header import GENESIS_PREV_HASH

PT = "application/vnd.test.event+json"


class FakeClientError(Exception):
    def __init__(self, code: str):
        self.response = {"Error": {"Code": code}}
        super().__init__(code)


class FakeBody:
    def __init__(self, data: bytes):
        self._data = data

    def read(self) -> bytes:
        return self._data


class FakeS3Client:
    """Just enough of the boto3 S3 client surface, with real 412 semantics."""

    def __init__(self) -> None:
        self._objects: dict[tuple[str, str], bytes] = {}
        self._lock = threading.Lock()

    def put_object(self, *, Bucket: str, Key: str, Body: bytes, **kwargs) -> dict:
        with self._lock:
            if kwargs.get("IfNoneMatch") == "*" and (Bucket, Key) in self._objects:
                raise FakeClientError("PreconditionFailed")
            self._objects[(Bucket, Key)] = Body
        return {}

    def get_object(self, *, Bucket: str, Key: str) -> dict:
        with self._lock:
            if (Bucket, Key) not in self._objects:
                raise FakeClientError("NoSuchKey")
            return {"Body": FakeBody(self._objects[(Bucket, Key)])}

    def list_objects_v2(self, *, Bucket: str, Prefix: str, **kwargs) -> dict:
        with self._lock:
            keys = sorted(
                k for (b, k) in self._objects if b == Bucket and k.startswith(Prefix)
            )
        start = kwargs.get("StartAfter", "")
        keys = [k for k in keys if k > start]
        page, rest = keys[:2], keys[2:]  # tiny page size to exercise pagination
        out = {"Contents": [{"Key": k} for k in page], "IsTruncated": bool(rest)}
        if rest:
            out["NextContinuationToken"] = page[-1]
        if "ContinuationToken" in kwargs:
            token = kwargs["ContinuationToken"]
            keys_after = [k for k in keys if k > token]
            page, rest = keys_after[:2], keys_after[2:]
            out = {"Contents": [{"Key": k} for k in page], "IsTruncated": bool(rest)}
            if rest:
                out["NextContinuationToken"] = page[-1]
        return out


@pytest.fixture()
def backend() -> S3Backend:
    return S3Backend(FakeS3Client(), bucket="audit", prefix="trail")


class TestS3BackendContract(BackendContractTests):
    # A base-class fixture wins over a same-named module fixture in pytest's
    # resolution order (class scope is closer than module scope), so the
    # module-level `backend` above can't be "reused" by omission — it must be
    # re-exposed here or the abstract NotImplementedError fixture shadows it.
    @pytest.fixture()
    def backend(self) -> S3Backend:
        return S3Backend(FakeS3Client(), bucket="audit", prefix="trail")


class TestAppend:
    def test_first_append_gets_seq_0_and_genesis_prev(self, backend: S3Backend) -> None:
        seen: list[tuple[int, str]] = []

        def build(seq: int, prev: str):
            seen.append((seq, prev))
            return build_entry(seq, prev)

        backend.append(build)
        assert seen == [(0, GENESIS_PREV_HASH)]

    def test_round_trip_and_verify_across_pagination(self, backend: S3Backend) -> None:
        for _ in range(7):  # > page size to force pagination
            backend.append(lambda seq, prev: build_entry(seq, prev))
        assert verify_chain(backend.entries(), VersionRegistry()).checked == 7

    def test_lost_conditional_write_race_is_retried(self) -> None:
        # Two writers over the SAME store: conditional PUT must serialize them.
        client = FakeS3Client()
        a = S3Backend(client, bucket="audit", prefix="trail")
        b = S3Backend(client, bucket="audit", prefix="trail")

        def worker(backend: S3Backend) -> None:
            for _ in range(20):
                backend.append(lambda seq, prev: build_entry(seq, prev))

        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(worker, [a, b, a, b]))
        entries = list(a.entries())
        assert [e.header.seq for e in entries] == list(range(80))
        assert verify_chain(entries, VersionRegistry()).ok

    def test_auditlog_works_over_s3_backend(self, backend: S3Backend) -> None:
        log = AuditLog(backend, now_fn=lambda: "2026-08-21T06:00:00+00:00")
        log.append(payload={"i": 1}, payload_type=PT)
        assert log.verify().ok


class TestStorageLayout:
    def test_entry_objects_are_zero_padded_json(self, backend: S3Backend) -> None:
        backend.append(lambda seq, prev: build_entry(seq, prev))
        client = backend._client
        body = client.get_object(Bucket="audit", Key="trail/entries/00000000000000000000.json")
        obj = json.loads(body["Body"].read())
        assert set(obj) == {"header", "entry_hash", "payload_b64"}


class TestConditionalWriteRetry:
    """CLAUDE.md rule 7 for object storage. The thread test above proves the
    two writers end up with one chain; these prove the retry path itself,
    deterministically — a lock that happens to serialize the fake would let
    that path rot untested and only the third writer in production would find
    out.
    """

    def rejecting_client(self, failures: int, error: Exception) -> FakeS3Client:
        client = FakeS3Client()
        real_put = client.put_object
        remaining = [failures]

        def put_object(*, Bucket: str, Key: str, Body: bytes, **kwargs) -> dict:
            if "entries/" in Key and remaining[0] > 0:
                remaining[0] -= 1
                raise error
            return real_put(Bucket=Bucket, Key=Key, Body=Body, **kwargs)

        client.put_object = put_object  # type: ignore[method-assign]
        return client

    def test_a_lost_race_is_rebuilt_on_a_fresh_tail(self) -> None:
        client = self.rejecting_client(1, FakeClientError("PreconditionFailed"))
        backend = S3Backend(client, bucket="audit", prefix="trail")
        seen: list[int] = []

        def build(seq: int, prev: str):
            seen.append(seq)
            return build_entry(seq, prev)

        entry = backend.append(build)
        # The entry is rebuilt, not resubmitted: a retry that reused the first
        # build's (seq, prev_hash) would fork the chain rather than extend it.
        assert seen == [0, 0]
        assert entry.header.seq == 0

    def test_a_412_by_status_code_is_also_a_lost_race(self) -> None:
        client = self.rejecting_client(1, FakeClientError("412"))
        backend = S3Backend(client, bucket="audit", prefix="trail")
        assert backend.append(lambda seq, prev: build_entry(seq, prev)).header.seq == 0

    def test_any_other_error_propagates_rather_than_looping(self) -> None:
        # A permissions failure retried 32 times is 32 failures and then a
        # misleading "contention is pathological" message.
        client = self.rejecting_client(1, FakeClientError("AccessDenied"))
        backend = S3Backend(client, bucket="audit", prefix="trail")
        with pytest.raises(FakeClientError, match="AccessDenied"):
            backend.append(lambda seq, prev: build_entry(seq, prev))

    def test_an_error_with_no_response_payload_propagates(self) -> None:
        # `_error_code` must survive an exception that is not a boto3
        # ClientError at all — an injected client can raise anything.
        client = self.rejecting_client(1, RuntimeError("socket closed"))
        backend = S3Backend(client, bucket="audit", prefix="trail")
        with pytest.raises(RuntimeError, match="socket closed"):
            backend.append(lambda seq, prev: build_entry(seq, prev))

    def test_endless_contention_gives_up_with_a_named_reason(self) -> None:
        client = self.rejecting_client(10_000, FakeClientError("PreconditionFailed"))
        backend = S3Backend(client, bucket="audit", prefix="trail")
        with pytest.raises(RuntimeError, match="pathological"):
            backend.append(lambda seq, prev: build_entry(seq, prev))


class TestTailDiscovery:
    def test_a_stale_head_hint_is_corrected_by_probing_forward(self) -> None:
        # head.json is a hint, never the truth: a writer that crashed between
        # the entry PUT and the head PUT leaves it behind. Trusting it would
        # overwrite a committed entry's seq.
        client = FakeS3Client()
        backend = S3Backend(client, bucket="audit", prefix="trail")
        for _ in range(3):
            backend.append(lambda seq, prev: build_entry(seq, prev))

        client.put_object(
            Bucket="audit",
            Key="trail/head.json",
            Body=json.dumps({"seq": 0, "entry_hash": "0" * 64}).encode(),
        )
        entry = backend.append(lambda seq, prev: build_entry(seq, prev))
        assert entry.header.seq == 3

    def test_an_unreadable_head_falls_back_to_genesis_and_probes(self) -> None:
        client = FakeS3Client()
        backend = S3Backend(client, bucket="audit", prefix="trail")
        backend.append(lambda seq, prev: build_entry(seq, prev))
        client.put_object(Bucket="audit", Key="trail/head.json", Body=b"{ not json")
        assert backend.append(lambda seq, prev: build_entry(seq, prev)).header.seq == 1

    def test_a_probe_error_that_is_not_a_missing_key_propagates(self) -> None:
        # Reading "not found" out of a permissions error would report the tail
        # as shorter than it is, and the next append would overwrite history.
        client = FakeS3Client()
        backend = S3Backend(client, bucket="audit", prefix="trail")
        backend.append(lambda seq, prev: build_entry(seq, prev))

        def get_object(*, Bucket: str, Key: str) -> dict:
            raise FakeClientError("AccessDenied")

        client.get_object = get_object  # type: ignore[method-assign]
        with pytest.raises(FakeClientError, match="AccessDenied"):
            backend.append(lambda seq, prev: build_entry(seq, prev))
