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
