"""The two archive destinations for a sealed segment — J3.

Neither destination is new machinery: ``s3_destination`` is a thin adapter
over J1's ``upload_sealed_segment`` (which owns the PUT and the Object Lock
question), and ``server_import_destination`` posts the segment to the
server's imported-trail endpoint, where an imported trail is read-only
evidence from the moment it lands. What this module adds is the J3 vocabulary
on top: stored / failed / not-attempted, each labelled.

The fakes follow the patterns already in this directory: ``FakeS3Client``
from ``test_s3.py`` (extended, never re-invented) for S3, and a
``Transport``-shaped fake for HTTP, exactly as ``fake_chain_server.py`` does
for ``adapters/remote.py``. No test here opens a socket.

FALSIFIABILITY RECEIPT — measured 01/09/2026, baseline **70 tests, 0
failures** across this file, tests/test_sources_rotation.py and
tests/domain/test_archive.py. One branch removed at a time, same 70 tests
re-run, counts read out of the junit XML:

    4. `if not upload.uploaded:` -> `if False:` (a missing ``s3`` extra
       reported as STORED, i.e. an archive that does not exist)
         -> exit 1, tests=70 failures=1:
            test_a_missing_s3_extra_is_not_attempted_never_failed
    5. `s3_destination`'s `except Exception` narrowed to ZeroDivisionError,
       so a rejected PUT propagates instead of becoming FAILED
         -> exit 1, tests=70 failures=1 (FakeClientError escaped):
            test_a_failing_put_is_failed_and_names_where_it_was_headed
    6. `if response.status != 201:` -> `if False:` (an HTTP 403 reported as
       STORED)
         -> exit 1, tests=70 failures=1:
            test_a_rejected_upload_is_failed_with_the_status_and_the_body
    7. the multipart boundary guard -> `if False:`
         -> exit 1, tests=70 failures=1:
            test_a_segment_containing_the_boundary_is_failed_never_sent
    8. the unsafe-filename guard -> `if False:`
         -> exit 1, tests=70 failures=1:
            test_a_filename_that_could_forge_headers_is_failed_never_sent
"""

from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta
from email.parser import BytesParser
from typing import Any

import pytest

from tests.adapters.test_s3 import FakeClientError, FakeS3Client
from waxseal.adapters.remote import RemoteRequest, RemoteResponse
from waxseal.adapters.s3 import WormRetention
from waxseal.adapters.segment_archive import (
    _MULTIPART_BOUNDARY,
    s3_destination,
    server_import_destination,
)
from waxseal.domain.archive import ArchiveState

SEGMENT = b'{"header": {"seq": 0}}\n{"header": {"seq": 1}}\n'
NAME = "trail.00000.jsonl"
NOW = datetime(2026, 8, 31, 12, 0, 0, tzinfo=UTC)


def now_fn() -> datetime:
    return NOW


class FakeLockS3Client(FakeS3Client):
    """``FakeS3Client`` plus the one Object Lock read J1 makes after a PUT."""

    def __init__(self, *, retention: Any = None, put_error: Exception | None = None) -> None:
        super().__init__()
        self.retention = retention
        self.put_error = put_error
        self.put_kwargs: dict[str, Any] = {}

    def put_object(self, *, Bucket: str, Key: str, Body: bytes, **kwargs: Any) -> dict[str, Any]:
        if self.put_error is not None:
            raise self.put_error
        self.put_kwargs = dict(kwargs)
        return super().put_object(Bucket=Bucket, Key=Key, Body=Body, **kwargs)

    def get_object_retention(self, **kwargs: Any) -> Any:
        if isinstance(self.retention, Exception):
            raise self.retention
        return self.retention

    def stored(self, bucket: str, key: str) -> bytes:
        return self._objects[(bucket, key)]


class FakeImportServer:
    """The server's ``POST /v1/imports`` endpoint, as a ``Transport``.

    It stores the bytes it actually parsed OUT of the multipart body, not the
    bytes the test handed the destination: a destination that mis-encoded the
    body would store the wrong thing here, which is the point of parsing with
    stdlib ``email`` instead of trusting the encoder.
    """

    def __init__(self, *, status: int = 201, raises: Exception | None = None) -> None:
        self.status = status
        self.raises = raises
        self.requests: list[RemoteRequest] = []
        self.files: dict[str, bytes] = {}

    def __call__(self, request: RemoteRequest) -> RemoteResponse:
        if self.raises is not None:
            raise self.raises
        self.requests.append(request)
        if self.status == 201:
            filename, content = self.parse(request)
            self.files[filename] = content
            return RemoteResponse(status=201, body=b'{"import_id": "imp-0001"}')
        return RemoteResponse(status=self.status, body=b'{"error":"denied"}')

    @staticmethod
    def parse(request: RemoteRequest) -> tuple[str, bytes]:
        assert request.body is not None
        headers = f"Content-Type: {request.headers['Content-Type']}\r\nMIME-Version: 1.0\r\n\r\n"
        message = BytesParser().parsebytes(headers.encode("ascii") + request.body)
        assert message.is_multipart()
        part = message.get_payload(0)
        assert not isinstance(part, str)
        assert part.get_param("name", header="content-disposition") == "file"
        filename = part.get_filename()
        assert filename is not None
        payload = part.get_payload(decode=True)
        assert isinstance(payload, bytes)
        return filename, payload


class TestS3DestinationStores:
    def test_a_sealed_segment_reaches_the_bucket_byte_for_byte(self) -> None:
        client = FakeLockS3Client()
        report = s3_destination(bucket="audit", client=client, now_fn=now_fn)(NAME, SEGMENT)
        assert report.state is ArchiveState.STORED
        assert client.stored("audit", NAME) == SEGMENT

    def test_the_destination_names_the_bucket_and_key_it_used(self) -> None:
        client = FakeLockS3Client()
        report = s3_destination(
            bucket="audit", key_prefix="segments/proj/", client=client, now_fn=now_fn
        )(NAME, SEGMENT)
        assert report.destination == f"s3://audit/segments/proj/{NAME}"
        assert client.stored("audit", f"segments/proj/{NAME}") == SEGMENT

    def test_the_detail_carries_j1s_worm_line_so_availability_and_immutability_stay_apart(
        self,
    ) -> None:
        # A successful PUT is availability. Whether storage REFUSES an
        # overwrite is a separate question J1 answers by asking afterwards,
        # and the two must never be printed as one fact.
        client = FakeLockS3Client(retention=FakeClientError("AccessDenied"))
        report = s3_destination(bucket="audit", client=client, now_fn=now_fn)(NAME, SEGMENT)
        assert report.state is ArchiveState.STORED
        assert "object_version/worm_unknown" in report.detail

    def test_operator_declared_retention_is_passed_through_to_j1(self) -> None:
        client = FakeLockS3Client()
        retention = WormRetention(mode="COMPLIANCE", retain_until=NOW + timedelta(days=1))
        s3_destination(bucket="audit", client=client, retention=retention, now_fn=now_fn)(
            NAME, SEGMENT
        )
        assert client.put_kwargs["ObjectLockMode"] == "COMPLIANCE"


class TestS3DestinationDoesNotCollapseItsThreeStates:
    def test_a_failing_put_is_failed_and_names_where_it_was_headed(self) -> None:
        client = FakeLockS3Client(put_error=FakeClientError("AccessDenied"))
        report = s3_destination(bucket="audit", client=client, now_fn=now_fn)(NAME, SEGMENT)
        assert report.state is ArchiveState.FAILED
        assert report.destination == f"s3://audit/{NAME}"
        assert "AccessDenied" in report.detail

    def test_a_missing_s3_extra_is_not_attempted_never_failed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Nothing was asked and nothing went wrong: the deployment simply has
        # no boto3. Rendering that as a failure would alarm an operator who
        # never opted in (CLAUDE.md rule 5).
        monkeypatch.setitem(sys.modules, "boto3", None)
        report = s3_destination(bucket="audit", now_fn=now_fn)(NAME, SEGMENT)
        assert report.state is ArchiveState.NOT_ATTEMPTED
        assert "boto3" in report.detail


class TestServerImportDestination:
    def test_a_sealed_segment_reaches_the_import_endpoint_byte_for_byte(self) -> None:
        server = FakeImportServer()
        report = server_import_destination("https://audit.example", transport=server)(NAME, SEGMENT)
        assert report.state is ArchiveState.STORED
        assert server.files == {NAME: SEGMENT}

    def test_it_posts_to_the_imports_route_of_the_wire_contract(self) -> None:
        server = FakeImportServer()
        server_import_destination("https://audit.example/", transport=server)(NAME, SEGMENT)
        assert server.requests[0].method == "POST"
        assert server.requests[0].url == "https://audit.example/v1/imports"

    def test_the_api_key_travels_as_a_bearer_header_never_in_the_url(self) -> None:
        server = FakeImportServer()
        server_import_destination("https://audit.example", transport=server, api_key="s3cret")(
            NAME, SEGMENT
        )
        assert server.requests[0].headers["Authorization"] == "Bearer s3cret"
        assert "s3cret" not in server.requests[0].url

    def test_no_api_key_sends_no_authorization_header(self) -> None:
        server = FakeImportServer()
        server_import_destination("https://audit.example", transport=server)(NAME, SEGMENT)
        assert "Authorization" not in server.requests[0].headers

    def test_a_rejected_upload_is_failed_with_the_status_and_the_body(self) -> None:
        server = FakeImportServer(status=403)
        report = server_import_destination("https://audit.example", transport=server)(NAME, SEGMENT)
        assert report.state is ArchiveState.FAILED
        assert "403" in report.detail and "denied" in report.detail

    def test_an_unreachable_server_is_failed_and_labelled_not_a_crash(self) -> None:
        server = FakeImportServer(raises=OSError("connection refused"))
        report = server_import_destination("https://audit.example", transport=server)(NAME, SEGMENT)
        assert report.state is ArchiveState.FAILED
        assert "connection refused" in report.detail

    def test_the_default_transport_is_the_stdlib_one_and_refuses_a_file_url(self) -> None:
        # Every network adapter in the package funnels through
        # urllib_transport, which opens only http/https. A file:// archive
        # destination out of a config file must not become a local write.
        report = server_import_destination("file:///tmp/imports")(NAME, SEGMENT)
        assert report.state is ArchiveState.FAILED
        assert "file" in report.detail


class TestTheMultipartBodyIsNeverSilentlyCorrupted:
    def test_a_segment_containing_the_boundary_is_failed_never_sent(self) -> None:
        # A payload an agent controls could contain any byte string. A
        # boundary appearing inside the part would split the body and the
        # server would store a truncated segment that still parses as JSONL —
        # a corrupt archive nobody is told about. Refused and labelled
        # instead (rule 6).
        server = FakeImportServer()
        hostile = b'{"payload_b64": "--' + _MULTIPART_BOUNDARY.encode("ascii") + b'"}\n'
        report = server_import_destination("https://audit.example", transport=server)(NAME, hostile)
        assert report.state is ArchiveState.FAILED
        assert "boundary" in report.detail
        assert server.requests == []

    def test_a_filename_that_could_forge_headers_is_failed_never_sent(self) -> None:
        # A trail path comes from an environment variable, so a quote in a
        # segment name is reachable input, not a hypothetical.
        server = FakeImportServer()
        report = server_import_destination("https://audit.example", transport=server)(
            'tr"ail.00000.jsonl', SEGMENT
        )
        assert report.state is ArchiveState.FAILED
        assert "filename" in report.detail
        assert server.requests == []


class TestTheStoredLineCarriesTheHandleForRestoring:
    def test_the_servers_import_id_is_reported_so_the_copy_can_be_fetched_back(self) -> None:
        server = FakeImportServer()
        report = server_import_destination("https://audit.example", transport=server)(NAME, SEGMENT)
        assert "import_id=imp-0001" in report.detail

    def test_a_201_whose_body_names_no_import_id_is_still_stored(self) -> None:
        # The upload DID arrive. Downgrading it to failed because this build
        # could not read the receipt would report a copy that exists as one
        # that does not.
        class Terse(FakeImportServer):
            def __call__(self, request: RemoteRequest) -> RemoteResponse:
                self.requests.append(request)
                return RemoteResponse(status=201, body=b"created")

        report = server_import_destination("https://audit.example", transport=Terse())(
            NAME, SEGMENT
        )
        assert report.state is ArchiveState.STORED
        assert "no import_id" in report.detail


class TestTheDefaultClock:
    def test_the_uninjected_clock_is_real_utc_and_dates_a_retention_correctly(self) -> None:
        # now_fn is injectable (CLAUDE.md rule 8) and every other test here
        # pins it. This one leaves it alone, so the retain-until comparison
        # runs against the wall clock exactly as it does in production.
        client = FakeLockS3Client(
            retention={
                "Retention": {
                    "Mode": "COMPLIANCE",
                    "RetainUntilDate": datetime.now(UTC) + timedelta(days=1),
                }
            }
        )
        report = s3_destination(bucket="audit", client=client)(NAME, SEGMENT)
        assert report.state is ArchiveState.STORED
        assert "object_version/worm_locked" in report.detail
