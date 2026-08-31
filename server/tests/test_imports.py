"""Imported trails: evidence brought in from elsewhere, kept read-only.

An imported trail is somebody else's history. The server verifies it and shows
the verdict; it never appends to it and never repairs it. That is not a policy
choice bolted on at the UI — the stored copy is made read-only on disk and there
is no route that could write to it.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

import pytest
from conftest import PAYLOAD_TYPE
from fastapi.testclient import TestClient
from waxseal_server.app import Settings, create_app
from waxseal_server.domain.errors import UnsupportedTrailFormat
from waxseal_server.storage.imports import ImportStore

from waxseal import AuditLog


@pytest.fixture
def client(tmp_path: Path) -> TestClient:
    return TestClient(create_app(Settings(data_dir=tmp_path / "data")))


@pytest.fixture
def store(tmp_path: Path) -> ImportStore:
    return ImportStore(tmp_path / "imports")


def foreign_trail(tmp_path: Path, *, name: str = "foreign.jsonl", count: int = 4) -> bytes:
    path = tmp_path / name
    log = AuditLog.open(path)
    for i in range(count):
        log.append(payload={"origin": "another system", "i": i}, payload_type=PAYLOAD_TYPE)
    return path.read_bytes()


class TestImportStore:
    def test_an_imported_trail_gets_an_id_and_its_digest(
        self, store: ImportStore, tmp_path: Path
    ) -> None:
        data = foreign_trail(tmp_path)
        record = store.create("foreign.jsonl", data)
        assert record.filename == "foreign.jsonl"
        assert record.sha256 == hashlib.sha256(data).hexdigest()
        assert record.size == len(data)

    def test_the_stored_copy_is_byte_identical(
        self, store: ImportStore, tmp_path: Path
    ) -> None:
        data = foreign_trail(tmp_path)
        record = store.create("foreign.jsonl", data)
        assert store.trail_path(record.import_id).read_bytes() == data

    def test_the_stored_copy_is_not_writable(
        self, store: ImportStore, tmp_path: Path
    ) -> None:
        # An imported trail is evidence, not a live trail. Read-only on disk is
        # the statement that survives someone adding a handler later.
        record = store.create("foreign.jsonl", foreign_trail(tmp_path))
        mode = store.trail_path(record.import_id).stat().st_mode
        assert not mode & 0o222

    def test_two_imports_of_the_same_bytes_are_two_records(
        self, store: ImportStore, tmp_path: Path
    ) -> None:
        # De-duplicating would silently merge two separate acts of evidence
        # submission, and lose whichever filename and timestamp came second.
        data = foreign_trail(tmp_path)
        first = store.create("a.jsonl", data)
        second = store.create("b.jsonl", data)
        assert first.import_id != second.import_id

    def test_records_are_listed_newest_first(
        self, store: ImportStore, tmp_path: Path
    ) -> None:
        first = store.create("a.jsonl", foreign_trail(tmp_path, name="a.jsonl"))
        second = store.create("b.jsonl", foreign_trail(tmp_path, name="b.jsonl"))
        assert [r.import_id for r in store.records()][:2] == [
            second.import_id,
            first.import_id,
        ]

    def test_an_empty_store_lists_nothing(self, store: ImportStore) -> None:
        assert store.records() == []

    def test_an_unknown_id_is_none(self, store: ImportStore) -> None:
        assert store.get("does-not-exist") is None

    @pytest.mark.parametrize("suffix", [".jsonl", ".db", ".sqlite", ".sqlite3"])
    def test_the_formats_waxseal_can_open_are_accepted(
        self, store: ImportStore, tmp_path: Path, suffix: str
    ) -> None:
        assert store.create(f"trail{suffix}", b"x").filename == f"trail{suffix}"

    @pytest.mark.parametrize("name", ["trail.txt", "trail", "trail.json", "trail.jsonl.gz"])
    def test_a_format_waxseal_cannot_open_is_refused(
        self, store: ImportStore, name: str
    ) -> None:
        # Accepting it would produce an import whose every verdict is "no
        # backend for this suffix" — a stored file that can never be evidence.
        with pytest.raises(UnsupportedTrailFormat):
            store.create(name, b"x")

    def test_a_filename_carrying_a_path_is_stripped_to_its_basename(
        self, store: ImportStore, tmp_path: Path
    ) -> None:
        record = store.create("../../etc/evil.jsonl", foreign_trail(tmp_path))
        assert store.trail_path(record.import_id).parent.parent == store.root
        assert store.trail_path(record.import_id).name == "evil.jsonl"

    def test_an_id_that_is_not_a_safe_segment_never_builds_a_path(
        self, store: ImportStore
    ) -> None:
        with pytest.raises(ValueError):
            store.trail_path("../escape")


class TestImportEndpoints:
    def _upload(self, client: TestClient, tmp_path: Path, name: str = "foreign.jsonl") -> Any:
        return client.post(
            "/v1/imports",
            files={"file": (name, foreign_trail(tmp_path, name=name), "application/octet-stream")},
        )

    def test_uploading_a_trail_is_201_with_its_record(
        self, client: TestClient, tmp_path: Path
    ) -> None:
        resp = self._upload(client, tmp_path)
        assert resp.status_code == 201
        assert resp.json()["filename"] == "foreign.jsonl"

    def test_an_unsupported_format_is_400(self, client: TestClient) -> None:
        resp = client.post(
            "/v1/imports", files={"file": ("notes.txt", b"hello", "text/plain")}
        )
        assert resp.status_code == 400

    def test_an_empty_upload_is_400(self, client: TestClient) -> None:
        resp = client.post("/v1/imports", files={"file": ("t.jsonl", b"", "text/plain")})
        assert resp.status_code == 400

    def test_the_import_is_listed(self, client: TestClient, tmp_path: Path) -> None:
        self._upload(client, tmp_path)
        assert len(client.get("/v1/imports").json()["imports"]) == 1

    def test_an_imported_trail_verifies(self, client: TestClient, tmp_path: Path) -> None:
        import_id = self._upload(client, tmp_path).json()["import_id"]
        body = client.get(f"/v1/imports/{import_id}/verify").json()
        assert body["status"] == "ok"
        assert body["verdict"] == "ok"

    def test_a_tampered_import_verifies_as_broken(
        self, client: TestClient, tmp_path: Path
    ) -> None:
        raw = foreign_trail(tmp_path).decode().splitlines()
        record = json.loads(raw[2])
        record["header"]["ts"] = "2000-01-01T00:00:00+00:00"
        raw[2] = json.dumps(record, sort_keys=True, separators=(",", ":"))
        resp = client.post(
            "/v1/imports",
            files={"file": ("t.jsonl", ("\n".join(raw) + "\n").encode(), "text/plain")},
        )
        body = client.get(f"/v1/imports/{resp.json()['import_id']}/verify").json()
        assert body["status"] == "broken"

    def test_an_import_with_an_unknown_fingerprint_is_unverifiable(
        self, client: TestClient, tmp_path: Path
    ) -> None:
        raw = foreign_trail(tmp_path).decode().splitlines()
        record = json.loads(raw[1])
        record["header"]["hash_version"] = "ff" * 32
        raw[1] = json.dumps(record, sort_keys=True, separators=(",", ":"))
        resp = client.post(
            "/v1/imports",
            files={"file": ("t.jsonl", ("\n".join(raw) + "\n").encode(), "text/plain")},
        )
        body = client.get(f"/v1/imports/{resp.json()['import_id']}/verify").json()
        assert body["status"] == "unverifiable"

    def test_an_imported_trail_reports(self, client: TestClient, tmp_path: Path) -> None:
        import_id = self._upload(client, tmp_path).json()["import_id"]
        body = client.get(f"/v1/imports/{import_id}/report").json()
        assert body["report"]["inventory"]["entries_total"] == 4

    def test_the_imported_entries_can_be_read_for_display(
        self, client: TestClient, tmp_path: Path
    ) -> None:
        import_id = self._upload(client, tmp_path).json()["import_id"]
        body = client.get(f"/v1/imports/{import_id}/entries").json()
        assert [e["header"]["seq"] for e in body["entries"]] == [0, 1, 2, 3]

    def test_segments_on_an_import_degrades_honestly(
        self, client: TestClient, tmp_path: Path
    ) -> None:
        import_id = self._upload(client, tmp_path).json()["import_id"]
        assert client.get(f"/v1/imports/{import_id}/segments").json()["status"] == "unavailable"

    def test_a_well_formed_but_unknown_import_is_404(self, client: TestClient) -> None:
        assert client.get(f"/v1/imports/{'ab' * 16}/verify").status_code == 404

    @pytest.mark.parametrize("bad", ["nope", "a%20b", "AB" * 16])
    def test_an_import_id_that_is_not_well_formed_is_400(
        self, client: TestClient, bad: str
    ) -> None:
        # Malformed and unknown are different answers: one is the caller's
        # mistake, the other is a fact about this server's store.
        assert client.get(f"/v1/imports/{bad}/verify").status_code == 400

    def test_a_traversal_attempt_never_resolves_to_a_file(self, client: TestClient) -> None:
        assert client.get("/v1/imports/..%2F..%2Fetc/verify").status_code in (400, 404)

    def test_a_read_this_server_does_not_offer_is_404_not_executed(
        self, client: TestClient, tmp_path: Path
    ) -> None:
        import_id = self._upload(client, tmp_path).json()["import_id"]
        assert client.get(f"/v1/imports/{import_id}/anchor").status_code == 404

    def test_an_import_is_never_a_chain_that_can_be_appended_to(
        self, client: TestClient, tmp_path: Path
    ) -> None:
        # The imported trail must not become reachable through the chain write
        # path by sharing its id namespace.
        import_id = self._upload(client, tmp_path).json()["import_id"]
        assert client.get("/public/v1/chains").json()["chains"] == []
        assert client.get(f"/v1/chains/{import_id}/head").status_code == 404

    def test_the_only_import_route_that_writes_is_the_upload(
        self, client: TestClient
    ) -> None:
        paths = client.app.openapi()["paths"]  # type: ignore[attr-defined]
        mutating = {
            (path, method)
            for path, operations in paths.items()
            for method in operations
            if method in {"post", "put", "patch", "delete"} and "/imports" in path
        }
        assert mutating == {("/v1/imports", "post")}


class TestImportsRespectTheCredential:
    @pytest.fixture
    def keyed(self, tmp_path: Path) -> TestClient:
        return TestClient(
            create_app(Settings(data_dir=tmp_path / "data", api_key="chain-write-key"))
        )

    def test_uploading_needs_the_credential(self, keyed: TestClient, tmp_path: Path) -> None:
        resp = keyed.post(
            "/v1/imports",
            files={"file": ("t.jsonl", foreign_trail(tmp_path), "text/plain")},
        )
        assert resp.status_code == 401

    @pytest.mark.parametrize(
        "path",
        [
            "/v1/imports",
            "/v1/imports/x",
            "/v1/imports/x/verify",
            "/v1/imports/x/report",
            "/v1/imports/x/entries",
        ],
    )
    def test_reading_imports_needs_the_credential(self, keyed: TestClient, path: str) -> None:
        assert keyed.get(path).status_code == 401


class TestUmaskDoesNotWidenTheStoredCopy:
    def test_the_read_only_bit_holds_under_a_permissive_umask(
        self, store: ImportStore, tmp_path: Path
    ) -> None:
        previous = os.umask(0)
        try:
            record = store.create("foreign.jsonl", foreign_trail(tmp_path))
        finally:
            os.umask(previous)
        assert not store.trail_path(record.import_id).stat().st_mode & 0o222


class TestImportRecordEndpoint:
    def test_the_record_is_readable_by_id(self, client: TestClient, tmp_path: Path) -> None:
        created = client.post(
            "/v1/imports",
            files={"file": ("foreign.jsonl", foreign_trail(tmp_path), "text/plain")},
        ).json()
        fetched = client.get(f"/v1/imports/{created['import_id']}").json()
        assert fetched == created

    def test_an_unknown_record_is_404(self, client: TestClient) -> None:
        assert client.get(f"/v1/imports/{'ab' * 16}").status_code == 404

    def test_a_malformed_id_on_the_record_route_is_400(self, client: TestClient) -> None:
        assert client.get("/v1/imports/nope").status_code == 400

    def test_a_malformed_id_on_the_entries_route_is_400(self, client: TestClient) -> None:
        assert client.get("/v1/imports/nope/entries").status_code == 400


class TestAnUnreadableImportIsReportedNotCrashed:
    """A file with the right suffix and the wrong bytes.

    Nothing stops an operator uploading a `.db` that is not a database. The
    screen must say "could not read this" — never render an empty entry list,
    which would claim a trail was read and found to hold nothing.
    """

    def _upload_junk(self, client: TestClient) -> str:
        resp = client.post(
            "/v1/imports",
            files={"file": ("broken.db", b"this is not a sqlite database", "text/plain")},
        )
        return str(resp.json()["import_id"])

    def test_reading_its_entries_is_422_not_an_empty_list(self, client: TestClient) -> None:
        resp = client.get(f"/v1/imports/{self._upload_junk(client)}/entries")
        assert resp.status_code == 422
        assert resp.json()["error"] == "unreadable_trail"

    def test_its_report_has_no_report_body_rather_than_an_empty_one(
        self, client: TestClient
    ) -> None:
        body = client.get(f"/v1/imports/{self._upload_junk(client)}/report").json()
        assert body["report"] is None
