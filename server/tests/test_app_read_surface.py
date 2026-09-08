"""Verify/report/inspect over HTTP, and honest reporting of what this build has.

Every one of these is read-only. There is no route that edits or deletes an
entry, and the structural test at the bottom is what keeps it that way as the
surface grows: "verify reports, never repairs" has to hold for the UI too, and a
convention only holds until someone adds one more handler.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any, cast

import pytest
from conftest import NO_ABSENT_COMMAND, PAYLOAD_TYPE, planned_but_absent, withhold
from fastapi.testclient import TestClient
from waxseal_server.api.chains import CHAIN_READS
from waxseal_server.api.deps import Services
from waxseal_server.app import Settings, create_app
from waxseal_server.runtime.cli import READ_ONLY_COMMANDS

from waxseal.sources.rotation import open_segmented


@pytest.fixture
def client(tmp_path: Path) -> TestClient:
    return TestClient(create_app(Settings(data_dir=tmp_path / "data")))


@pytest.fixture
def stocked(client: TestClient, envelopes: list[dict[str, Any]]) -> TestClient:
    for env in envelopes:
        client.post("/v1/chains/default/entries", json=env)
    return client


def _trail(tmp_path: Path) -> Path:
    return tmp_path / "data" / "chains" / "default" / "trail.jsonl"


def _services(client: TestClient) -> Services:
    return cast(Services, client.app.state.services)  # type: ignore[attr-defined]


def _lacking(client: TestClient, monkeypatch: pytest.MonkeyPatch, command: str) -> None:
    """Make this server's waxseal build lack `command`, whatever it really ships.

    Naming a planned command as the stand-in for "absent" is what expired four
    tests the day Workstream B shipped `segments` (waxseal-fg4.16) and five more
    when Workstream E shipped `preflight` the next batch (waxseal-fg4.36). The
    property under test is not about any one command: it is that a capability
    this build cannot run is REPORTED, not omitted, and that its screen says so
    instead of borrowing argparse's exit 2 as a verdict. Controlling the
    condition rather than picking a name states that property in a form the
    release calendar cannot invalidate. Shared with the runner and import suites
    (`conftest.withhold`) so all three state it the same way.
    """
    withhold(monkeypatch, _services(client).cli, command)


def _absent_read_or_skip(client: TestClient, offered: Iterable[str]) -> str:
    """One read this server offers that the wheel behind it really lacks.

    Derived, never named: this is the shape the portal renders for an operator
    whose wheel is older than their server, and the two agents before this one
    both hardcoded the name of a command that shipped days later.
    """
    absent = sorted(planned_but_absent(_services(client).cli, offered))
    if not absent:
        pytest.skip(NO_ABSENT_COMMAND)
    return absent[0]


def _rotate(trail: Path, times: int = 2) -> None:
    """Seal `trail` into a real segment group with the library's own rotation.

    Hand-written segment files would let the fixture agree with the test and
    disagree with `open_segmented`, which is the one thing a rotation fixture
    exists to rule out.
    """
    for i in range(times):
        open_segmented(trail, max_segment_bytes=1, notice=lambda _m: None).append(
            payload={"rotated": i}, payload_type=PAYLOAD_TYPE
        )


class TestCapabilities:
    def test_it_reports_which_commands_this_build_has(self, client: TestClient) -> None:
        commands = client.get("/v1/capabilities").json()["commands"]
        assert commands["verify"] is True
        assert commands["report"] is True

    def test_a_planned_command_is_reported_absent_not_omitted(self, client: TestClient) -> None:
        # Omitting it would leave the UI unable to distinguish "this build lacks
        # that command" from "the server forgot to answer". Present-and-false is
        # the measured answer; a missing key is not. This is the surface the
        # portal's FeatureGate reads, so it is the one case kept in the REAL
        # shape rather than the withheld one.
        #
        # The name is DERIVED from the build, not written down. Written down it
        # was `segments` until Workstream B shipped it, then `preflight` until
        # Workstream E shipped it one batch later — twice red, for a fact about
        # the release calendar rather than about this server (waxseal-fg4.36).
        command = _absent_read_or_skip(client, READ_ONLY_COMMANDS)
        commands = client.get("/v1/capabilities").json()["commands"]
        assert command in commands, "an absent capability must be reported, not omitted"
        assert commands[command] is False

    def test_a_command_this_build_lacks_is_present_and_false_whatever_it_is(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _lacking(client, monkeypatch, "verify")
        commands = client.get("/v1/capabilities").json()["commands"]
        assert commands["verify"] is False
        assert commands["report"] is True

    def test_every_read_only_command_is_reported_one_way_or_the_other(
        self, client: TestClient
    ) -> None:
        # A key for every command, never a filtered list: "not mentioned at all"
        # is the third state this surface exists to make unrepresentable.
        commands = client.get("/v1/capabilities").json()["commands"]
        assert set(commands) == set(READ_ONLY_COMMANDS)
        assert all(isinstance(value, bool) for value in commands.values())

    @pytest.mark.parametrize("command", ["segments", "preflight"])
    def test_a_planned_command_that_has_shipped_is_reported_available(
        self, client: TestClient, command: str
    ) -> None:
        # The other half of the gate: `available()` is parsed from `--help`, so
        # the flag has to turn true on its own. A stale false would hand an
        # operator the "not yet" notice for a command their build can run —
        # which is a false negative about their own deployment, not a cosmetic
        # one. `segments` was covered when B shipped it (waxseal-fg4.16);
        # `preflight` is here because E shipped it in the very next batch and
        # nothing asserted its available side.
        assert client.get("/v1/capabilities").json()["commands"][command] is True


class TestVerifyEndpoint:
    def test_an_intact_chain_verifies(self, stocked: TestClient) -> None:
        body = stocked.get("/v1/chains/default/verify").json()
        assert body["status"] == "ok"
        assert body["exit_code"] == 0
        assert body["verdict"] == "ok"

    def test_the_response_carries_the_argv_that_produced_it(self, stocked: TestClient) -> None:
        assert "verify" in stocked.get("/v1/chains/default/verify").json()["argv"]

    def test_a_chain_that_does_not_exist_is_absent_not_broken(self, client: TestClient) -> None:
        body = client.get("/v1/chains/nothinghere/verify").json()
        assert body["status"] == "absent"
        assert body["verdict"] is None

    def test_a_tampered_chain_is_broken(self, stocked: TestClient, tmp_path: Path) -> None:
        trail = _trail(tmp_path)
        lines = trail.read_text().splitlines()
        record = json.loads(lines[2])
        record["header"]["ts"] = "2000-01-01T00:00:00+00:00"
        lines[2] = json.dumps(record, sort_keys=True, separators=(",", ":"))
        trail.write_text("\n".join(lines) + "\n")

        body = stocked.get("/v1/chains/default/verify").json()
        assert body["status"] == "broken"
        assert body["exit_code"] == 1

    def test_an_unknown_fingerprint_is_unverifiable_never_broken(
        self, stocked: TestClient, tmp_path: Path
    ) -> None:
        trail = _trail(tmp_path)
        lines = trail.read_text().splitlines()
        record = json.loads(lines[2])
        record["header"]["hash_version"] = "ff" * 32
        lines[2] = json.dumps(record, sort_keys=True, separators=(",", ":"))
        trail.write_text("\n".join(lines) + "\n")

        body = stocked.get("/v1/chains/default/verify").json()
        assert body["status"] == "unverifiable"
        assert body["exit_code"] == 2

    def test_an_invalid_chain_id_is_400(self, client: TestClient) -> None:
        assert client.get("/v1/chains/a%20b/verify").status_code == 400


class TestReportEndpoint:
    def test_the_parsed_report_comes_through(self, stocked: TestClient) -> None:
        body = stocked.get("/v1/chains/default/report").json()
        assert body["report"]["inventory"]["entries_total"] == 5

    def test_the_scope_statement_is_carried_verbatim(self, stocked: TestClient) -> None:
        body = stocked.get("/v1/chains/default/report").json()
        assert body["report"]["scope"]["id"] == "waxseal-scope-v1"

    def test_dropped_writes_stays_null_when_never_measured(self, stocked: TestClient) -> None:
        body = stocked.get("/v1/chains/default/report").json()
        assert body["report"]["completeness"]["dropped_writes"] is None

    def test_a_missing_chain_reports_absent_with_no_report_body(self, client: TestClient) -> None:
        body = client.get("/v1/chains/nothinghere/report").json()
        assert body["status"] == "absent"
        assert body["report"] is None


class TestInspectEndpoint:
    def test_inspect_returns_its_stdout(self, stocked: TestClient) -> None:
        assert stocked.get("/v1/chains/default/inspect").json()["stdout"]


class TestExportProofEndpoint:
    def test_a_bundle_is_returned_for_a_present_seq(self, stocked: TestClient) -> None:
        body = stocked.get("/v1/chains/default/export-proof/2").json()
        assert body["status"] == "ok"
        bundle = json.loads(body["stdout"])
        assert bundle["bundle_version"] == "waxseal-proof-bundle-v1"
        assert bundle["header"]["seq"] == 2

    def test_a_seq_past_the_head_is_reported_not_crashed(self, stocked: TestClient) -> None:
        assert stocked.get("/v1/chains/default/export-proof/99").json()["exit_code"] == 1

    def test_a_negative_seq_is_400_and_never_reaches_argv(self, stocked: TestClient) -> None:
        assert stocked.get("/v1/chains/default/export-proof/-1").status_code == 400


class TestPlannedCommandsDegradeHonestly:
    def test_a_planned_screen_says_unavailable_rather_than_faking_a_verdict(
        self, stocked: TestClient
    ) -> None:
        # A screen for a read this wheel does not have must say the capability
        # is missing — never draw a verdict from argparse's exit 2.
        #
        # The command is DERIVED from CHAIN_READS minus what the build ships,
        # because a parametrize list of real planned names went red twice: once
        # when B shipped `segments`, once when E shipped `preflight`. The
        # withheld-command case below states the same property with no
        # dependence on the build at all, and runs whether or not this one has a
        # live instance to point at.
        command = _absent_read_or_skip(stocked, CHAIN_READS)
        body = stocked.get(f"/v1/chains/default/{command}").json()
        assert body["status"] == "unavailable"
        assert body["verdict"] is None
        assert body["exit_code"] is None

    def test_a_screen_for_a_command_the_build_lacks_never_fakes_a_verdict(
        self, stocked: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _lacking(stocked, monkeypatch, "verify")
        body = stocked.get("/v1/chains/default/verify").json()
        assert body["status"] == "unavailable"
        assert body["verdict"] is None
        assert body["exit_code"] is None
        # Never executed, so there is nothing to mistake for output.
        assert body["stdout"] == ""


class TestSegmentsIsShippedNow:
    """`segments` landed in 0.1.5 Workstream B, and this read had never run.

    It is the one chain read whose subject is a DIRECTORY of sealed segments and
    the rotation bindings between them (SPEC.md section 20), not a single trail
    file. Handed the trail file it printed "no such segment directory" and exited
    3, so a fully rotated, fully intact chain reported `absent` — "nothing was
    read" — about a directory that does exist. B was forbidden from touching
    `server/` to keep batch footprints disjoint, so the argument was never fixed
    on this side (waxseal-fg4.16).
    """

    def test_the_read_is_handed_the_trail_directory(
        self, stocked: TestClient, tmp_path: Path
    ) -> None:
        body = stocked.get("/v1/chains/default/segments").json()
        assert body["argv"][-1] == str(_trail(tmp_path).parent)

    def test_a_rotated_chain_gets_a_real_verdict(self, stocked: TestClient, tmp_path: Path) -> None:
        _rotate(_trail(tmp_path))
        body = stocked.get("/v1/chains/default/segments").json()
        assert body["status"] == "ok"
        assert body["verdict"] == "ok"
        assert body["exit_code"] == 0
        assert "segment(s)" in body["stdout"]

    def test_a_chain_that_has_not_rotated_is_absent_not_intact(self, stocked: TestClient) -> None:
        # Exit 3: nothing was checked. Rendering it as "ok" would report every
        # segment of a trail that has none as found intact (CLAUDE.md rule 5).
        body = stocked.get("/v1/chains/default/segments").json()
        assert body["status"] == "absent"
        assert body["verdict"] is None
        assert "no sealed segments" in body["stderr"]


class TestPreflightIsShippedNow:
    """`preflight` landed in 0.1.5 Workstream E, and this read had never run.

    Its available side is what the five expired fixtures were standing in front
    of: while the command was planned, every assertion about this route was
    about the placeholder, so nothing checked what an operator now actually
    sees. Unlike `segments` it reads the trail FILE — its subject is that
    trail's sidecars — so it is deliberately not in `DIRECTORY_READS`.
    """

    def test_the_read_is_handed_the_trail_file(self, stocked: TestClient, tmp_path: Path) -> None:
        body = stocked.get("/v1/chains/default/preflight").json()
        assert body["argv"][-1] == str(_trail(tmp_path))

    def test_a_live_chain_gets_the_command_reading(self, stocked: TestClient) -> None:
        # exit 0 from `preflight` means A READING WAS PRINTED, not that anything
        # was verified: the command opens no network connection and checks no
        # hash. The assertions stay on what was observed — status, exit code and
        # the ladder text — and deliberately do not bless the `verdict` the
        # shared classifier derives from exit 0 for a command that computes
        # none; that question is filed separately, not settled here.
        body = stocked.get("/v1/chains/default/preflight").json()
        assert body["status"] == "ok"
        assert body["exit_code"] == 0
        assert "observed configuration" in body["stdout"]
        assert "NOT MEASURED" in body["stdout"]


class TestPublicReceiptRecords:
    def test_the_raw_receipt_records_are_public(self, stocked: TestClient) -> None:
        # A third party should not have to take the server's own verdict on the
        # server's own log. Handing over the records lets them recompute it.
        body = stocked.get("/public/v1/chains/default/receipts").json()
        assert [r["receipt_seq"] for r in body["receipts"]] == [0, 1, 2, 3, 4]

    def test_an_absent_log_is_404_not_an_empty_list(self, client: TestClient) -> None:
        assert client.get("/public/v1/chains/default/receipts").status_code == 404


class TestNoWriteSurfaceAnywhere:
    """Every mutating route, enumerated — and what each one is allowed to touch.

    The list is asserted exactly rather than filtered, so a sixth one cannot
    arrive unnoticed. Three of them append (a chain entry, a witness
    checkpoint, an imported file); three write the server's OWN records
    (operators and keys). None edits, deletes, reorders or repairs a chain
    entry, and no scope exists that would let one — see
    `test_operators_domain.py::TestScopes::test_no_role_can_edit_an_entry`.
    """

    #: route -> what it mutates. Membership is the assertion; the value is the
    #: justification, so adding a route means writing down what it may touch.
    EXPECTED_MUTATIONS = {
        ("/v1/chains/{chain_id}/entries", "post"): "appends one chain entry under CAS",
        ("/v1/witness/{witness_id}", "post"): "deposits a checkpoint with a witness",
        ("/v1/imports", "post"): "stores an uploaded trail, read-only",
        ("/v1/operators", "post"): "registers an operator (server records)",
        ("/v1/keys", "post"): "mints an API key (server records)",
        ("/v1/keys/{key_id}/revoke", "post"): "revokes an API key (server records)",
        ("/v1/operators/{username}", "patch"): "corrects an operator (server records)",
        # Added with the Settings screen. Both write the server's OWN
        # operational config and neither can reach a trail or a credential:
        # `domain/settings.py` refuses `api_key`, `witness_api_key`,
        # `database_url` and `data_dir` by name, so no value either route
        # accepts is a secret. `reset` is a POST rather than a DELETE because
        # this server has none — see the test below.
        ("/v1/settings/{key}", "put"): "sets one operational setting (server records)",
        ("/v1/settings/{key}/reset", "post"): "reverts one setting to its default",
    }

    def test_there_is_no_delete_anywhere(self, client: TestClient) -> None:
        # Not for an entry, and not for an operator either: an operator who
        # acted is part of the history, and removing the row would orphan every
        # key that names them. Deactivation is the reversible alternative.
        for _, method in self.EXPECTED_MUTATIONS:
            assert method != "delete"

    def test_the_mutating_routes_are_exactly_the_documented_ones(self, client: TestClient) -> None:
        paths = client.app.openapi()["paths"]  # type: ignore[attr-defined]
        mutating = {
            (path, method)
            for path, operations in paths.items()
            for method in operations
            if method in {"post", "put", "patch", "delete"}
        }
        assert mutating == set(self.EXPECTED_MUTATIONS)

    def test_no_mutating_route_addresses_an_existing_entry(self, client: TestClient) -> None:
        # An entry is addressed by its seq. No route that writes may name one:
        # that is what "verify reports, never repairs" looks like in a URL table.
        for path, _ in self.EXPECTED_MUTATIONS:
            assert "{seq}" not in path, path


class TestThePublicReadPointIsGetOnly:
    """The public read point carries no write route — asserted per route.

    `api/public.py` promises exactly this test in its docstring. The property
    was already implied by `TestNoWriteSurfaceAnywhere`'s census of mutating
    routes (all seven live under `/v1/`), but implication is not detection: that
    census goes red for a POST added ANYWHERE, and would name the wrong
    property while doing it. Read authority separated from write authority is
    the mirror-node guarantee (REMOTE.md section 10: the write credential
    "grants nothing here"), and a guarantee deserves a test that fails for its
    own reason.
    """

    #: The only method the public read point may expose. An allowlist, never
    #: `!= "post"`: a blocklist naming POST is silent about PUT, PATCH, DELETE
    #: and anything a later route adds. FastAPI's schema lists only the methods
    #: a handler declares — HEAD and OPTIONS are answered by Starlette outside
    #: the schema — so no implicit method needs permitting here.
    ALLOWED_METHODS = {"get"}

    @staticmethod
    def _by_tag(paths: dict[str, Any]) -> set[tuple[str, str]]:
        return {
            (path, method)
            for path, operations in paths.items()
            for method, operation in operations.items()
            if "public" in (operation.get("tags") or [])
        }

    @staticmethod
    def _by_prefix(paths: dict[str, Any]) -> set[tuple[str, str]]:
        return {
            (path, method)
            for path, operations in paths.items()
            for method in operations
            if path.startswith("/public/v1")
        }

    def test_every_route_on_the_public_read_point_is_get(self, client: TestClient) -> None:
        paths = client.app.openapi()["paths"]  # type: ignore[attr-defined]
        public = self._by_tag(paths) | self._by_prefix(paths)
        # A selector that silently matched nothing would pass forever. The
        # count is not asserted — the surface may grow — but its emptiness is.
        assert public, "no public routes found: the selector is broken, not the surface"
        offending = {
            (path, method) for path, method in public if method not in self.ALLOWED_METHODS
        }
        assert offending == set(), f"non-GET routes on the public read point: {offending}"

    def test_the_two_selectors_see_the_same_surface(self, client: TestClient) -> None:
        # Each covers the other's blind spot: a public route moved off the
        # prefix, and a route under the prefix that forgot the tag. If they ever
        # disagree, one of them has stopped seeing part of the surface and the
        # test above is weaker than it reads.
        paths = client.app.openapi()["paths"]  # type: ignore[attr-defined]
        assert self._by_tag(paths) == self._by_prefix(paths)


class TestReadSurfaceRespectsTheCredential:
    @pytest.fixture
    def keyed(self, tmp_path: Path) -> TestClient:
        return TestClient(
            create_app(Settings(data_dir=tmp_path / "data", api_key="chain-write-key"))
        )

    @pytest.mark.parametrize(
        "path",
        [
            "/v1/chains/default/verify",
            "/v1/chains/default/report",
            "/v1/chains/default/inspect",
            "/v1/chains/default/export-proof/0",
            "/v1/chains/default/segments",
            "/v1/chains/default/preflight",
        ],
    )
    def test_every_read_route_refuses_an_unauthenticated_caller(
        self, keyed: TestClient, path: str
    ) -> None:
        assert keyed.get(path).status_code == 401


class TestBadIdsOnTheReadSurface:
    @pytest.mark.parametrize(
        "path",
        [
            "/v1/chains/a%20b/report",
            "/v1/chains/a%20b/inspect",
            "/v1/chains/a%20b/export-proof/0",
            "/public/v1/chains/a%20b/receipts",
        ],
    )
    def test_a_bad_chain_id_is_400_before_anything_runs(
        self, client: TestClient, path: str
    ) -> None:
        assert client.get(path).status_code == 400


class TestPublicReceiptCrossCheck:
    """Published because the comparison needs no trust in the server to repeat.

    The server holds the acknowledgments and the trail; anyone holding both
    (they are both public) reaches the same verdict. That is what makes it
    evidence rather than an assurance.
    """

    def test_an_untouched_chain_agrees_with_its_receipts(self, stocked: TestClient) -> None:
        body = stocked.get("/public/v1/chains/default/receipts/cross-check").json()
        assert body == {
            "verdict": "ok",
            "checked": 5,
            "reason": None,
            "broken_seq": None,
            "exit_code": 0,
        }

    def test_a_self_consistent_rewrite_is_caught_here_and_not_by_verify(
        self, stocked: TestClient, tmp_path: Path
    ) -> None:
        from waxseal.domain.hashing import compute_entry_hash
        from waxseal.domain.header import header_from_obj

        trail = _trail(tmp_path)
        lines = trail.read_text().splitlines()
        record = json.loads(lines[0])
        record["header"]["ts"] = "2000-01-01T00:00:00+00:00"
        record["entry_hash"] = compute_entry_hash(header_from_obj(record["header"]))
        lines[0] = json.dumps(record, sort_keys=True, separators=(",", ":"))
        trail.write_text("\n".join(lines) + "\n")

        body = stocked.get("/public/v1/chains/default/receipts/cross-check").json()
        assert body["verdict"] == "broken"
        assert body["reason"] == "receipt_mismatch"
        assert body["broken_seq"] == 0

    def test_no_receipts_reports_not_recorded_never_zero(self, client: TestClient) -> None:
        body = client.get("/public/v1/chains/default/receipts/cross-check").json()
        assert body["checked"] is None
        assert body["reason"] == "not_recorded"

    def test_an_invalid_chain_id_is_400(self, client: TestClient) -> None:
        assert client.get("/public/v1/chains/a%20b/receipts/cross-check").status_code == 400


class TestADamagedReceiptLogIsReportedNotCrashed:
    def test_reading_the_records_is_422_with_a_label(
        self, stocked: TestClient, tmp_path: Path
    ) -> None:
        # "I could not read the log" must not arrive as a 500, and must not
        # arrive as the 404 that means "there is no log".
        (tmp_path / "data" / "chains" / "default" / "receipts.jsonl").write_text("{not json\n")
        resp = stocked.get("/public/v1/chains/default/receipts")
        assert resp.status_code == 422
        assert resp.json()["error"] == "damaged_receipt_log"

    def test_the_cross_check_reports_it_as_a_break(
        self, stocked: TestClient, tmp_path: Path
    ) -> None:
        (tmp_path / "data" / "chains" / "default" / "receipts.jsonl").write_text("{not json\n")
        body = stocked.get("/public/v1/chains/default/receipts/cross-check").json()
        assert body["verdict"] == "broken"
        assert body["reason"] == "malformed_receipt_record"


class TestSummaryEndpoint:
    """One request per dashboard row.

    It reports counts and identities and no verdict at all — counting lines is
    not verifying them, and a row that implied otherwise would be claiming a
    check nobody ran. The verdict is a separate call, to the CLI.
    """

    def test_it_reports_counts_head_and_receipt(self, stocked: TestClient) -> None:
        body = stocked.get("/v1/chains/default/summary").json()
        assert body["chain_id"] == "default"
        assert body["entries"] == 5
        assert body["size_bytes"] > 0
        assert body["head"]["seq"] == 4
        assert body["receipt"]["receipt_seq"] == 4

    def test_an_empty_chain_has_a_null_head_not_a_zero_one(self, client: TestClient) -> None:
        # seq 0 is a real entry. `head: null` is the only honest way to say
        # there is not one.
        body = client.get("/v1/chains/nothinghere/summary").json()
        assert body["head"] is None
        assert body["receipt"] is None
        assert body["entries"] == 0

    def test_it_carries_no_verdict(self, stocked: TestClient) -> None:
        assert "verdict" not in stocked.get("/v1/chains/default/summary").json()

    def test_an_invalid_chain_id_is_400(self, client: TestClient) -> None:
        assert client.get("/v1/chains/a%20b/summary").status_code == 400

    def test_it_needs_the_credential_when_one_is_configured(self, tmp_path: Path) -> None:
        keyed = TestClient(create_app(Settings(data_dir=tmp_path / "d", api_key="k")))
        assert keyed.get("/v1/chains/default/summary").status_code == 401


class TestOnlyTheOfferedReadsAreRoutable:
    """One route serves every CLI-backed chain read, driven by `CHAIN_READS`.

    That is what makes adding Workstream B's `segments` screen a tuple entry
    rather than a new handler — and it is also why the allowlist has to be
    checked here: without it, the same route would happily pass `anchor` or
    `install` down to the runner.
    """

    @pytest.mark.parametrize("command", ["anchor", "install", "cadence", "nonsense"])
    def test_a_command_outside_the_offered_reads_is_404(
        self, stocked: TestClient, command: str
    ) -> None:
        resp = stocked.get(f"/v1/chains/default/{command}")
        assert resp.status_code == 404
        assert resp.json()["error"] == "no_such_read"

    @pytest.mark.parametrize("command", ["verify", "report", "inspect", "segments", "preflight"])
    def test_every_offered_read_is_reachable(self, stocked: TestClient, command: str) -> None:
        assert stocked.get(f"/v1/chains/default/{command}").status_code == 200
