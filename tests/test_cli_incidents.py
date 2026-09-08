"""CLI: `waxseal incidents` — read the incident rows and their reporting window.

Read-only against the trail, appending nothing, like every other read verb.

**Its exit-code range excludes 1 by construction, and that is the design.**
`reconcile-tickets` earns its exit 1 from two things this command does not
have: an exogenous authority positively asserting that something should be
present (the issuer says "I issued 41"), and a comparison that is
deterministic given the trail. Here the reporting window is a parameter the
operator typed, the deadline is anchored to a moment the writer asserted, and
the reading depends on a clock this process supplied. An exit 1 would be
waxseal asserting that a legal obligation was not met — one of the three
things `SCOPE_STATEMENT` says no output of this library asserts. `preflight`
is the precedent: it is exit 0 always because it reports a reading, not a
verdict an operator then has to reconcile against `verify`.

So: 0 = every incident row was read and listed, flagged rows included, because
a flag is a printed reading; 2 = a row claiming the incident payload type could
not be read, so the listing is incomplete and must not be mistaken for
complete-and-clean; 3 = the trail does not exist.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from waxseal import AuditLog
from waxseal.cli import main
from waxseal.domain.incident import INCIDENT_PAYLOAD_TYPE, IncidentRecord
from waxseal.sources.incidents import record_incident

CONFIRMED = "2026-09-01T08:00:00+00:00"
AS_OF_INSIDE = "2026-09-02T08:00:00+00:00"  # +24h
AS_OF_OUTSIDE = "2026-09-05T08:00:00+00:00"  # +96h


def incident(**overrides: object) -> IncidentRecord:
    base: dict[str, object] = {
        "incident_id": "inc-1",
        "system_id": "agent-7",
        "detected_at": "2026-09-01T07:00:00+00:00",
        "severity": "nghiêm trọng",
        "confirmed_at": CONFIRMED,
    }
    base.update(overrides)
    return IncidentRecord(**base)  # type: ignore[arg-type]


def trail(tmp_path: Path, *records: IncidentRecord) -> Path:
    path = tmp_path / "trail.jsonl"
    log = AuditLog.open(path)
    for record in records:
        record_incident(log, record)
    return path


class TestWindowReadings:
    def test_a_submission_inside_the_window_is_read_as_such(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = trail(
            tmp_path,
            incident(report_ref="AI-2026-000123", reported_at=AS_OF_INSIDE),
        )
        code = main(["incidents", str(path), "--as-of", AS_OF_OUTSIDE])
        out = capsys.readouterr().out
        assert code == 0
        assert "report_recorded_within_window" in out
        assert "caller-asserted" in out

    def test_no_submission_past_the_window_is_a_reading_not_a_finding(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = trail(tmp_path, incident())
        code = main(["incidents", str(path), "--as-of", AS_OF_OUTSIDE])
        out = capsys.readouterr().out
        # Exit 0, deliberately: see this module's docstring.
        assert code == 0
        assert "no_report_recorded_past_window" in out
        assert "caller-asserted" in out

    def test_inside_the_window_with_no_submission_is_still_open(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = trail(tmp_path, incident())
        code = main(["incidents", str(path), "--as-of", AS_OF_INSIDE])
        assert code == 0
        assert "window_open" in capsys.readouterr().out

    def test_a_wider_window_moves_the_same_trail_back_inside_it(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = trail(tmp_path, incident())
        code = main(["incidents", str(path), "--as-of", AS_OF_OUTSIDE, "--report-window-h", "120"])
        assert code == 0
        assert "window_open" in capsys.readouterr().out

    def test_a_missing_confirmation_moment_is_unmeasured_never_the_detection_one(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # Điều 19(3)(c) anchors the deadline to the confirmation moment. With
        # none recorded, substituting detected_at would manufacture a finding
        # out of the wrong timestamp.
        path = trail(tmp_path, incident(confirmed_at=None))
        code = main(["incidents", str(path), "--as-of", AS_OF_OUTSIDE])
        out = capsys.readouterr().out
        assert code == 0
        assert "unmeasured" in out
        assert "confirmed_at" in out
        assert "no_report_recorded_past_window" not in out


class TestFoldingAndListing:
    def test_a_restating_row_folds_and_the_newest_row_wins(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = trail(
            tmp_path,
            incident(),
            incident(report_ref="AI-2026-000123", reported_at=AS_OF_INSIDE),
        )
        code = main(["incidents", str(path), "--as-of", AS_OF_OUTSIDE])
        out = capsys.readouterr().out
        assert code == 0
        assert "rows=2" in out
        assert "report_recorded_within_window" in out

    def test_an_empty_trail_says_a_count_of_records_is_not_a_count_of_events(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = tmp_path / "trail.jsonl"
        AuditLog.open(path).append(payload={"x": 1}, payload_type="application/vnd.t.e+json")
        code = main(["incidents", str(path)])
        out = capsys.readouterr().out
        assert code == 0
        assert "not evidence" in out.lower()

    def test_an_unreadable_incident_row_makes_the_listing_incomplete(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = trail(tmp_path, incident())
        AuditLog.open(path).append(payload=b"not json", payload_type=INCIDENT_PAYLOAD_TYPE)
        code = main(["incidents", str(path)])
        out = capsys.readouterr().out
        assert code == 2
        assert "incomplete" in out.lower()

    def test_the_scope_line_is_printed(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = trail(tmp_path, incident())
        main(["incidents", str(path)])
        assert "scope:" in capsys.readouterr().out.lower()


class TestJsonMode:
    def test_json_carries_every_reading_and_names_its_time_basis(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = trail(tmp_path, incident(consequence_kinds=("tài sản",)))
        code = main(["incidents", str(path), "--json", "--as-of", AS_OF_OUTSIDE])
        obj = json.loads(capsys.readouterr().out)
        assert code == 0
        assert obj["time_basis"] == "caller_asserted"
        assert obj["window_h"] == 72
        assert obj["as_of"] == AS_OF_OUTSIDE
        (row,) = obj["incidents"]
        assert row["incident_id"] == "inc-1"
        assert row["severity"] == "nghiêm trọng"
        assert row["consequence_kinds"] == ["tài sản"]
        assert row["status"] == "no_report_recorded_past_window"
        assert row["report_ref"] is None
        assert row["rows"] == 1
        assert obj["totals"]["recorded"] == 1
        assert obj["totals"]["no_report_recorded"] == 1
        assert obj["unreadable"] == []

    def test_json_states_the_count_caveat_rather_than_leaving_zero_bare(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = tmp_path / "trail.jsonl"
        AuditLog.open(path).append(payload={"x": 1}, payload_type="application/vnd.t.e+json")
        main(["incidents", str(path), "--json"])
        obj = json.loads(capsys.readouterr().out)
        assert obj["totals"]["recorded"] == 0
        assert "not evidence" in obj["note"].lower()


class TestReadOnlyAndErrors:
    def test_it_never_writes_to_the_trail(self, tmp_path: Path) -> None:
        path = trail(tmp_path, incident())
        before = path.read_bytes()
        main(["incidents", str(path), "--json"])
        assert path.read_bytes() == before

    def test_a_missing_trail_exits_3(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert main(["incidents", str(tmp_path / "nope.jsonl")]) == 3
        assert "no such trail" in capsys.readouterr().err

    def test_a_malformed_as_of_is_unmeasured_input_not_a_reading(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = trail(tmp_path, incident())
        code = main(["incidents", str(path), "--as-of", "yesterday"])
        out = capsys.readouterr().out
        assert code == 2
        assert "unverifiable" in out.lower()

    def test_a_naive_as_of_is_refused_rather_than_given_a_time_zone(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = trail(tmp_path, incident())
        code = main(["incidents", str(path), "--as-of", "2026-09-05T08:00:00"])
        assert code == 2
        assert "offset" in capsys.readouterr().out.lower()

    def test_a_non_positive_window_is_refused(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = trail(tmp_path, incident())
        code = main(["incidents", str(path), "--report-window-h", "0"])
        assert code == 2
        assert "unverifiable" in capsys.readouterr().out.lower()


class TestSinceFilter:
    def test_it_lists_only_incidents_confirmed_at_or_after_the_moment(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = trail(
            tmp_path,
            incident(incident_id="old", confirmed_at="2026-08-01T00:00:00+00:00"),
            incident(incident_id="new", confirmed_at=CONFIRMED),
        )
        code = main(
            [
                "incidents",
                str(path),
                "--since",
                "2026-08-15T00:00:00+00:00",
                "--as-of",
                AS_OF_OUTSIDE,
            ]
        )
        out = capsys.readouterr().out
        assert code == 0
        assert "new:" in out
        assert "old:" not in out

    def test_a_row_with_no_confirmation_moment_is_kept_and_labelled(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # A filter that drops what it cannot evaluate returns a shorter list
        # and calls it complete. The row stays, and the line says the filter
        # could not be applied to it.
        path = trail(tmp_path, incident(incident_id="noconf", confirmed_at=None))
        code = main(
            [
                "incidents",
                str(path),
                "--since",
                "2026-08-15T00:00:00+00:00",
                "--as-of",
                AS_OF_OUTSIDE,
            ]
        )
        out = capsys.readouterr().out
        assert code == 0
        assert "noconf" in out
        assert "--since could not be applied" in out

    def test_a_row_whose_confirmation_moment_is_unreadable_is_kept_and_labelled(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = trail(tmp_path, incident(incident_id="bad", confirmed_at="whenever"))
        code = main(
            [
                "incidents",
                str(path),
                "--since",
                "2026-08-15T00:00:00+00:00",
                "--as-of",
                AS_OF_OUTSIDE,
            ]
        )
        out = capsys.readouterr().out
        assert code == 0
        assert "bad" in out
        assert "--since could not be applied" in out

    def test_json_reports_the_rows_the_filter_could_not_evaluate(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = trail(
            tmp_path,
            incident(incident_id="keep", confirmed_at=CONFIRMED),
            incident(incident_id="noconf", confirmed_at=None),
        )
        code = main(
            [
                "incidents",
                str(path),
                "--json",
                "--since",
                "2026-08-15T00:00:00+00:00",
                "--as-of",
                AS_OF_OUTSIDE,
            ]
        )
        obj = json.loads(capsys.readouterr().out)
        assert code == 0
        assert obj["since"] == "2026-08-15T00:00:00+00:00"
        assert obj["since_not_applicable"] == ["noconf"]
        assert {row["incident_id"] for row in obj["incidents"]} == {"keep", "noconf"}

    def test_a_malformed_since_is_refused_before_anything_is_read(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = trail(tmp_path, incident())
        code = main(["incidents", str(path), "--since", "last week"])
        assert code == 2
        assert "nothing was read" in capsys.readouterr().out
