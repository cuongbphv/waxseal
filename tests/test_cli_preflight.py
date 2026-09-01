"""`waxseal preflight <trail>`: which rung of the attacker-capability ladder
this configuration stops (waxseal-ip8, Workstream E).

Condition R throughout: the bead's criterion is "it prints", so every
assertion below runs `main()` and reads real stdout, following `cadence`'s
precedent — a reading an operator cannot see is not a reading.

Exit codes: 0 ALWAYS, because this is an information command and not a
verdict, plus 3 for "nothing was read" (no such local trail). There is
deliberately no exit 1 and no exit 2 here: preflight computes no verdict, so
it has nothing to report one with. A configuration that stops nobody still
exits 0 — the finding is the printed rung, not the process status.

The one thing this file exists to hold shut: preflight must never render an
unmeasured fact as a zero or an absence. It contacts no witness and holds no
seal key, and an `.anchors` sidecar it cannot parse is not an empty one.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from waxseal import AuditLog
from waxseal.adapters.attest import FileAttestor
from waxseal.cli import main
from waxseal.domain.sealing import generate_key

PT = "application/vnd.test.event+json"


def make_trail(path: Path, n: int = 3, *, sealed: bool = False) -> AuditLog:
    attestor = FileAttestor(path, initial_key=generate_key()) if sealed else None
    log = AuditLog.open(path, attestor=attestor)
    for i in range(n):
        log.append(payload={"i": i}, payload_type=PT)
    return log


def duplicate_anchor_record(trail: Path, *, sink: str) -> None:
    """One more `.anchors` record for the checkpoint the last one already
    carries, under a different sink name — `tests/test_cli_pin.py`'s own
    trick for manufacturing a distinct external sink without standing up a
    real RFC 3161 responder."""
    anchors = Path(str(trail) + ".anchors")
    record = json.loads(anchors.read_text().splitlines()[-1])
    record["sink"] = sink
    with open(anchors, "a") as f:
        f.write(json.dumps(record) + "\n")


def add_aggregate_binding(trail: Path) -> None:
    """Promote the last `.anchors` record to a SPEC 15 v2 record carrying an
    aggregate commitment. Hand-built, like `test_cli_pin.py`'s
    `_append_anchor_record`: the commitment's own value is not what preflight
    reports on (it holds no seal key to check it with), only its presence."""
    anchors = Path(str(trail) + ".anchors")
    record = json.loads(anchors.read_text().splitlines()[-1])
    record["v"] = 2
    record["agg_commit"] = "ab" * 32
    record["agg_epoch"] = 3
    with open(anchors, "a") as f:
        f.write(json.dumps(record) + "\n")


def declare_topology(
    pin: Path,
    *,
    seal_escrow: bool = True,
    anchor_sinks: int = 2,
    witness: bool = True,
    pin_separate: bool = True,
    ledger: bool | None = None,
) -> None:
    state = json.loads(pin.read_text())
    topology: dict[str, object] = {
        "seal_escrow": seal_escrow,
        "anchor_sinks": anchor_sinks,
        "witness": witness,
        "pin_separate": pin_separate,
    }
    if ledger is not None:
        # waxseal-fg4.45: only written when explicitly given, matching
        # domain/pinning.py's own omit-when-undeclared round-trip.
        topology["ledger"] = ledger
    state["declared_topology"] = topology
    pin.write_text(json.dumps(state))


def write_pin(trail: Path, pin: Path) -> None:
    assert main(["verify", str(trail), "--pin", str(pin)]) == 0


def preflight(
    capsys: pytest.CaptureFixture[str], *argv: str
) -> tuple[int, str]:
    code = main(["preflight", *argv])
    return code, capsys.readouterr().out


class TestLowestRung:
    def test_bare_trail_stops_nobody_and_says_what_rung_one_needs(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        trail = tmp_path / "trail.jsonl"
        make_trail(trail)
        code, out = preflight(capsys, str(trail))
        assert code == 0
        assert "stops an attacker at rung 0" in out
        assert "rung 1 needs:" in out
        assert "SPEC 11" in out

    def test_it_prints_the_whole_six_row_table(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        trail = tmp_path / "trail.jsonl"
        make_trail(trail)
        _, out = preflight(capsys, str(trail))
        assert "attacker-capability ladder" in out
        for n in range(1, 7):
            assert f"rung {n}" in out

    def test_it_names_the_trail_and_how_much_of_it_it_read(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        trail = tmp_path / "trail.jsonl"
        make_trail(trail, 3)
        _, out = preflight(capsys, str(trail))
        assert "3 recorded entries" in out
        assert "head seq=2" in out

    def test_an_empty_trail_reads_as_empty_not_as_unmeasured(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        trail = tmp_path / "trail.jsonl"
        trail.write_text("")
        _, out = preflight(capsys, str(trail))
        assert "0 recorded entries" in out
        assert "no head yet" in out


class TestMiddleRung:
    def test_a_sealed_trail_stops_rung_one(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        trail = tmp_path / "trail.jsonl"
        make_trail(trail, sealed=True)
        code, out = preflight(capsys, str(trail))
        assert code == 0
        assert "stops an attacker at rung 1" in out
        assert "rung 2 needs:" in out
        assert "trail.jsonl.attest" in out

    def test_a_sealed_locally_anchored_trail_stops_rung_two(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        trail = tmp_path / "trail.jsonl"
        make_trail(trail, sealed=True)
        assert main(["anchor", str(trail)]) == 0
        capsys.readouterr()
        code, out = preflight(capsys, str(trail))
        assert code == 0
        assert "stops an attacker at rung 2" in out
        # Rung 3 is the honest stopping point of a local-only configuration:
        # its other half (a witness) was never contacted, so the rung is
        # unmeasured rather than absent.
        assert "rung 3: NOT MEASURED" in out


class TestHighestRung:
    def test_full_stack_stops_rung_four_and_names_the_collusion_wall(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        trail = tmp_path / "trail.jsonl"
        make_trail(trail, sealed=True)
        assert main(["anchor", str(trail)]) == 0
        duplicate_anchor_record(trail, sink="rfc3161")
        duplicate_anchor_record(trail, sink="ots")
        add_aggregate_binding(trail)
        pin = tmp_path / "pin.json"
        write_pin(trail, pin)
        declare_topology(pin)
        capsys.readouterr()
        code, out = preflight(capsys, str(trail), "--pin", str(pin))
        assert code == 0
        assert "stops an attacker at rung 4" in out
        assert "rung 5: no configuration raises this rung" in out
        assert "administrative authority" in out
        assert "external anchor sinks: 2 observed" in out
        assert "ots" in out and "rfc3161" in out

    def test_the_top_of_the_ladder_is_still_only_tamper_evident(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # CLAUDE.md: "tamper-proof" is only ever SCOPED, so the strongest
        # reading this command can print must not read as one.
        trail = tmp_path / "trail.jsonl"
        make_trail(trail, sealed=True)
        assert main(["anchor", str(trail)]) == 0
        duplicate_anchor_record(trail, sink="rfc3161")
        add_aggregate_binding(trail)
        capsys.readouterr()
        _, out = preflight(capsys, str(trail))
        assert "tamper-proof" not in out


class TestDeclaredIsNotMeasured:
    def test_a_declared_topology_is_labelled_as_declared(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        trail = tmp_path / "trail.jsonl"
        make_trail(trail)
        pin = tmp_path / "pin.json"
        write_pin(trail, pin)
        declare_topology(pin, anchor_sinks=7)
        capsys.readouterr()
        _, out = preflight(capsys, str(trail), "--pin", str(pin))
        line = next(ln for ln in out.splitlines() if "pin on separate storage" in ln)
        assert "DECLARED" in line
        assert "declared, not measured" in out
        # The declared count must never be printed as if this run had seen it.
        assert "anchor_sinks=7" in out
        assert "external anchor sinks: 0 observed" in out

    def test_pin_on_separate_storage_is_never_measurable(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        trail = tmp_path / "trail.jsonl"
        make_trail(trail)
        pin = tmp_path / "pin.json"
        write_pin(trail, pin)
        declare_topology(pin, pin_separate=False)
        capsys.readouterr()
        _, out = preflight(capsys, str(trail), "--pin", str(pin))
        assert "pin on separate storage: DECLARED false" in out

    def test_no_pin_means_not_declared_not_declared_false(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        trail = tmp_path / "trail.jsonl"
        make_trail(trail)
        _, out = preflight(capsys, str(trail))
        assert "pin state: NOT READ" in out
        assert "pin on separate storage: NOT DECLARED" in out
        assert "τ (separation degree): not declared" in out

    def test_a_declared_witness_does_not_become_a_measured_one(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        trail = tmp_path / "trail.jsonl"
        make_trail(trail, sealed=True)
        assert main(["anchor", str(trail)]) == 0
        pin = tmp_path / "pin.json"
        write_pin(trail, pin)
        declare_topology(pin, witness=True)
        capsys.readouterr()
        _, out = preflight(capsys, str(trail), "--pin", str(pin))
        # A declaration must not raise the rung: rung 3 stays unmeasured.
        assert "rung 3: NOT MEASURED" in out
        assert "witness=true" in out

    def test_a_declared_ledger_does_not_become_a_measured_one(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # waxseal-fg4.45: the ledger dimension's own version of the witness
        # test immediately above — preflight opens no network connection to
        # check either one, so a DECLARED ledger authority must ride along
        # as a caveat on the NOT MEASURED line, never raise the rung.
        trail = tmp_path / "trail.jsonl"
        make_trail(trail, sealed=True)
        assert main(["anchor", str(trail)]) == 0
        pin = tmp_path / "pin.json"
        write_pin(trail, pin)
        declare_topology(pin, ledger=True)
        capsys.readouterr()
        _, out = preflight(capsys, str(trail), "--pin", str(pin))
        assert "rung 3: NOT MEASURED" in out
        assert "ledger=true" in out
        line = next(ln for ln in out.splitlines() if ln.strip().startswith("ledger (F4)"))
        assert "NOT MEASURED" in line
        assert "declared, not measured" in line

    def test_no_declared_ledger_reads_as_not_measured_not_declared_false(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # Rule 5, on the ledger row specifically: no pin at all must print
        # plain NOT MEASURED, with no "declared" caveat invented for a
        # topology that never mentioned ledger.
        trail = tmp_path / "trail.jsonl"
        make_trail(trail)
        _, out = preflight(capsys, str(trail))
        line = next(ln for ln in out.splitlines() if ln.strip().startswith("ledger (F4)"))
        assert "NOT MEASURED" in line
        assert "declared" not in line


class TestNotMeasuredIsNeverZero:
    def test_an_unparseable_anchor_sidecar_is_not_zero_records(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        trail = tmp_path / "trail.jsonl"
        make_trail(trail, sealed=True)
        Path(str(trail) + ".anchors").write_text("{not json at all\n")
        code, out = preflight(capsys, str(trail))
        assert code == 0
        # Rule 5, in the single easiest place in this command to lie: a
        # sidecar this build cannot read might have carried anything.
        assert "0 observed" not in out
        assert "rung 2: NOT MEASURED" in out
        assert "could not parse" in out

    def test_a_record_version_this_build_cannot_read_is_not_zero_sinks(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        trail = tmp_path / "trail.jsonl"
        make_trail(trail, sealed=True)
        Path(str(trail) + ".anchors").write_text(json.dumps({"v": "99"}) + "\n")
        code, out = preflight(capsys, str(trail))
        assert code == 0
        assert "unverifiable by name" in out
        assert "external anchor sinks: NOT MEASURED" in out
        assert "rung 2: NOT MEASURED" in out

    def test_a_witness_is_never_contacted_so_it_is_never_absent(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        trail = tmp_path / "trail.jsonl"
        make_trail(trail)
        _, out = preflight(capsys, str(trail))
        assert "witness (SPEC 14): NOT MEASURED" in out
        assert "contacts no witness" in out

    def test_distinct_administrative_domains_are_never_counted(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        trail = tmp_path / "trail.jsonl"
        make_trail(trail, sealed=True)
        assert main(["anchor", str(trail)]) == 0
        duplicate_anchor_record(trail, sink="rfc3161")
        capsys.readouterr()
        _, out = preflight(capsys, str(trail))
        # The sidecar names a sink TECHNOLOGY, never its operator, so two
        # rfc3161 records could be one TSA or two. Printing a domain count
        # would be inventing evidence this process never had.
        assert "distinct administrative domains: NOT MEASURED" in out

    def test_a_trail_this_build_cannot_read_is_not_an_empty_one(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        trail = tmp_path / "trail.jsonl"
        make_trail(trail)
        trail.write_text(trail.read_text() + "{torn line\n")
        code, out = preflight(capsys, str(trail))
        assert code == 0
        assert "entries: NOT READ" in out
        assert "recorded entries" not in out


class TestPinStates:
    def test_a_pin_that_does_not_exist_yet_is_not_a_declaration(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        trail = tmp_path / "trail.jsonl"
        make_trail(trail)
        code, out = preflight(capsys, str(trail), "--pin", str(tmp_path / "absent.json"))
        assert code == 0
        assert "no pin recorded yet" in out
        assert "pin on separate storage: NOT DECLARED" in out

    def test_a_malformed_pin_is_labelled_not_swallowed(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        trail = tmp_path / "trail.jsonl"
        make_trail(trail)
        pin = tmp_path / "pin.json"
        pin.write_text("not a pin state")
        code, out = preflight(capsys, str(trail), "--pin", str(pin))
        # Rule 6: the degradation is in the output. Still exit 0 — preflight
        # reports no verdict, and `waxseal verify --pin` is what calls this a
        # break.
        assert code == 0
        assert "malformed_pin" in out
        assert "waxseal verify --pin" in out

    def test_a_pin_from_a_newer_build_is_unverifiable_by_name(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        trail = tmp_path / "trail.jsonl"
        make_trail(trail)
        pin = tmp_path / "pin.json"
        write_pin(trail, pin)
        state = json.loads(pin.read_text())
        state["v"] = 99
        pin.write_text(json.dumps(state))
        capsys.readouterr()
        code, out = preflight(capsys, str(trail), "--pin", str(pin))
        assert code == 0
        assert "pin_version_unknown" in out
        assert "NOT evidence of tampering" in out

    def test_a_pin_declares_its_policies_and_they_are_re_presented(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        trail = tmp_path / "trail.jsonl"
        make_trail(trail)
        pin = tmp_path / "pin.json"
        assert (
            main(
                [
                    "verify", str(trail), "--pin", str(pin),
                    "--expect-anchor-binding", "--max-anchor-age-s", "3600",
                ]
            )
            == 0
        )
        capsys.readouterr()
        _, out = preflight(capsys, str(trail), "--pin", str(pin))
        assert "expect_anchor_binding: true" in out
        assert "max_anchor_age_s: 3600" in out

    def test_the_pin_is_not_presented_as_a_rung_stopper(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # threat-model.md section 5 names seals, anchors, an external anchor
        # and the SPEC 15 binding — not the pin, which lives in section 4's
        # table. Letting a pin raise a rung here would invent a row.
        trail = tmp_path / "trail.jsonl"
        make_trail(trail)
        pin = tmp_path / "pin.json"
        write_pin(trail, pin)
        declare_topology(pin)
        capsys.readouterr()
        _, out = preflight(capsys, str(trail), "--pin", str(pin))
        assert "stops an attacker at rung 0" in out
        assert "not a stopper on this ladder" in out


class TestSegments:
    def test_a_segmented_trail_says_the_rungs_describe_one_segment(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        base = tmp_path / "trail.jsonl"
        make_trail(base)
        segment = tmp_path / "trail.00000.jsonl"
        make_trail(segment)
        _, out = preflight(capsys, str(segment))
        assert "segment 2 of 2" in out
        assert "trail.00000" in out
        assert "SPEC 20" in out
        assert "THIS segment only" in out

    def test_an_unrotated_trail_says_so_rather_than_inventing_a_segment(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        trail = tmp_path / "trail.jsonl"
        make_trail(trail)
        _, out = preflight(capsys, str(trail))
        assert "segments: not rotated" in out


class TestNothingWasRead:
    def test_a_missing_trail_is_exit_three(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        code = main(["preflight", str(tmp_path / "nope.jsonl")])
        assert code == 3
        err = capsys.readouterr().err
        assert "no such trail" in err

    def test_a_url_target_is_exit_three_and_says_why(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # preflight reads LOCAL sidecars; a remote trail has no local sidecar
        # location at all, the same limit `verify-handoff --origin` carries.
        code = main(["preflight", "https://example.invalid/trail"])
        assert code == 3
        err = capsys.readouterr().err
        assert "local" in err


class TestItAppendsNothing:
    def test_preflight_writes_no_file_and_changes_none(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # CLAUDE.md's CLI contract: the CLI never appends chain entries, and
        # preflight is not one of the two spec'd verifier-state carve-outs
        # (`--pin`, `anchor`) — it writes nothing whatsoever.
        trail = tmp_path / "trail.jsonl"
        make_trail(trail, sealed=True)
        assert main(["anchor", str(trail)]) == 0
        pin = tmp_path / "pin.json"
        write_pin(trail, pin)
        capsys.readouterr()
        before = {p: p.read_bytes() for p in sorted(tmp_path.iterdir())}
        assert main(["preflight", str(trail), "--pin", str(pin)]) == 0
        after = {p: p.read_bytes() for p in sorted(tmp_path.iterdir())}
        assert before == after


class TestScope:
    def test_it_says_it_is_not_a_verdict(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        trail = tmp_path / "trail.jsonl"
        make_trail(trail)
        _, out = preflight(capsys, str(trail))
        assert "not a verdict" in out
        assert "waxseal verify" in out


class TestImmutablePrefixLines:
    """J4 (waxseal-p8s): the invariant prefix line (mechanism + checkpoint)
    and the scope-honest tail line (DESIGN.md §11), present in every
    scenario — not folded into the ladder, and never claiming a mechanism
    this command cannot check (no network, no storage credentials)."""

    def test_a_bare_trail_names_no_checkpoint_and_the_tail_is_the_whole_trail(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        trail = tmp_path / "trail.jsonl"
        make_trail(trail)
        _, out = preflight(capsys, str(trail))
        assert "immutable prefix: up to checkpoint NONE" in out
        assert "mechanism NOT CONFIRMED this run (finalized ledger / WORM / none)" in out
        assert "DESIGN.md §11" in out
        assert (
            "tail from the whole trail — nothing is anchored: tamper-evident "
            "only, never more"
        ) in out
        # CLAUDE.md: "tamper-proof" is only ever SCOPED, and this command
        # never claims it at all (same discipline as the ladder above).
        assert "tamper-proof" not in out

    def test_an_anchored_trail_names_the_latest_anchored_seq_both_lines(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        trail = tmp_path / "trail.jsonl"
        make_trail(trail, sealed=True)
        assert main(["anchor", str(trail)]) == 0
        capsys.readouterr()
        _, out = preflight(capsys, str(trail))
        assert "immutable prefix: up to checkpoint seq 2" in out
        assert "tail from seq 2 onward: tamper-evident only, never more" in out
        assert "tamper-proof" not in out

    def test_an_unparseable_sidecar_leaves_the_checkpoint_unmeasured_not_none(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # Same rule 5 discipline `TestNotMeasuredIsNeverZero` already checks
        # for the ladder: a sidecar this build cannot read might have
        # carried a checkpoint, so the prefix line must not print NONE.
        trail = tmp_path / "trail.jsonl"
        make_trail(trail, sealed=True)
        Path(str(trail) + ".anchors").write_text("{not json at all\n")
        _, out = preflight(capsys, str(trail))
        assert "immutable prefix: up to checkpoint UNMEASURED" in out
        assert "the .anchors sidecar could not be read" in out
        assert "tail from the whole trail — no checkpoint could be read" in out
        assert "up to checkpoint NONE" not in out

    def test_the_two_lines_sit_between_the_ladder_and_the_scope_line(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        trail = tmp_path / "trail.jsonl"
        make_trail(trail)
        _, out = preflight(capsys, str(trail))
        ladder_at = out.index("attacker-capability ladder")
        prefix_at = out.index("immutable prefix:")
        scope_at = out.index("scope: this is a reading of CONFIGURATION")
        assert ladder_at < prefix_at < scope_at
