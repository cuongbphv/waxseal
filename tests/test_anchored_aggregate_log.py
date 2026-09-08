"""End-to-end: the aggregate binding reaches an anchor, and the anchor catches
the attack the local sidecars cannot.

`tests/domain/test_anchored_aggregate.py` covers the arithmetic. This file
covers the wiring, which is where the property is actually won or lost: a
correct commitment that never reaches the anchor record protects nothing, and
an old anchor record that this build refuses to read would turn a v1 sidecar
into a false alarm.

The headline test is `test_replayed_aggregate_over_a_truncated_trail_is_caught`
— the scenario the aggregate scheme's own documentation lists as its residual
risk. It is paired with a falsifiability receipt: the same tampered state
passes every check that does not consult the anchor.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

import pytest

from waxseal import AuditLog
from waxseal.adapters.anchors import FileAnchorSink, read_anchor_records
from waxseal.adapters.attest import FileAttestor
from waxseal.domain.sealing import FS_HMAC_AGG_SCHEME, aggregate_commit

PT = "application/vnd.test.event+json"
KEY = b"\x22" * 32


def sealed_log(path: Path, *, anchor: bool = True) -> AuditLog:
    attestor = FileAttestor(path, initial_key=KEY, scheme=FS_HMAC_AGG_SCHEME)
    return AuditLog.open(
        path,
        attestor=attestor,
        anchor_sink=FileAnchorSink(path) if anchor else None,
    )


class TestAnchorCarriesTheBinding:
    def test_anchor_records_the_aggregate_commitment(self, tmp_path: Path) -> None:
        path = tmp_path / "trail.jsonl"
        log = sealed_log(path)
        for i in range(3):
            log.append(payload={"i": i}, payload_type=PT)
        cp = log.anchor()

        assert cp.agg_epoch == 3
        agg_start, epoch, agg = FileAttestor(path, initial_key=KEY).read_aggregate()  # type: ignore[misc]
        assert cp.agg_commit == aggregate_commit(epoch, agg)

    def test_the_commitment_not_the_accumulator_is_written(self, tmp_path: Path) -> None:
        # The rule the aggregate scheme lives by: an intermediate accumulator
        # in any durable record is a truncation hole.
        path = tmp_path / "trail.jsonl"
        log = sealed_log(path)
        for i in range(3):
            log.append(payload={"i": i}, payload_type=PT)
        log.anchor()

        _, _, agg = FileAttestor(path, initial_key=KEY).read_aggregate()  # type: ignore[misc]
        assert agg not in Path(str(path) + ".anchors").read_text()

    def test_record_is_version_2_when_bound(self, tmp_path: Path) -> None:
        path = tmp_path / "trail.jsonl"
        log = sealed_log(path)
        log.append(payload={"i": 0}, payload_type=PT)
        log.anchor()
        record = json.loads(Path(str(path) + ".anchors").read_text().strip())
        assert record["v"] == 2
        assert record["agg_epoch"] == 1

    def test_unsealed_log_still_writes_a_version_1_record(self, tmp_path: Path) -> None:
        # No aggregate to bind, so nothing changes for the overwhelming
        # majority of trails — including every one written before this
        # existed.
        path = tmp_path / "trail.jsonl"
        log = AuditLog.open(path, anchor_sink=FileAnchorSink(path))
        log.append(payload={"i": 0}, payload_type=PT)
        log.anchor()
        record = json.loads(Path(str(path) + ".anchors").read_text().strip())
        assert record["v"] == 1
        assert "agg_commit" not in record

    def test_plain_fs_hmac_seal_does_not_bind(self, tmp_path: Path) -> None:
        # fs-hmac without aggregation keeps no accumulator, so there is
        # nothing to commit to and the checkpoint must not claim otherwise.
        path = tmp_path / "trail.jsonl"
        log = AuditLog.open(
            path,
            attestor=FileAttestor(path, initial_key=KEY),
            anchor_sink=FileAnchorSink(path),
        )
        log.append(payload={"i": 0}, payload_type=PT)
        cp = log.anchor()
        assert cp.agg_commit is None


class TestVerifyAnchoredAggregates:
    def test_intact_trail_verifies(self, tmp_path: Path) -> None:
        path = tmp_path / "trail.jsonl"
        log = sealed_log(path)
        for i in range(4):
            log.append(payload={"i": i}, payload_type=PT)
        log.anchor()

        result = log.verify_anchored_aggregates(initial_key=KEY)
        assert result.ok
        assert result.checked == 1

    def unreadable_record(self) -> str:
        return (
            json.dumps(
                {
                    "entry_hash": "a" * 64,
                    "receipt": None,
                    "root": "b" * 64,
                    "seq": 0,
                    "sink": "file",
                    "ts": "t",
                    "v": 99,
                }
            )
            + "\n"
        )

    def test_a_record_this_build_cannot_read_is_named_not_swallowed(self, tmp_path: Path) -> None:
        # The API path and `verify --anchors` read the same sidecar and must
        # not disagree about it: the CLI already reports
        # `unreadable_record_version`, while this returned ok with reason None
        # and nothing to tell the caller a record went unlooked-at. That is an
        # unlabelled fail-open (CLAUDE.md rule 6).
        path = tmp_path / "trail.jsonl"
        log = sealed_log(path)
        for i in range(3):
            log.append(payload={"i": i}, payload_type=PT)
        log.anchor()
        anchors = Path(str(path) + ".anchors")
        anchors.write_text(anchors.read_text() + self.unreadable_record(), encoding="utf-8")

        result = log.verify_anchored_aggregates(initial_key=KEY)
        assert result.ok  # the readable record still verified
        assert result.checked == 1
        assert result.reason == "unreadable_record_version"

    def test_a_sidecar_of_nothing_but_unreadable_records_is_not_a_pass(
        self, tmp_path: Path
    ) -> None:
        path = tmp_path / "trail.jsonl"
        log = sealed_log(path, anchor=False)
        log.append(payload={"i": 0}, payload_type=PT)
        Path(str(path) + ".anchors").write_text(self.unreadable_record(), encoding="utf-8")

        result = log.verify_anchored_aggregates(initial_key=KEY)
        assert result.checked == 0
        assert result.reason == "unreadable_record_version"

    def test_replayed_aggregate_over_a_truncated_trail_is_caught(self, tmp_path: Path) -> None:
        path = tmp_path / "trail.jsonl"
        log = sealed_log(path)
        for i in range(5):
            log.append(payload={"i": i}, payload_type=PT)
        log.anchor()

        # Snapshot the state as it was at 2 rows, then restore it over a
        # truncated trail: keyfile, attestation sidecar and .sealagg all agree
        # with each other. This is the documented residual risk.
        agg_path = Path(str(path) + ".sealagg")
        key_path = Path(str(path) + ".sealkey")
        attest_path = Path(str(path) + ".attest")

        replay = tmp_path / "replay.jsonl"
        replay_log = sealed_log(replay, anchor=False)
        for i in range(2):
            replay_log.append(payload={"i": i}, payload_type=PT)

        path.write_text("\n".join(replay.read_text().splitlines()[:2]) + "\n")
        agg_path.write_bytes(Path(str(replay) + ".sealagg").read_bytes())
        key_path.write_bytes(Path(str(replay) + ".sealkey").read_bytes())
        attest_path.write_bytes(Path(str(replay) + ".attest").read_bytes())

        reopened = AuditLog.open(path, attestor=FileAttestor(path, initial_key=KEY))

        # Falsifiability receipt: every check that consults only local state
        # is satisfied by this forgery.
        assert reopened.verify().ok
        assert reopened.verify_attestations(initial_key=KEY).ok

        # The anchor is not local state. It still says five rows were folded.
        result = reopened.verify_anchored_aggregates(initial_key=KEY)
        assert not result.ok
        assert result.reason == "anchored_aggregate_epoch_mismatch"

    def test_a_forged_commitment_in_the_sidecar_is_caught(self, tmp_path: Path) -> None:
        path = tmp_path / "trail.jsonl"
        log = sealed_log(path)
        for i in range(3):
            log.append(payload={"i": i}, payload_type=PT)
        log.anchor()

        anchors = Path(str(path) + ".anchors")
        record = json.loads(anchors.read_text().strip())
        record["agg_commit"] = "ab" * 32
        anchors.write_text(json.dumps(record) + "\n")

        result = log.verify_anchored_aggregates(initial_key=KEY)
        assert not result.ok
        assert result.reason == "anchored_aggregate_mismatch"

    def test_v1_records_are_counted_unverifiable_not_broken(self, tmp_path: Path) -> None:
        # An anchor taken before the binding existed carries no aggregate
        # claim. Reporting that as a failure would call an old, honest record
        # a forgery.
        path = tmp_path / "trail.jsonl"
        log = sealed_log(path)
        for i in range(3):
            log.append(payload={"i": i}, payload_type=PT)
        anchors = Path(str(path) + ".anchors")
        anchors.write_text(
            json.dumps(
                {
                    "entry_hash": log.entry_hashes()[-1],
                    "receipt": None,
                    "root": "0" * 64,
                    "seq": 2,
                    "sink": "file",
                    "ts": "2026-08-23T09:00:00+00:00",
                    "v": 1,
                }
            )
            + "\n"
        )

        result = log.verify_anchored_aggregates(initial_key=KEY)
        assert result.ok
        assert result.checked == 0
        assert result.unverifiable == (2,)

    def test_no_anchors_is_not_a_pass(self, tmp_path: Path) -> None:
        path = tmp_path / "trail.jsonl"
        log = sealed_log(path, anchor=False)
        log.append(payload={"i": 0}, payload_type=PT)
        result = log.verify_anchored_aggregates(initial_key=KEY)
        assert result.ok
        assert result.checked == 0
        assert result.reason == "no_anchors_recorded"

    def test_signer_mode_attestor_has_no_aggregate_to_bind(self, tmp_path: Path) -> None:
        # A signer-backed attestor keeps no accumulator: agg_start stays 0 and
        # every anchor record is unverifiable-for-aggregate rather than a
        # failure, because no aggregate claim was ever made.
        class FakeSigner:
            algorithm = "ed25519"
            key_id = "k1"

            def sign(self, data: bytes) -> bytes:
                return b"\x01" * 64

        path = tmp_path / "trail.jsonl"
        attestor = FileAttestor(path, signer=FakeSigner())
        log = AuditLog.open(path, attestor=attestor, anchor_sink=FileAnchorSink(path))
        log.append(payload={"i": 0}, payload_type=PT)
        cp = log.anchor()
        assert cp.agg_commit is None

        result = log.verify_anchored_aggregates(initial_key=KEY)
        assert result.ok
        assert result.unverifiable == (0,)

    def test_attestor_without_an_aggregate_api_is_tolerated(self, tmp_path: Path) -> None:
        # The attestor port is structural: a third-party implementation need
        # not have read_aggregate at all. Assuming it does would turn a valid
        # custom attestor into an AttributeError mid-audit.
        from waxseal.domain.sealing import Attestation

        class MinimalAttestor:
            def __init__(self) -> None:
                self.seen: list[Attestation] = []

            def attest(self, seq: int, entry_hash: str) -> Attestation:
                att = Attestation(seq=seq, entry_hash=entry_hash, scheme="custom-v1", value="00")
                self.seen.append(att)
                return att

            def attestations(self) -> list[Attestation]:
                return self.seen

            trail_path = None  # replaced below, once tmp_path is known

        path = tmp_path / "trail.jsonl"
        attestor = MinimalAttestor()
        attestor.trail_path = path  # type: ignore[assignment]
        log = AuditLog.open(path, attestor=attestor, anchor_sink=FileAnchorSink(path))
        log.append(payload={"i": 0}, payload_type=PT)
        cp = log.anchor()
        assert cp.agg_commit is None

        result = log.verify_anchored_aggregates(initial_key=KEY)
        assert result.ok
        assert result.unverifiable == (0,)

    def test_requires_an_attestor(self, tmp_path: Path) -> None:
        path = tmp_path / "trail.jsonl"
        log = AuditLog.open(path)
        log.append(payload={"i": 0}, payload_type=PT)
        with pytest.raises(ValueError, match="attestor"):
            log.verify_anchored_aggregates(initial_key=KEY)

    def test_malformed_sidecar_is_a_verdict_not_a_crash(self, tmp_path: Path) -> None:
        path = tmp_path / "trail.jsonl"
        log = sealed_log(path)
        log.append(payload={"i": 0}, payload_type=PT)
        Path(str(path) + ".anchors").write_text("{ not json\n")

        result = log.verify_anchored_aggregates(initial_key=KEY)
        assert not result.ok
        assert result.reason == "malformed_anchor"


class TestReadAnchorRecords:
    def test_reads_v1_and_v2_records_together(self, tmp_path: Path) -> None:
        path = tmp_path / "trail.jsonl"
        anchors = Path(str(path) + ".anchors")
        anchors.write_text(
            "\n".join(
                [
                    json.dumps(
                        {
                            "entry_hash": "a" * 64,
                            "receipt": None,
                            "root": "b" * 64,
                            "seq": 0,
                            "sink": "file",
                            "ts": "t",
                            "v": 1,
                        }
                    ),
                    json.dumps(
                        {
                            "entry_hash": "c" * 64,
                            "receipt": "r",
                            "root": "d" * 64,
                            "seq": 1,
                            "sink": "http",
                            "ts": "t",
                            "v": 2,
                            "agg_commit": "e" * 64,
                            "agg_epoch": 2,
                        }
                    ),
                ]
            )
            + "\n"
        )
        sidecar = read_anchor_records(path)
        assert [r.checkpoint.seq for r in sidecar.records] == [0, 1]
        assert sidecar.records[0].checkpoint.agg_commit is None
        assert sidecar.records[1].checkpoint.agg_epoch == 2
        assert sidecar.records[1].receipt == "r"
        assert sidecar.unreadable_versions == ()

    def test_a_record_from_a_newer_version_is_unreadable_not_fatal(self, tmp_path: Path) -> None:
        # The beads-v1.2.2 class applied to the sidecar's own version field.
        path = tmp_path / "trail.jsonl"
        Path(str(path) + ".anchors").write_text(
            json.dumps(
                {
                    "entry_hash": "a" * 64,
                    "receipt": None,
                    "root": "b" * 64,
                    "seq": 0,
                    "sink": "file",
                    "ts": "t",
                    "v": 99,
                }
            )
            + "\n"
        )
        sidecar = read_anchor_records(path)
        assert sidecar.records == ()
        assert sidecar.unreadable_versions == ("99",)

    def test_a_missing_version_defaults_to_v1(self, tmp_path: Path) -> None:
        # Records this library wrote before it stamped a version are v1 by
        # definition; refusing them would strand every existing sidecar.
        path = tmp_path / "trail.jsonl"
        Path(str(path) + ".anchors").write_text(
            json.dumps({"entry_hash": "a" * 64, "root": "b" * 64, "seq": 0}) + "\n"
        )
        sidecar = read_anchor_records(path)
        assert len(sidecar.records) == 1
        assert sidecar.records[0].sink == "unknown"
        assert sidecar.records[0].receipt is None

    def test_absent_sidecar_reads_as_empty(self, tmp_path: Path) -> None:
        sidecar = read_anchor_records(tmp_path / "trail.jsonl")
        assert sidecar.records == ()
        assert sidecar.unreadable_versions == ()

    def test_malformed_lines_raise_for_the_caller_to_render(self, tmp_path: Path) -> None:
        # A verdict of malformed_anchor belongs to the CLI, which knows the
        # exit code; the reader's job is only to refuse to invent data.
        path = tmp_path / "trail.jsonl"
        Path(str(path) + ".anchors").write_text("{ not json\n")
        with pytest.raises(ValueError):
            read_anchor_records(path)

    def test_blank_lines_are_skipped(self, tmp_path: Path) -> None:
        path = tmp_path / "trail.jsonl"
        Path(str(path) + ".anchors").write_text(
            "\n" + json.dumps({"entry_hash": "a" * 64, "root": "b" * 64, "seq": 0, "v": 1}) + "\n\n"
        )
        assert len(read_anchor_records(path).records) == 1

    def test_a_json_array_line_is_refused(self, tmp_path: Path) -> None:
        # Valid JSON, not a record. Reading index 0 of it and calling the
        # result a checkpoint would invent data.
        path = tmp_path / "trail.jsonl"
        Path(str(path) + ".anchors").write_text("[1, 2, 3]\n")
        with pytest.raises(ValueError, match="JSON object"):
            read_anchor_records(path)

    def test_legacy_records_iterator_still_yields_checkpoints(self, tmp_path: Path) -> None:
        path = tmp_path / "trail.jsonl"
        log = AuditLog.open(path, anchor_sink=FileAnchorSink(path))
        log.append(payload={"i": 0}, payload_type=PT)
        log.anchor()
        assert [cp.seq for cp in FileAnchorSink(path).records()] == [0]


class TestHTTPAnchorSinkBinding:
    def test_body_carries_the_binding_when_present(self) -> None:
        from waxseal.adapters.anchors import HTTPAnchorSink
        from waxseal.adapters.remote import RemoteResponse
        from waxseal.domain.checkpoint import Checkpoint

        sent: list[bytes] = []

        def transport(request: object) -> RemoteResponse:
            sent.append(request.body)  # type: ignore[attr-defined]
            return RemoteResponse(status=200, headers={}, body=b"{}")

        sink = HTTPAnchorSink("http://witness/anchor", transport=transport)
        sink.anchor(
            Checkpoint(seq=1, entry_hash="a" * 64, root="b" * 64, agg_commit="c" * 64, agg_epoch=2)
        )
        body = json.loads(sent[0])
        assert body["agg_commit"] == "c" * 64
        assert body["agg_epoch"] == 2

    def test_body_omits_the_binding_when_absent(self) -> None:
        from waxseal.adapters.anchors import HTTPAnchorSink
        from waxseal.adapters.remote import RemoteResponse
        from waxseal.domain.checkpoint import Checkpoint

        sent: list[bytes] = []

        def transport(request: object) -> RemoteResponse:
            sent.append(request.body)  # type: ignore[attr-defined]
            return RemoteResponse(status=200, headers={}, body=b"{}")

        sink = HTTPAnchorSink("http://witness/anchor", transport=transport)
        sink.anchor(Checkpoint(seq=1, entry_hash="a" * 64, root="b" * 64))
        assert "agg_commit" not in json.loads(sent[0])


class TestCliLabelsTheUncheckedBinding:
    def test_verify_anchors_says_the_binding_was_not_checked(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # The CLI holds no seal key, so it can check the chain shape of a v2
        # record but not its aggregate claim. Rule 6: say so.
        from waxseal.cli import main

        path = tmp_path / "trail.jsonl"
        log = sealed_log(path)
        for i in range(2):
            log.append(payload={"i": i}, payload_type=PT)
        log.anchor()

        assert main(["verify", str(path), "--anchors"]) == 0
        out = capsys.readouterr().out
        assert "aggregate binding" in out
        assert "NOT checked" in out

    def test_no_such_note_without_a_binding(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from waxseal.cli import main

        path = tmp_path / "trail.jsonl"
        log = AuditLog.open(path, anchor_sink=FileAnchorSink(path))
        log.append(payload={"i": 0}, payload_type=PT)
        log.anchor()
        assert main(["verify", str(path), "--anchors"]) == 0
        assert "aggregate binding" not in capsys.readouterr().out

    def test_unreadable_record_version_is_exit_2(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from waxseal.cli import main

        path = tmp_path / "trail.jsonl"
        log = AuditLog.open(path)
        log.append(payload={"i": 0}, payload_type=PT)
        Path(str(path) + ".anchors").write_text(
            json.dumps(
                {
                    "entry_hash": "a" * 64,
                    "receipt": None,
                    "root": "b" * 64,
                    "seq": 0,
                    "sink": "file",
                    "ts": "t",
                    "v": 99,
                }
            )
            + "\n"
        )
        assert main(["verify", str(path), "--anchors"]) == 2
        out = capsys.readouterr().out
        assert "unreadable" in out
        assert "NOT evidence of tampering" in out


class TestKeylessAggregateBinding:
    """`waxseal anchor` holds no seal key, but binding the aggregate does not
    need one — only the accumulator already on disk. Omitting the binding
    because the CLI cannot seal would publish an unbound checkpoint on a sealed
    trail: the anchor would then witness a chain shape nobody can tie back to
    the aggregate, which is precisely the gap the binding closes."""

    def test_reader_returns_the_persisted_state(self, tmp_path: Path) -> None:
        from waxseal.adapters.attest import AggregateReader

        path = tmp_path / "trail.jsonl"
        log = sealed_log(path, anchor=False)
        for i in range(3):
            log.append(payload={"i": i}, payload_type=PT)

        reader = AggregateReader(path)
        assert reader.trail_path == path
        assert reader.read_aggregate() == FileAttestor(path, initial_key=KEY).read_aggregate()

    def test_reader_on_an_unsealed_trail_reads_nothing(self, tmp_path: Path) -> None:
        from waxseal.adapters.attest import AggregateReader

        path = tmp_path / "trail.jsonl"
        AuditLog.open(path).append(payload={"i": 0}, payload_type=PT)
        assert AggregateReader(path).read_aggregate() is None

    def test_a_keyless_view_still_binds(self, tmp_path: Path) -> None:
        from waxseal.adapters.attest import AggregateReader

        path = tmp_path / "trail.jsonl"
        log = sealed_log(path, anchor=False)
        for i in range(2):
            log.append(payload={"i": i}, payload_type=PT)

        keyless = AuditLog.open(path)
        cp = keyless.with_anchor_sink(
            FileAnchorSink(path), aggregate_source=AggregateReader(path)
        ).anchor()
        assert cp.agg_epoch == 2
        assert cp.agg_commit is not None

    def test_cli_anchor_binds_a_sealed_trail(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from waxseal.cli import main

        path = tmp_path / "trail.jsonl"
        log = sealed_log(path, anchor=False)
        for i in range(3):
            log.append(payload={"i": i}, payload_type=PT)

        assert main(["anchor", str(path)]) == 0
        printed = json.loads(capsys.readouterr().out.strip())
        assert printed["agg_epoch"] == 3
        _, epoch, agg = FileAttestor(path, initial_key=KEY).read_aggregate()  # type: ignore[misc]
        assert printed["agg_commit"] == aggregate_commit(epoch, agg)

    def test_cli_anchor_on_an_unsealed_trail_is_unchanged(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from waxseal.cli import main

        path = tmp_path / "trail.jsonl"
        AuditLog.open(path).append(payload={"i": 0}, payload_type=PT)
        assert main(["anchor", str(path)]) == 0
        assert "agg_commit" not in json.loads(capsys.readouterr().out.strip())


class TestFaultInjectionBetweenAnchorsAndSealagg:
    """`anchor()` reads `.sealagg` to bind a commitment into the checkpoint,
    THEN writes that checkpoint to `.anchors` — a read-then-write pair
    across the two files this module's own docstring calls out ("the
    aggregate binding reaches an anchor"). Both directions of a crash
    between them must surface as something checkable, never a silent pass
    and never a raw crash indistinguishable from an unrelated bug
    elsewhere (CLAUDE.md rule 6).
    """

    def test_a_crash_mid_write_of_the_anchors_record_is_a_labelled_mismatch(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The `.sealagg` read that feeds the checkpoint's binding succeeds
        # (three appends sealed cleanly first); the crash lands DURING the
        # dependent `.anchors` write, after some bytes already reached disk
        # — a real torn record, not merely "raised before touching the
        # file". `file_lock` (CLAUDE.md rule 7) only serializes this writer
        # against OTHER writers; it cannot stop this writer's own process
        # from dying mid-syscall.
        import os

        path = tmp_path / "trail.jsonl"
        log = sealed_log(path)
        for i in range(3):
            log.append(payload={"i": i}, payload_type=PT)

        real_fdopen = os.fdopen

        class TornFile:
            def __init__(self, real: object) -> None:
                self._real = real

            def write(self, s: str) -> None:
                self._real.write(s[:10])  # type: ignore[attr-defined]
                self._real.flush()  # type: ignore[attr-defined]
                raise OSError("simulated crash mid-write of the .anchors record")

            def __enter__(self) -> TornFile:
                return self

            def __exit__(self, *exc: object) -> Literal[False]:
                self._real.close()  # type: ignore[attr-defined]
                return False

        def faulty_fdopen(fd: int, *a: object, **kw: object) -> object:
            # os.fdopen's overloads key off literal mode strings; this stub
            # forwards whatever the real caller passed through unchanged.
            return TornFile(real_fdopen(fd, *a, **kw))  # type: ignore[call-overload]

        monkeypatch.setattr(os, "fdopen", faulty_fdopen)
        with pytest.raises(OSError, match="simulated crash"):
            log.anchor()
        monkeypatch.undo()

        # The torn line is unreadable BY NAME (a parse failure), which is
        # exactly what must never be silently accepted as a valid record.
        with pytest.raises(ValueError):
            read_anchor_records(path)

        result = log.verify_anchored_aggregates(initial_key=KEY)
        assert not result.ok
        assert result.reason == "malformed_anchor"
        # The CHAIN itself was never touched — a torn LOCAL sidecar must
        # never read back as the chain having been tampered with.
        assert log.verify().ok

    def test_a_malformed_sealagg_refuses_the_anchor_with_a_named_reason(
        self, tmp_path: Path
    ) -> None:
        # The other direction: the FIRST step (reading `.sealagg` to build
        # the commitment) is itself corrupt, so the dependent `.anchors`
        # write must never even be attempted.
        path = tmp_path / "trail.jsonl"
        log = sealed_log(path)
        for i in range(3):
            log.append(payload={"i": i}, payload_type=PT)
        (tmp_path / "trail.jsonl.sealagg").write_text("{not json at all")

        with pytest.raises(RuntimeError, match="sealagg.*malformed"):
            log.anchor()

        assert not (tmp_path / "trail.jsonl.anchors").exists()
        assert log.verify().ok
