"""A server-hosted chain rotates (waxseal-fg4.17).

Workstream B built segment rotation for the HOOK path and the server writes
through the library directly, so the deployment path — the one place a trail
grows for months unattended — kept appending to a single `trail.jsonl` forever.
The owner settled the scope question on 01/09/2026: a hosted chain SHOULD
rotate, for bounded growth, for a Segments screen that is useful rather than
merely correct, and so J3 archiving reaches hosted chains at all.

THE HAZARD THIS FILE EXISTS FOR. REMOTE.md section 4's compare-and-set is
atomic because `JSONLBackend.append`'s builder runs under the backend's own
per-file lock: the tail that decides the precondition is the tail of the file
being written. Rotation puts `segments.lock` ABOVE that, so there are now two
nested critical sections over two different files, and the new window is not
the CAS itself but the segment the CAS lands in: a rotation between "which
file is active" and "append to it" seals a segment that an append is still
about to extend. The result is a sealed segment whose bound tail is not its
tail — evidence the server manufactured against itself.

Two falsifiability receipts, because the two failures need different shapes of
test. `TestRotationUnderConcurrency` measures the fork (rule 7) under eight
racing writers. `TestARotationCannotSealTheSegmentAnAppendIsLandingIn` measures
the rotation window, by constructing the interleaving instead of hoping eight
threads stumble into it — and its receipt records that the racing-writers test
stays GREEN without the lock, which is why it is not the one that pins it.
"""

from __future__ import annotations

import json
import logging
import threading
from pathlib import Path
from typing import Any, cast

import pytest
from fastapi.testclient import TestClient
from waxseal_server.app import Settings, create_app
from waxseal_server.domain.errors import PreconditionFailed
from waxseal_server.storage.chains import ChainStore, decode_cursor, encode_cursor

from tests.adapters.test_jsonl import build_entry
from waxseal.adapters.jsonl import JSONLBackend
from waxseal.domain.archive import ArchiveReport, ArchiveState
from waxseal.domain.header import GENESIS_PREV_HASH
from waxseal.domain.registry import VersionRegistry
from waxseal.domain.segments import ROTATION_PAYLOAD_TYPE
from waxseal.domain.verify import verify_chain
from waxseal.sources.rotation import open_segmented, segments_lock

#: A measured stored envelope here is ~450 bytes, so this leaves ~3 entries to
#: a segment: small enough that a handful of appends rotates several times,
#: large enough that a fresh segment is not instantly over threshold again
#: (which would be a property of the fixture, not of the code).
TINY = 1400


def envelope_for(scratch: Path, seq: int, prev_hash: str, payload: bytes) -> dict[str, Any]:
    """A real client envelope for an exact `(seq, prev_hash)`.

    Written through the library's own backend and read back off disk, for
    `conftest.build_envelopes`' reason: an envelope this test hand-rolled could
    let the server agree with the test and disagree with every real client. The
    builder ignores the `(next_seq, prev_hash)` it is handed on purpose —
    choosing them is the whole point — and the scratch file is disposable.
    """
    scratch.parent.mkdir(parents=True, exist_ok=True)
    scratch.unlink(missing_ok=True)
    JSONLBackend(scratch).append(lambda *_: build_entry(seq, prev_hash, payload))
    return cast(dict[str, Any], json.loads(scratch.read_text(encoding="utf-8").splitlines()[-1]))


def stored(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]


def genesis_binding(segment: Path) -> dict[str, Any]:
    """The rotation binding at seq 0 of `segment`, decoded from its payload."""
    import base64

    first = stored(segment)[0]
    assert first["header"]["payload_type"] == ROTATION_PAYLOAD_TYPE
    return cast(dict[str, Any], json.loads(base64.b64decode(first["payload_b64"])))


def fill_over(store: ChainStore, tmp_path: Path, chain_id: str, count: int) -> list[str]:
    """Append `count` entries one at a time, returning their entry hashes.

    Retries a `PreconditionFailed` exactly as REMOTE.md section 4 tells a
    client to — re-read the head, rebuild, never resend the same body. A
    rotation invalidates the head this caller was holding, so the 409 is the
    contract working, not a failure to route around: `RemoteBackend` does the
    same thing on the wire.
    """
    landed: list[str] = []
    for i in range(count):
        for _ in range(8):
            head = store.head(chain_id)
            seq, prev = (0, GENESIS_PREV_HASH) if head is None else (head[0] + 1, head[1])
            envelope = envelope_for(
                tmp_path / "scratch" / "seq.jsonl", seq, prev, json.dumps({"i": i}).encode()
            )
            try:
                landed.append(store.append(chain_id, envelope).entry_hash)
            except PreconditionFailed:
                continue
            break
        else:  # pragma: no cover - a single-threaded caller cannot lose twice
            raise AssertionError("the head kept moving with no other writer")
    return landed


@pytest.fixture
def store(tmp_path: Path) -> ChainStore:
    return ChainStore(tmp_path / "chains", max_segment_bytes=TINY, notice=lambda _m: None)


class TestRotationOnTheDeploymentPath:
    def test_a_chain_under_the_threshold_stays_one_file(self, tmp_path: Path) -> None:
        big = ChainStore(tmp_path / "chains", notice=lambda _m: None)
        fill_over(big, tmp_path, "default", 3)
        assert [p.name for p in big.segment_paths("default")] == ["trail.jsonl"]

    def test_a_chain_past_the_threshold_seals_its_base_and_opens_a_segment(
        self, store: ChainStore, tmp_path: Path
    ) -> None:
        landed = fill_over(store, tmp_path, "default", 8)
        names = [p.name for p in store.segment_paths("default")]
        assert names[0] == "trail.jsonl"
        assert len(names) > 1, "the threshold never fired; this test proves nothing"
        assert names[1:] == sorted(names[1:])
        assert len(landed) == 8

    def test_every_sealed_segment_is_bound_by_its_successor_at_its_own_tail(
        self, store: ChainStore, tmp_path: Path
    ) -> None:
        fill_over(store, tmp_path, "default", 8)
        segments = store.segment_paths("default")
        for sealed, successor in zip(segments, segments[1:], strict=False):
            binding = genesis_binding(successor)
            entries = stored(sealed)
            assert binding["seq"] == len(entries) - 1
            assert binding["head_hash"] == entries[-1]["entry_hash"]

    def test_every_segment_verifies_as_its_own_chain(
        self, store: ChainStore, tmp_path: Path
    ) -> None:
        # Segments are linked by a binding, never by prev_hash across a file
        # boundary (SPEC.md section 20), so each one starts again at seq 0 with
        # a genesis prev_hash and must verify standalone.
        fill_over(store, tmp_path, "default", 8)
        for segment in store.segment_paths("default"):
            entries = list(JSONLBackend(segment).entries())
            assert verify_chain(entries, VersionRegistry()).ok, segment.name
            assert entries[0].header.prev_hash == GENESIS_PREV_HASH

    def test_nothing_already_written_is_rewritten_when_a_chain_rotates(
        self, store: ChainStore, tmp_path: Path
    ) -> None:
        # What an operator upgrading an existing hosted chain gets: the bytes
        # already on disk are never migrated, re-hashed or re-numbered. The
        # base file becomes segment "before 0" exactly as it does on the hook
        # path, and rotation only ever CREATES a file.
        fill_over(store, tmp_path, "default", 3)
        base = store.trail_path("default")
        before = base.read_bytes()
        fill_over(store, tmp_path, "default", 6)
        assert store.trail_path("default").read_bytes().startswith(before)
        assert len(store.segment_paths("default")) > 1


class TestTheReadSurfaceFollowsTheActiveSegment:
    def test_head_is_the_tail_of_the_segment_being_written(
        self, store: ChainStore, tmp_path: Path
    ) -> None:
        landed = fill_over(store, tmp_path, "default", 8)
        active = store.active_trail_path("default")
        assert active != store.trail_path("default")
        head = store.head("default")
        assert head is not None
        assert head[1] == stored(active)[-1]["entry_hash"] == landed[-1]

    def test_a_rotated_chain_still_verifies_through_a_paging_client(
        self, store: ChainStore, tmp_path: Path
    ) -> None:
        # The reason paging never crosses a segment boundary: concatenating two
        # segments hands a client verifier a seq that restarts at 0, which is
        # fork-shaped. A false tamper alarm the server manufactured out of its
        # own housekeeping is the one thing this project must never print.
        fill_over(store, tmp_path, "default", 8)
        page, _ = store.page("default", cursor=None, limit=100)
        entries = [json.loads(json.dumps(obj)) for obj in page]
        assert entries[0]["header"]["seq"] == 0
        assert verify_chain(
            list(JSONLBackend(store.active_trail_path("default")).entries()), VersionRegistry()
        ).ok

    def test_a_cursor_keeps_reading_the_segment_it_was_issued_against(
        self, store: ChainStore, tmp_path: Path
    ) -> None:
        # A reader mid-page when a rotation lands must not be silently
        # short-read against a file it never saw the start of.
        fill_over(store, tmp_path, "default", 3)
        first_page, cursor = store.page("default", cursor=None, limit=2)
        assert cursor is not None
        opened = store.active_trail_path("default")
        fill_over(store, tmp_path, "default", 6)
        assert store.active_trail_path("default") != opened
        rest, _ = store.page("default", cursor=cursor, limit=100)
        assert len(first_page) + len(rest) == len(stored(opened))

    def test_a_cursor_naming_a_segment_this_chain_does_not_have_is_refused(
        self, store: ChainStore, tmp_path: Path
    ) -> None:
        fill_over(store, tmp_path, "default", 3)
        with pytest.raises(ValueError):
            store.page("default", cursor="e0~trail.09999", limit=10)

    def test_a_cursor_cannot_name_a_path_outside_the_chain(
        self, store: ChainStore, tmp_path: Path
    ) -> None:
        fill_over(store, tmp_path, "default", 3)
        with pytest.raises(ValueError):
            store.page("default", cursor="e0~../../etc/passwd", limit=10)

    def test_a_summary_counts_every_segment_not_just_the_live_one(
        self, store: ChainStore, tmp_path: Path
    ) -> None:
        landed = fill_over(store, tmp_path, "default", 8)
        segments = store.segment_paths("default")
        summary = store.summary("default")
        assert summary.entries == len(landed) + len(segments) - 1  # + one binding per rotation
        assert summary.size_bytes == sum(p.stat().st_size for p in segments)
        assert summary.head == store.head("default")

    def test_a_chain_restored_from_numbered_segments_alone_is_still_listed(
        self, store: ChainStore, tmp_path: Path
    ) -> None:
        # An operator who restored only the later segments from an off-box
        # archive has a chain. A listing keyed on the unnumbered base alone
        # would report it as absent.
        fill_over(store, tmp_path, "default", 8)
        store.trail_path("default").unlink()
        assert store.chain_ids() == ["default"]
        assert store.head("default") is not None


class TestReceiptsSurviveRotation:
    def test_the_cross_check_holds_across_a_rotation(
        self, store: ChainStore, tmp_path: Path
    ) -> None:
        # Receipts span every segment; entry seq restarts at 0 in each. A
        # cross-check that only knew the active segment would report every
        # older acknowledgment as `receipt_beyond_head` — a rollback alarm
        # raised by the server's own housekeeping.
        landed = fill_over(store, tmp_path, "default", 8)
        report = store.cross_check_receipts("default")
        assert report.reason is None
        assert report.checked == len(landed)
        assert report.verdict.to_exit_code() == 0

    def test_the_cross_check_still_catches_an_edit_in_a_sealed_segment(
        self, store: ChainStore, tmp_path: Path
    ) -> None:
        fill_over(store, tmp_path, "default", 8)
        sealed = store.segment_paths("default")[0]
        records = stored(sealed)
        records[0]["entry_hash"] = "ff" * 32
        sealed.write_text(
            "".join(json.dumps(r, sort_keys=True, separators=(",", ":")) + "\n" for r in records),
            encoding="utf-8",
        )
        report = store.cross_check_receipts("default")
        assert report.reason == "receipt_mismatch"
        assert report.broken_seq == 0


class TestArchivingReachesHostedChains:
    def test_a_sealed_segment_is_offered_to_the_archive_outside_the_lock(
        self, tmp_path: Path
    ) -> None:
        # J3's archive step is a NETWORK call and runs outside `segments.lock`
        # deliberately (rotation.py::_archive_sealed): a stalled endpoint
        # holding that lock would block every writer that needs to rotate,
        # which is unbounded growth arriving by J3's own hand. The server must
        # inherit that placement, not undo it by wrapping the call.
        taken = threading.Event()
        seen: list[str] = []

        def destination(name: str, data: bytes) -> ArchiveReport:
            seen.append(name)

            def grab() -> None:
                with segments_lock(store.trail_path("default")):
                    taken.set()

            thread = threading.Thread(target=grab)
            thread.start()
            thread.join(timeout=10)
            return ArchiveReport(
                state=ArchiveState.STORED, destination="test", detail=f"{len(data)} bytes"
            )

        store = ChainStore(
            tmp_path / "chains",
            max_segment_bytes=TINY,
            notice=lambda _m: None,
            archive=destination,
        )
        fill_over(store, tmp_path, "default", 8)
        assert seen, "no segment was ever offered to the archive"
        assert taken.is_set(), "the archive ran while segments.lock was still held"

    def test_no_archive_destination_is_a_labelled_state_not_a_silence(self, tmp_path: Path) -> None:
        notices: list[str] = []
        store = ChainStore(tmp_path / "chains", max_segment_bytes=TINY, notice=notices.append)
        fill_over(store, tmp_path, "default", 8)
        assert any("rotated" in line for line in notices)
        assert any("exists only on this box" in line for line in notices)


class TestARotationCannotSealTheSegmentAnAppendIsLandingIn:
    """The window `segments_lock` closes in `ChainStore.append`, forced open.

    The interleaving is CONSTRUCTED rather than hoped for. Eight racing writers
    (below) do not reach it: every writer calls `open_segmented` immediately
    before resolving the active segment, so a writer whose segment is over
    threshold is itself inside the rotation lock, and a writer whose segment is
    under it cannot have that segment sealed without an append that would fail
    its own compare-and-set first. Hoping a thread schedule stumbles into a
    window that argument says is narrow is how a concurrency test comes out
    green for the wrong reason — so this one holds the append at the exact
    point the lock protects and rotates underneath it.

    FALSIFIABILITY RECEIPT — measured 01/09/2026, not argued from theory.
    `ChainStore.append`'s `with segments_lock(base):` was replaced by
    `contextlib.nullcontext()` (the only change; the CAS builder and the
    backend's own per-file lock left exactly as they are):

        with segments_lock : 3/3 runs green. The rotation blocks, the held
                             append lands, `trail.jsonl` is sealed at seq 3
                             and `trail.00000.jsonl`'s binding names seq 3.
        without            : 3/3 runs RED, same failure every time —
                             test_the_append_completes_before_a_rotation_can_seal_its_segment
                               -> "AssertionError: assert 2 == (4 - 1)"
                             The rotation gets in first and binds seq 2; the
                             held append then extends the sealed file to four
                             entries, so its tail is seq 3 and the binding is
                             one entry short of the file it sealed. The
                             preceding assertion still holds in both cases —
                             the entry IS in the sealed segment — which is why
                             the binding, not the append, is what detects it.

    What does NOT break without the lock is the chain: the append still holds
    the backend's per-file lock and the CAS still runs under it, so there is no
    fork and rule 7 is intact. What breaks is the SEGMENT the append lands in.
    The sealed file grows past the tail its successor's binding names, and
    `waxseal segments` then reads a rotation binding that does not point at the
    end of what it sealed — the server manufacturing evidence against itself
    out of its own housekeeping.
    """

    def test_the_append_completes_before_a_rotation_can_seal_its_segment(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # A threshold nothing here will cross, so the ONLY rotation is the one
        # this test performs by hand, at the moment of its choosing. What
        # triggered a rotation is not the property under test; that one can
        # land between resolving the active segment and appending to it is.
        store = ChainStore(tmp_path / "chains", notice=lambda _m: None)
        fill_over(store, tmp_path, "default", 3)
        base = store.trail_path("default")

        head = store.head("default")
        assert head is not None
        envelope = envelope_for(
            tmp_path / "scratch" / "held.jsonl", head[0] + 1, head[1], b'{"held":true}'
        )

        resolved = threading.Event()
        proceed = threading.Event()
        rotated = threading.Event()
        real = ChainStore.active_trail_path
        hooked = threading.Event()

        def hold(self: ChainStore, chain_id: str) -> Path:
            path = real(self, chain_id)
            if not hooked.is_set():
                hooked.set()
                resolved.set()
                assert proceed.wait(timeout=20)
            return path

        monkeypatch.setattr(ChainStore, "active_trail_path", hold)

        def append() -> None:
            store.append("default", envelope)

        def rotate() -> None:
            open_segmented(base, max_segment_bytes=1, notice=lambda _m: None)
            rotated.set()

        writer = threading.Thread(target=append)
        writer.start()
        assert resolved.wait(timeout=20), "the append never resolved a segment"
        rotator = threading.Thread(target=rotate)
        rotator.start()
        # A bounded wait, and the assertions do not depend on it: it only gives
        # the rotation every chance to get in FIRST. Held off by the lock it
        # times out; without the lock it returns at once.
        rotated.wait(timeout=1.0)
        proceed.set()
        writer.join(timeout=20)
        rotator.join(timeout=20)

        segments = store.segment_paths("default")
        assert [p.name for p in segments] == ["trail.jsonl", "trail.00000.jsonl"]
        sealed = stored(segments[0])
        binding = genesis_binding(segments[1])
        # The held append is IN the sealed segment and the binding names it: a
        # rotation that had slipped in first would leave the binding pointing
        # one entry short of the file's tail.
        assert sealed[-1]["entry_hash"] == envelope["entry_hash"]
        assert binding["seq"] == len(sealed) - 1
        assert binding["head_hash"] == sealed[-1]["entry_hash"]


class TestRotationUnderConcurrency:
    """Racing writers against a rotating chain: rule 7 with rotation underneath.

    FALSIFIABILITY RECEIPT — measured 01/09/2026, not argued from theory.
    The compare-and-set in `ChainStore.append`'s builder was removed (the
    `raise PreconditionFailed` replaced by `pass`, the only change):

        with the CAS    : 3/3 runs green. 48 appends land at 48 distinct
                          seqs across 5-6 segments, every segment verifying
                          ok, and every sealed segment's tail equal to the
                          seq its successor's binding names.
        without         : 3/3 runs RED, same failure every time —
                          test_racing_writers_never_fork_and_never_land_in_a_sealed_segment
                            -> "AssertionError: trail.jsonl
                                assert [0, 0, 0, 0, 0, 0, ...] == [0, 1, 2, ...]
                                At index 1 diff: 0 != 1"
                          Every writer is handed seq 0 and every one of them
                          keeps it: the chain forks in place, which is exactly
                          the failure CLAUDE.md rule 7 and REMOTE.md section 4
                          name. (The sibling receipt test stays green without
                          the CAS — with no writer ever refused, receipts and
                          accepted appends still match one for one, so it is
                          not the falsifier here.)

    Measured and recorded because it is the negative result that matters:
    replacing `segments_lock` with `contextlib.nullcontext()` leaves THIS class
    green (3/3 runs). That is not evidence the lock is unnecessary, it is
    evidence this shape of test cannot see it — the window is closed to eight
    writers for the reason
    `TestARotationCannotSealTheSegmentAnAppendIsLandingIn` states, and that
    class is where the lock is actually falsified. A receipt that claimed this
    test goes red without the lock would have been a lie.
    """

    def test_racing_writers_never_fork_and_never_land_in_a_sealed_segment(
        self, store: ChainStore, tmp_path: Path
    ) -> None:
        writers = 8
        rounds = 6
        barrier = threading.Barrier(writers)
        landed: list[str] = []
        guard = threading.Lock()
        errors: list[BaseException] = []

        def write(index: int) -> None:
            try:
                barrier.wait(timeout=30)
                for attempt in range(rounds):
                    payload = json.dumps({"writer": index, "round": attempt}).encode()
                    for _ in range(400):
                        head = store.head("default")
                        seq, prev = (
                            (0, GENESIS_PREV_HASH) if head is None else (head[0] + 1, head[1])
                        )
                        envelope = envelope_for(
                            tmp_path / "scratch" / f"w{index}.jsonl", seq, prev, payload
                        )
                        try:
                            result = store.append("default", envelope)
                        except PreconditionFailed:
                            continue
                        with guard:
                            landed.append(result.entry_hash)
                        break
                    else:  # pragma: no cover - a starved writer is a test bug
                        raise AssertionError(f"writer {index} never won a round")
            except BaseException as e:  # noqa: BLE001 - reported, not swallowed
                errors.append(e)

        threads = [threading.Thread(target=write, args=(i,)) for i in range(writers)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=120)

        assert not errors, errors
        assert len(landed) == writers * rounds
        assert len(set(landed)) == len(landed), "an entry hash was accepted twice"

        segments = store.segment_paths("default")
        assert len(segments) > 2, "no rotation raced an append; this test proves nothing"

        # 1. rule 7: no fork. Each segment is its own contiguous chain.
        total = 0
        for segment in segments:
            entries = list(JSONLBackend(segment).entries())
            total += len(entries)
            assert [e.header.seq for e in entries] == list(range(len(entries))), segment.name
            assert verify_chain(entries, VersionRegistry()).ok, segment.name

        # 2. no rotation between a CAS read and its append: a sealed segment's
        #    tail IS the tail its successor's binding named. An append that
        #    slipped in after the seal shows up here and nowhere else.
        for sealed, successor in zip(segments, segments[1:], strict=False):
            binding = genesis_binding(successor)
            entries = stored(sealed)
            assert binding["seq"] == len(entries) - 1, (
                f"{sealed.name} grew after it was sealed: bound at seq "
                f"{binding['seq']}, tail is seq {len(entries) - 1}"
            )
            assert binding["head_hash"] == entries[-1]["entry_hash"]

        # 3. nothing lost, nothing duplicated: every accepted append plus one
        #    binding per rotation.
        assert total == len(landed) + len(segments) - 1

    def test_racing_writers_issue_one_receipt_per_accepted_append(
        self, store: ChainStore, tmp_path: Path
    ) -> None:
        writers = 6
        barrier = threading.Barrier(writers)
        accepted: list[str] = []
        guard = threading.Lock()

        def write(index: int) -> None:
            barrier.wait(timeout=30)
            for _ in range(400):
                head = store.head("default")
                seq, prev = (0, GENESIS_PREV_HASH) if head is None else (head[0] + 1, head[1])
                envelope = envelope_for(
                    tmp_path / "scratch" / f"r{index}.jsonl",
                    seq,
                    prev,
                    json.dumps({"writer": index}).encode(),
                )
                try:
                    result = store.append("default", envelope)
                except PreconditionFailed:
                    continue
                with guard:
                    accepted.append(result.entry_hash)
                return

        threads = [threading.Thread(target=write, args=(i,)) for i in range(writers)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=120)

        head = store.receipt_head("default")
        assert head is not None
        assert head[0] == len(accepted) - 1
        assert store.verify_receipt_log("default").checked == len(accepted)


class TestTheDefaultNoticeGoesSomewhereAnOperatorReads:
    def test_a_rotation_is_logged_rather_than_dropped(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        # rotation.py defaults its notice to stderr because a hook's stdout is
        # read by its host. The server's default is the log, and rule 6's point
        # is that there IS a default: a degradation nobody configured a sink
        # for still has to come out somewhere.
        store = ChainStore(tmp_path / "chains", max_segment_bytes=TINY)
        with caplog.at_level(logging.WARNING, logger="waxseal_server.storage.chains"):
            fill_over(store, tmp_path, "default", 8)
        assert any("rotated" in record.getMessage() for record in caplog.records)


class TestCursorCodec:
    def test_a_cursor_that_names_no_segment_is_refused(self) -> None:
        # The pre-rotation format. Aiming it at whatever is active now would be
        # a resumed read silently continuing in a different file — refused
        # instead, so the client re-reads from the start and knows it did.
        with pytest.raises(ValueError):
            decode_cursor("e5")

    def test_a_cursor_round_trips(self) -> None:
        assert decode_cursor(encode_cursor(7, "trail.00003")) == (7, "trail.00003")


class TestTheHttpReadsFollowTheGroup:
    def test_verify_targets_the_live_segment_and_segments_sees_the_whole_group(
        self, tmp_path: Path
    ) -> None:
        # The payoff fg4.16 could not deliver: a hosted chain that has rotated
        # has sealed segments, so the Segments screen reports a group instead
        # of honestly saying `absent` forever. `verify` meanwhile has to be
        # about the segment being written — a truthful verdict on a sealed
        # segment would be a verdict about the wrong chain.
        settings = Settings(data_dir=tmp_path / "data")
        store = ChainStore(settings.chains_dir, max_segment_bytes=TINY, notice=lambda _m: None)
        fill_over(store, tmp_path, "default", 8)
        segments = [p.name for p in store.segment_paths("default")]
        assert len(segments) > 1

        client = TestClient(create_app(settings))
        verify = client.get("/v1/chains/default/verify").json()
        assert verify["exit_code"] == 0
        group = client.get("/v1/chains/default/segments").json()
        assert group["exit_code"] == 0
        for name in segments:
            assert name.removesuffix(".jsonl") in group["stdout"]
