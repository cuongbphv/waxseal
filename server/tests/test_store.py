"""The multi-chain store behind the REMOTE.md endpoints.

Everything here is the wire contract expressed at the storage layer: the CAS
precondition of REMOTE.md section 4, the byte-faithful envelope of section 3,
and the receipt chain of section 10.
"""

from __future__ import annotations

import contextlib
import copy
import json
import threading
from pathlib import Path
from typing import Any

import pytest
from conftest import build_envelopes
from waxseal_server.domain.errors import (
    DamagedReceiptLog,
    InvalidIdentifier,
    MalformedEnvelope,
    PreconditionFailed,
)
from waxseal_server.storage.chains import ChainStore

from waxseal import Verdict
from waxseal.domain.hashing import compute_entry_hash
from waxseal.domain.header import GENESIS_PREV_HASH, header_from_obj


@pytest.fixture
def store(tmp_path: Path) -> ChainStore:
    return ChainStore(tmp_path / "chains")


class TestHead:
    def test_a_chain_with_no_entries_has_no_head(self, store: ChainStore) -> None:
        # REMOTE.md section 4: 404 is "empty", not an error. None is that state.
        assert store.head("default") is None

    def test_head_reports_the_last_accepted_entry(
        self, store: ChainStore, envelopes: list[dict[str, Any]]
    ) -> None:
        for env in envelopes:
            store.append("default", env)
        last = envelopes[-1]
        assert store.head("default") == (last["header"]["seq"], last["entry_hash"])

    def test_head_survives_a_restart(self, tmp_path: Path, envelopes: list[dict[str, Any]]) -> None:
        root = tmp_path / "chains"
        ChainStore(root).append("default", envelopes[0])
        assert ChainStore(root).head("default") == (0, envelopes[0]["entry_hash"])


class TestAppendCas:
    def test_genesis_entry_is_accepted(
        self, store: ChainStore, envelopes: list[dict[str, Any]]
    ) -> None:
        result = store.append("default", envelopes[0])
        assert result.seq == 0
        assert result.entry_hash == envelopes[0]["entry_hash"]

    def test_entries_are_accepted_in_order(
        self, store: ChainStore, envelopes: list[dict[str, Any]]
    ) -> None:
        for env in envelopes:
            store.append("default", env)
        assert store.head("default") == (4, envelopes[4]["entry_hash"])

    def test_replaying_an_accepted_entry_is_a_precondition_failure(
        self, store: ChainStore, envelopes: list[dict[str, Any]]
    ) -> None:
        store.append("default", envelopes[0])
        with pytest.raises(PreconditionFailed):
            store.append("default", envelopes[0])

    def test_a_gap_in_seq_is_a_precondition_failure(
        self, store: ChainStore, envelopes: list[dict[str, Any]]
    ) -> None:
        with pytest.raises(PreconditionFailed):
            store.append("default", envelopes[1])

    def test_a_wrong_prev_hash_is_a_precondition_failure(
        self, store: ChainStore, envelopes: list[dict[str, Any]]
    ) -> None:
        store.append("default", envelopes[0])
        forked = copy.deepcopy(envelopes[1])
        forked["header"]["prev_hash"] = "ff" * 32
        with pytest.raises(PreconditionFailed):
            store.append("default", forked)

    def test_a_rejected_append_leaves_the_head_untouched(
        self, store: ChainStore, envelopes: list[dict[str, Any]]
    ) -> None:
        store.append("default", envelopes[0])
        with pytest.raises(PreconditionFailed):
            store.append("default", envelopes[2])
        assert store.head("default") == (0, envelopes[0]["entry_hash"])


class TestByteFaithfulStorage:
    def test_a_stored_envelope_comes_back_verbatim(
        self, store: ChainStore, envelopes: list[dict[str, Any]]
    ) -> None:
        store.append("default", envelopes[0])
        page, _ = store.page("default", cursor=None, limit=10)
        assert page == [envelopes[0]]

    def test_entry_hash_is_stored_as_posted_and_never_recomputed(
        self, store: ChainStore, envelopes: list[dict[str, Any]]
    ) -> None:
        # REMOTE.md section 3: the server MUST NOT "correct" entry_hash. A
        # server that silently repaired it would launder a broken chain into a
        # verifying one and destroy the client's only tamper signal.
        lying = copy.deepcopy(envelopes[0])
        lying["entry_hash"] = "ab" * 32
        store.append("default", lying)
        page, _ = store.page("default", cursor=None, limit=10)
        assert page[0]["entry_hash"] == "ab" * 32

    def test_entries_come_back_in_append_order(
        self, store: ChainStore, envelopes: list[dict[str, Any]]
    ) -> None:
        for env in envelopes:
            store.append("default", env)
        page, _ = store.page("default", cursor=None, limit=100)
        assert [e["header"]["seq"] for e in page] == [0, 1, 2, 3, 4]


class TestPagination:
    def test_a_full_listing_ends_with_a_null_cursor(
        self, store: ChainStore, envelopes: list[dict[str, Any]]
    ) -> None:
        store.append("default", envelopes[0])
        _, cursor = store.page("default", cursor=None, limit=10)
        assert cursor is None

    def test_a_partial_page_hands_back_a_cursor(
        self, store: ChainStore, envelopes: list[dict[str, Any]]
    ) -> None:
        for env in envelopes:
            store.append("default", env)
        page, cursor = store.page("default", cursor=None, limit=2)
        assert [e["header"]["seq"] for e in page] == [0, 1]
        assert cursor is not None

    def test_following_cursors_walks_every_entry_exactly_once(
        self, store: ChainStore, envelopes: list[dict[str, Any]]
    ) -> None:
        for env in envelopes:
            store.append("default", env)
        seen: list[int] = []
        cursor: str | None = None
        while True:
            page, cursor = store.page("default", cursor=cursor, limit=2)
            seen.extend(e["header"]["seq"] for e in page)
            if cursor is None:
                break
        assert seen == [0, 1, 2, 3, 4]

    def test_an_empty_chain_pages_to_nothing(self, store: ChainStore) -> None:
        assert store.page("default", cursor=None, limit=10) == ([], None)

    def test_an_unparsable_cursor_is_rejected(
        self, store: ChainStore, envelopes: list[dict[str, Any]]
    ) -> None:
        store.append("default", envelopes[0])
        with pytest.raises(ValueError):
            store.page("default", cursor="not-a-cursor", limit=10)


class TestChainIsolation:
    def test_two_chain_ids_are_independent_sequences(
        self, tmp_path: Path, store: ChainStore
    ) -> None:
        left = build_envelopes(tmp_path / "l", 2)
        right = build_envelopes(tmp_path / "r", 2)
        for env in left:
            store.append("alpha", env)
        store.append("beta", right[0])
        assert store.head("alpha") == (1, left[1]["entry_hash"])
        assert store.head("beta") == (0, right[0]["entry_hash"])

    def test_chain_ids_lists_only_chains_that_exist(
        self, store: ChainStore, envelopes: list[dict[str, Any]]
    ) -> None:
        assert store.chain_ids() == []
        store.append("beta", envelopes[0])
        assert store.chain_ids() == ["beta"]

    @pytest.mark.parametrize(
        "bad", ["..", "../escape", "a/b", "a\\b", "", "with space", "x" * 200, "."]
    )
    def test_a_chain_id_that_could_escape_the_root_is_rejected(
        self, store: ChainStore, bad: str
    ) -> None:
        with pytest.raises(InvalidIdentifier):
            store.head(bad)

    def test_a_plain_chain_id_is_accepted(self, store: ChainStore) -> None:
        assert store.head("my-project_01") is None


class TestMalformedEnvelope:
    @pytest.mark.parametrize(
        "mutate",
        [
            pytest.param(lambda e: e.pop("entry_hash"), id="missing-entry_hash"),
            pytest.param(lambda e: e.pop("payload_b64"), id="missing-payload_b64"),
            pytest.param(lambda e: e.pop("header"), id="missing-header"),
            pytest.param(lambda e: e["header"].pop("seq"), id="missing-seq"),
            pytest.param(lambda e: e["header"].pop("prev_hash"), id="missing-prev_hash"),
            pytest.param(lambda e: e.update(entry_hash="zz" * 32), id="non-hex-entry_hash"),
            pytest.param(lambda e: e.update(entry_hash="aa"), id="short-entry_hash"),
            pytest.param(lambda e: e["header"].update(seq="0"), id="seq-not-an-int"),
            pytest.param(lambda e: e["header"].update(seq=-1), id="seq-negative"),
            pytest.param(lambda e: e["header"].update(payload_hash=None), id="payload_hash-null"),
            pytest.param(lambda e: e["header"].update(hash_version="nope"), id="bad-hash_version"),
            pytest.param(lambda e: e["header"].update(payload_type=7), id="payload_type-not-str"),
            pytest.param(lambda e: e["header"].update(ts=7), id="ts-not-str"),
            pytest.param(lambda e: e.update(payload_b64="!!!not base64!!!"), id="bad-base64"),
            pytest.param(lambda e: e.update(header=[]), id="header-not-an-object"),
        ],
    )
    def test_a_malformed_envelope_is_rejected_before_anything_is_stored(
        self, store: ChainStore, envelopes: list[dict[str, Any]], mutate: Any
    ) -> None:
        broken = copy.deepcopy(envelopes[0])
        mutate(broken)
        with pytest.raises(MalformedEnvelope):
            store.append("default", broken)
        assert store.head("default") is None

    def test_genesis_prev_hash_of_all_zeros_is_valid(
        self, store: ChainStore, envelopes: list[dict[str, Any]]
    ) -> None:
        assert envelopes[0]["header"]["prev_hash"] == GENESIS_PREV_HASH
        store.append("default", envelopes[0])

    def test_an_envelope_that_is_not_an_object_is_rejected(self, store: ChainStore) -> None:
        with pytest.raises(MalformedEnvelope):
            store.append("default", ["not", "an", "object"])  # type: ignore[arg-type]


class TestReceiptChain:
    def test_append_returns_a_receipt(
        self, store: ChainStore, envelopes: list[dict[str, Any]]
    ) -> None:
        result = store.append("default", envelopes[0])
        assert result.receipt_seq == 0
        assert len(result.receipt_head) == 64

    def test_receipt_seq_advances_with_each_acknowledgement(
        self, store: ChainStore, envelopes: list[dict[str, Any]]
    ) -> None:
        store.append("default", envelopes[0])
        assert store.append("default", envelopes[1]).receipt_seq == 1

    def test_a_rejected_append_issues_no_receipt(
        self, store: ChainStore, envelopes: list[dict[str, Any]]
    ) -> None:
        store.append("default", envelopes[0])
        with pytest.raises(PreconditionFailed):
            store.append("default", envelopes[0])
        assert store.receipt_head("default") == (0, store.receipt_head("default")[1])  # type: ignore[index]
        assert store.receipt_head("default")[0] == 0  # type: ignore[index]

    def test_receipt_head_is_none_before_any_acknowledgement(self, store: ChainStore) -> None:
        assert store.receipt_head("default") is None

    def test_the_receipt_head_survives_a_restart(
        self, tmp_path: Path, envelopes: list[dict[str, Any]]
    ) -> None:
        # REMOTE.md section 10: once issued, a (receipt_seq, receipt_head) pair
        # must never be answered differently. A restart is where a server that
        # keeps the chain only in memory breaks that promise.
        root = tmp_path / "chains"
        live = ChainStore(root)
        live.append("default", envelopes[0])
        live.append("default", envelopes[1])
        before = live.receipt_head("default")
        assert ChainStore(root).receipt_head("default") == before

    def test_a_restarted_store_continues_the_same_chain(
        self, tmp_path: Path, envelopes: list[dict[str, Any]]
    ) -> None:
        root = tmp_path / "chains"
        ChainStore(root).append("default", envelopes[0])
        restarted = ChainStore(root)
        assert restarted.append("default", envelopes[1]).receipt_seq == 1

    def test_receipt_chains_are_per_chain_id(self, tmp_path: Path, store: ChainStore) -> None:
        store.append("alpha", build_envelopes(tmp_path / "l", 1)[0])
        assert store.receipt_head("beta") is None

    def test_receipts_are_recorded_durably_one_line_each(
        self, tmp_path: Path, envelopes: list[dict[str, Any]]
    ) -> None:
        root = tmp_path / "chains"
        store = ChainStore(root)
        store.append("default", envelopes[0])
        store.append("default", envelopes[1])
        lines = [
            json.loads(line)
            for line in store.receipt_log_path("default").read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        assert [r["receipt_seq"] for r in lines] == [0, 1]
        assert [r["entry_hash"] for r in lines] == [e["entry_hash"] for e in envelopes[:2]]


class TestConcurrentWriters:
    def test_racing_writers_never_both_extend_the_same_prev_hash(
        self, tmp_path: Path, store: ChainStore
    ) -> None:
        # CLAUDE.md rule 7, server side (REMOTE.md section 4): two POSTs racing
        # for one seq MUST NOT both succeed. Falsifiability receipt: drop the
        # CAS check inside ChainStore.append's builder and this goes red — both
        # writers are handed seq 0 and the chain forks.
        candidates = [build_envelopes(tmp_path / f"w{i}", 1)[0] for i in range(8)]
        accepted: list[int] = []
        rejected: list[int] = []
        barrier = threading.Barrier(len(candidates))
        lock = threading.Lock()

        def race(index: int) -> None:
            barrier.wait()
            try:
                store.append("default", candidates[index])
            except PreconditionFailed:
                with lock:
                    rejected.append(index)
            else:
                with lock:
                    accepted.append(index)

        threads = [threading.Thread(target=race, args=(i,)) for i in range(len(candidates))]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(accepted) == 1
        assert len(rejected) == len(candidates) - 1
        page, _ = store.page("default", cursor=None, limit=100)
        assert len(page) == 1

    def test_racing_writers_issue_exactly_one_receipt(
        self, tmp_path: Path, store: ChainStore
    ) -> None:
        candidates = [build_envelopes(tmp_path / f"w{i}", 1)[0] for i in range(6)]
        barrier = threading.Barrier(len(candidates))

        def race(index: int) -> None:
            barrier.wait()
            with contextlib.suppress(PreconditionFailed):
                store.append("default", candidates[index])

        threads = [threading.Thread(target=race, args=(i,)) for i in range(len(candidates))]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert store.receipt_head("default")[0] == 0  # type: ignore[index]


class TestVerifyReceiptLog:
    """The server's own acknowledgment history, checkable by anyone.

    A receipt chain that only the server can evaluate is a promise, not
    evidence. This is the check a third party runs over the mirror-style read
    endpoint, and its three outcomes are SPEC.md section 19's own table.
    """

    def _records(self, store: ChainStore, chain_id: str) -> list[dict[str, Any]]:
        return [
            json.loads(line)
            for line in store.receipt_log_path(chain_id).read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    def _rewrite(self, store: ChainStore, chain_id: str, records: list[dict[str, Any]]) -> None:
        store.receipt_log_path(chain_id).write_text(
            "".join(json.dumps(r, sort_keys=True, separators=(",", ":")) + "\n" for r in records),
            encoding="utf-8",
        )

    def test_an_absent_log_is_not_recorded_never_zero_checked(self, store: ChainStore) -> None:
        # CLAUDE.md rule 5: "no log" is not "a log with nothing wrong in it".
        report = store.verify_receipt_log("default")
        assert report.verdict is Verdict.OK
        assert report.checked is None
        assert report.reason == "not_recorded"

    def test_an_untouched_log_verifies(
        self, store: ChainStore, envelopes: list[dict[str, Any]]
    ) -> None:
        for env in envelopes:
            store.append("default", env)
        report = store.verify_receipt_log("default")
        assert report.verdict is Verdict.OK
        assert report.checked == 5
        assert report.reason is None

    def test_an_edited_receipt_head_is_broken_at_that_receipt_seq(
        self, store: ChainStore, envelopes: list[dict[str, Any]]
    ) -> None:
        for env in envelopes[:3]:
            store.append("default", env)
        records = self._records(store, "default")
        records[1]["receipt_head"] = "ab" * 32
        self._rewrite(store, "default", records)

        report = store.verify_receipt_log("default")
        assert report.verdict is Verdict.BROKEN
        assert report.reason == "receipt_head_mismatch"
        assert report.broken_receipt_seq == 1

    def test_an_edited_entry_hash_is_broken(
        self, store: ChainStore, envelopes: list[dict[str, Any]]
    ) -> None:
        for env in envelopes[:2]:
            store.append("default", env)
        records = self._records(store, "default")
        records[0]["entry_hash"] = "cd" * 32
        self._rewrite(store, "default", records)
        assert store.verify_receipt_log("default").verdict is Verdict.BROKEN

    def test_a_removed_receipt_is_a_seq_gap(
        self, store: ChainStore, envelopes: list[dict[str, Any]]
    ) -> None:
        for env in envelopes[:3]:
            store.append("default", env)
        records = self._records(store, "default")
        self._rewrite(store, "default", [records[0], records[2]])

        report = store.verify_receipt_log("default")
        assert report.verdict is Verdict.BROKEN
        assert report.reason == "receipt_seq_gap"
        assert report.broken_receipt_seq == 2

    def test_a_record_from_a_newer_build_is_unverifiable_never_broken(
        self, store: ChainStore, envelopes: list[dict[str, Any]]
    ) -> None:
        # SPEC.md section 19: a `v` this build does not know is unverifiable by
        # name (exit 2). Calling it tampered would be the one lie a
        # tamper-evidence mechanism must never tell.
        store.append("default", envelopes[0])
        records = self._records(store, "default")
        records[0]["v"] = 99
        self._rewrite(store, "default", records)

        report = store.verify_receipt_log("default")
        assert report.verdict is Verdict.UNVERIFIABLE
        assert report.reason == "unreadable_record_version"

    def test_a_corrupt_record_in_a_known_version_is_broken(
        self, store: ChainStore, envelopes: list[dict[str, Any]]
    ) -> None:
        # SPEC.md section 17's asymmetry: broken bytes inside this project's
        # OWN format are a break, not an unknown.
        store.append("default", envelopes[0])
        store.receipt_log_path("default").write_text(
            '{"v": 1, "receipt_seq": "not-an-int"}\n', encoding="utf-8"
        )

        report = store.verify_receipt_log("default")
        assert report.verdict is Verdict.BROKEN
        assert report.reason == "malformed_receipt_record"

    def test_an_unparsable_line_is_broken(
        self, store: ChainStore, envelopes: list[dict[str, Any]]
    ) -> None:
        store.append("default", envelopes[0])
        store.receipt_log_path("default").write_text("{not json\n", encoding="utf-8")
        assert store.verify_receipt_log("default").reason == "malformed_receipt_record"

    def test_the_verdict_maps_to_the_documented_exit_codes(
        self, store: ChainStore, envelopes: list[dict[str, Any]]
    ) -> None:
        store.append("default", envelopes[0])
        assert store.verify_receipt_log("default").verdict.to_exit_code() == 0


class TestBlankLinesAreNotEntries:
    """A trailing newline is not a record.

    `read_last_line` already trims blank tails; the readers here have to agree
    with it, or a file the writer considers finished reads as one entry longer.
    """

    def test_a_blank_line_in_the_trail_is_skipped(
        self, store: ChainStore, envelopes: list[dict[str, Any]]
    ) -> None:
        store.append("default", envelopes[0])
        with open(store.trail_path("default"), "a", encoding="utf-8") as f:
            f.write("\n")
        page, cursor = store.page("default", cursor=None, limit=10)
        assert len(page) == 1
        assert cursor is None

    def test_a_blank_line_in_the_receipt_log_is_skipped(
        self, store: ChainStore, envelopes: list[dict[str, Any]]
    ) -> None:
        store.append("default", envelopes[0])
        with open(store.receipt_log_path("default"), "a", encoding="utf-8") as f:
            f.write("\n")
        assert store.verify_receipt_log("default").checked == 1


class TestCrossCheckReceipts:
    """The server holds both halves, so it can compare them.

    `verify_receipt_log` asks whether the acknowledgment log is internally
    consistent. That question stays "ok" after an edit to the TRAIL, because the
    log itself was not touched — which is correct, and useless on its own. This
    is the other half: does what the server acknowledged still match what the
    server is storing? The reason vocabulary is SPEC.md section 19's, and the
    comparison is deterministic, so its failures are breaks and never
    unverifiable.
    """

    def test_an_untouched_pair_agrees(
        self, store: ChainStore, envelopes: list[dict[str, Any]]
    ) -> None:
        for env in envelopes:
            store.append("default", env)
        report = store.cross_check_receipts("default")
        assert report.verdict is Verdict.OK
        assert report.checked == 5

    def test_a_self_consistent_rewrite_contradicts_its_receipt(
        self, store: ChainStore, envelopes: list[dict[str, Any]]
    ) -> None:
        # The case the receipt chain exists for. Editing a field and leaving
        # entry_hash stale is caught by `verify` alone (entry_hash_mismatch);
        # what `verify` alone cannot catch is an edit that RECOMPUTES the hash,
        # because the rewritten row is then internally consistent. The receipt
        # is the memory the rewriter does not hold.
        for env in envelopes[:3]:
            store.append("default", env)
        trail = store.trail_path("default")
        lines = trail.read_text(encoding="utf-8").splitlines()
        record = json.loads(lines[1])
        record["header"]["ts"] = "2000-01-01T00:00:00+00:00"
        record["entry_hash"] = compute_entry_hash(header_from_obj(record["header"]))
        lines[1] = json.dumps(record, sort_keys=True, separators=(",", ":"))
        trail.write_text("\n".join(lines) + "\n", encoding="utf-8")

        report = store.cross_check_receipts("default")
        assert report.verdict is Verdict.BROKEN
        assert report.reason == "receipt_mismatch"
        assert report.broken_seq == 1

    def test_a_truncated_trail_is_a_rollback(
        self, store: ChainStore, envelopes: list[dict[str, Any]]
    ) -> None:
        for env in envelopes[:3]:
            store.append("default", env)
        trail = store.trail_path("default")
        lines = trail.read_text(encoding="utf-8").splitlines()
        trail.write_text("\n".join(lines[:2]) + "\n", encoding="utf-8")

        report = store.cross_check_receipts("default")
        assert report.verdict is Verdict.BROKEN
        assert report.reason == "receipt_beyond_head"
        assert report.broken_seq == 2

    def test_no_receipt_log_is_not_recorded_never_zero(self, store: ChainStore) -> None:
        report = store.cross_check_receipts("default")
        assert report.verdict is Verdict.OK
        assert report.checked is None
        assert report.reason == "not_recorded"

    def test_a_record_from_a_newer_build_is_unverifiable(
        self, store: ChainStore, envelopes: list[dict[str, Any]]
    ) -> None:
        store.append("default", envelopes[0])
        log = store.receipt_log_path("default")
        record = json.loads(log.read_text(encoding="utf-8").splitlines()[0])
        record["v"] = 99
        log.write_text(
            json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8"
        )

        report = store.cross_check_receipts("default")
        assert report.verdict is Verdict.UNVERIFIABLE
        assert report.reason == "unreadable_record_version"

    def test_a_corrupt_record_is_broken(
        self, store: ChainStore, envelopes: list[dict[str, Any]]
    ) -> None:
        store.append("default", envelopes[0])
        store.receipt_log_path("default").write_text(
            '{"v": 1, "seq": "not-an-int"}\n', encoding="utf-8"
        )
        assert store.cross_check_receipts("default").reason == "malformed_receipt_record"

    def test_a_blank_line_is_skipped(
        self, store: ChainStore, envelopes: list[dict[str, Any]]
    ) -> None:
        store.append("default", envelopes[0])
        with open(store.receipt_log_path("default"), "a", encoding="utf-8") as f:
            f.write("\n")
        assert store.cross_check_receipts("default").checked == 1


class TestCrossCheckSurvivesADamagedLog:
    """A damaged receipt log is a finding, never a crash.

    Every one of these reaches an HTTP handler, so an unguarded parse here is a
    500 where a labelled verdict belongs — and a 500 tells an auditor nothing
    about their trail.
    """

    def test_an_unparsable_line_is_a_break(
        self, store: ChainStore, envelopes: list[dict[str, Any]]
    ) -> None:
        store.append("default", envelopes[0])
        store.receipt_log_path("default").write_text("{not json at all\n", encoding="utf-8")
        report = store.cross_check_receipts("default")
        assert report.verdict is Verdict.BROKEN
        assert report.reason == "malformed_receipt_record"

    def test_a_record_with_no_version_is_a_break(
        self, store: ChainStore, envelopes: list[dict[str, Any]]
    ) -> None:
        store.append("default", envelopes[0])
        store.receipt_log_path("default").write_text('{"seq": 0}\n', encoding="utf-8")
        assert store.cross_check_receipts("default").reason == "malformed_receipt_record"

    def test_a_line_that_is_not_an_object_is_a_break(
        self, store: ChainStore, envelopes: list[dict[str, Any]]
    ) -> None:
        store.append("default", envelopes[0])
        store.receipt_log_path("default").write_text("[1, 2, 3]\n", encoding="utf-8")
        assert store.cross_check_receipts("default").reason == "malformed_receipt_record"

    def test_receipts_without_a_trail_are_a_rollback_not_a_crash(
        self, store: ChainStore, envelopes: list[dict[str, Any]]
    ) -> None:
        # The whole trail deleted, the acknowledgments left behind. Every
        # receipt now names an entry that is not there.
        store.append("default", envelopes[0])
        store.trail_path("default").unlink()
        report = store.cross_check_receipts("default")
        assert report.verdict is Verdict.BROKEN
        assert report.reason == "receipt_beyond_head"

    def test_records_distinguishes_damaged_from_absent(
        self, store: ChainStore, envelopes: list[dict[str, Any]]
    ) -> None:
        # None already means "no log". A damaged log must not borrow that
        # answer: "there is nothing to read" and "I could not read it" send an
        # operator to different places.
        store.append("default", envelopes[0])
        store.receipt_log_path("default").write_text("{not json\n", encoding="utf-8")
        with pytest.raises(DamagedReceiptLog):
            store.receipt_records("default")


class TestSummary:
    """One read for the dashboard row, instead of three round trips per chain.

    The dashboard draws a row per chain; asking for head, count and size
    separately turns a six-chain page into eighteen requests, each of which
    re-walks the trail.
    """

    def test_an_empty_chain_summarizes_as_empty(self, store: ChainStore) -> None:
        summary = store.summary("default")
        assert summary.entries == 0
        assert summary.size_bytes == 0
        assert summary.head is None
        assert summary.receipt is None

    def test_it_counts_entries_and_measures_bytes(
        self, store: ChainStore, envelopes: list[dict[str, Any]]
    ) -> None:
        for env in envelopes:
            store.append("default", env)
        summary = store.summary("default")
        assert summary.entries == 5
        assert summary.size_bytes == store.trail_path("default").stat().st_size

    def test_it_carries_the_head_and_the_receipt(
        self, store: ChainStore, envelopes: list[dict[str, Any]]
    ) -> None:
        for env in envelopes[:2]:
            store.append("default", env)
        summary = store.summary("default")
        assert summary.head == (1, envelopes[1]["entry_hash"])
        assert summary.receipt is not None
        assert summary.receipt[0] == 1

    def test_a_damaged_receipt_log_does_not_sink_the_summary(
        self, store: ChainStore, envelopes: list[dict[str, Any]]
    ) -> None:
        # A dashboard row must still render the chain it can read. A broken
        # sidecar is a finding about the sidecar, not a reason to blank the row.
        store.append("default", envelopes[0])
        store.receipt_log_path("default").write_text("{not json\n", encoding="utf-8")
        summary = store.summary("default")
        assert summary.entries == 1
        assert summary.receipt is None

    def test_a_blank_line_is_not_an_entry(
        self, store: ChainStore, envelopes: list[dict[str, Any]]
    ) -> None:
        store.append("default", envelopes[0])
        with open(store.trail_path("default"), "a", encoding="utf-8") as f:
            f.write("\n")
        assert store.summary("default").entries == 1

    def test_an_invalid_chain_id_is_refused(self, store: ChainStore) -> None:
        with pytest.raises(InvalidIdentifier):
            store.summary("../escape")
