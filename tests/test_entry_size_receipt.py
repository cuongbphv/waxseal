"""What a stored entry actually costs in bytes, and the fixture that produced
each number (waxseal-fg4.23).

Three per-entry figures used to coexist in this tree -- 1.9 KB in
`sources/rotation.py`, 462 B in `tests/test_sources_rotation.py`, 462 B again
in commit 18dfe11's message -- and none of them named the workload it
described, so a reader could not tell which one applied to them. 18dfe11 went
further and cited the 462 B / 624 B pair (1.35x apart) as the evidence for a
"~100x" spread, which it cannot be.

Nothing here measures wall-clock time; every assertion counts bytes actually
written to disk (CLAUDE.md: tests never sleep to pass), in the style of
`tests/adapters/test_perf_receipts.py`. Timestamps are injected so a line
length is a property of the fixture and not of the clock (rule 8): a real
`datetime.now(UTC).isoformat()` drops the microseconds field entirely on the
roughly one-in-a-million tick where it is zero, which would move every count
below by 7 bytes.

The exact byte counts are asserted, not bounded, because they are quoted in
prose: `sources/rotation.py`'s module docstring and its
`DEFAULT_MAX_SEGMENT_BYTES` comment both cite these numbers, and a receipt
that tolerated drift would let that prose go stale the same way 1.9 KB did.
A failure here means the prose needs re-deriving, never that the number needs
loosening.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

from waxseal import AuditLog
from waxseal.adapters.redactors import RegexRedactor
from waxseal.domain.segments import ROTATION_PAYLOAD_TYPE, segment_chain_id
from waxseal.integrations import claude_code
from waxseal.sources.rotation import DEFAULT_MAX_SEGMENT_BYTES, open_segmented

# ---------------------------------------------------------------------------
# The fixtures. Every string below is part of the measurement: a longer `cwd`
# or a longer `session_id` moves the counts, which is precisely why the old
# figures had to state one and did not.
# ---------------------------------------------------------------------------

#: One fixed instant, in the shape `datetime.now(UTC).isoformat()` produces
#: when the microseconds field is non-zero (32 characters).
FIXED_TS = "2026-09-01T00:00:00.000001+00:00"

#: A Claude Code session id: the 36-character canonical UUID form the hook
#: receives.
SESSION_ID = "b3f1c0de-1234-4a56-89ab-cdef01234567"

#: The project directory the hook event reports. 27 characters.
CWD = "/Users/dev/Projects/waxseal"

#: FIXTURE "minimal prompt event" -- the floor. A `UserPromptSubmit` hook
#: event carrying only the fields Claude Code always sends for it, with a
#: 13-character prompt. This is the short end of the comparison SPEC section
#: 20.2 and `sources/rotation.py` both make.
MINIMAL_PROMPT_EVENT: dict[str, Any] = {
    "hook_event_name": "UserPromptSubmit",
    "session_id": SESSION_ID,
    "cwd": CWD,
    "prompt": "run the tests",
}

#: 400 lines of pytest progress output: 26_290 characters, six times past
#: `MAX_FIELD_CHARS`, so the stored field is the clip and not the dump.
TERMINAL_DUMP = "".join(
    f"{i:5d}  ok  tests/integrations/test_thing.py::test_case_{i} passed\n"
    for i in range(400)
)

#: FIXTURE "clipped tool result" -- the ceiling. A `PostToolUse` hook event
#: for a `Bash` call whose `tool_output` is the terminal dump above, clipped
#: at `MAX_FIELD_CHARS`. This is the long end of the same comparison: the
#: clip, not the dump, is what bounds it, so no larger single-field event
#: exists.
CLIPPED_TOOL_RESULT_EVENT: dict[str, Any] = {
    "hook_event_name": "PostToolUse",
    "session_id": SESSION_ID,
    "cwd": CWD,
    "tool_use_id": "toolu_01ABCdefGHIjklMNOpqrST",
    "tool_name": "Bash",
    "tool_input": {"command": "uv run --extra dev pytest"},
    "tool_output": TERMINAL_DUMP,
}

#: FIXTURE "synthetic test event" -- the payload `tests/test_sources_rotation.py`
#: appends, under a 31-character payload type. Not a hook workload at all,
#: which is the whole reason its 462 B never belonged in the same sentence as
#: a hook entry's size.
SYNTHETIC_TEST_PAYLOAD: dict[str, Any] = {"i": 0}
SYNTHETIC_TEST_PAYLOAD_TYPE = "application/vnd.test.event+json"

# ---------------------------------------------------------------------------
# The measured numbers. Quoted in sources/rotation.py; change one place and
# this file fails.
# ---------------------------------------------------------------------------

MINIMAL_PROMPT_BYTES = 650
CLIPPED_TOOL_RESULT_BYTES = 6_374
SYNTHETIC_TEST_EVENT_BYTES = 462
ROTATION_BINDING_BYTES = 624

#: The directory name that produces `ROTATION_BINDING_BYTES`. A binding's
#: `chain_id` is `<directory name>/<segment identity>`, so the binding line
#: grows with the directory it sits in -- the 624 B figure was never a
#: constant, and nothing said so. 11 characters here; base64 quantizes at
#: three payload bytes, so 9 to 11 all land on 624 and 12 lands on 628.
BINDING_DIR_NAME = "waxseal-fg4"


def _stored_line_bytes(
    tmp_path: Path, payload: dict[str, Any], payload_type: str
) -> int:
    """Bytes appended to a fresh JSONL trail by one real `AuditLog.append`.

    The whole append path, not a hand-built envelope: redactor, canonical
    encoding, base64 payload and trailing newline all count, because all of
    them are on disk.
    """
    path = tmp_path / "trail.jsonl"
    log = AuditLog.open(path, redactor=RegexRedactor(), now_fn=lambda: FIXED_TS)
    log.append(payload=payload, payload_type=payload_type)
    return path.stat().st_size


class TestStoredEntrySizeAtBothExtremes:
    def test_minimal_prompt_event_is_the_floor(self, tmp_path: Path) -> None:
        size = _stored_line_bytes(
            tmp_path,
            claude_code.build_payload(MINIMAL_PROMPT_EVENT),
            claude_code.PAYLOAD_TYPE,
        )
        assert size == MINIMAL_PROMPT_BYTES, (
            f"the minimal prompt event now stores {size} B, not "
            f"{MINIMAL_PROMPT_BYTES} B — sources/rotation.py quotes this number "
            "twice and both citations need re-deriving"
        )

    def test_clipped_tool_result_is_the_ceiling(self, tmp_path: Path) -> None:
        payload = claude_code.build_payload(CLIPPED_TOOL_RESULT_EVENT)
        # The clip, not the dump, is what this measures. If MAX_FIELD_CHARS
        # ever stopped applying, the ceiling would be unbounded and the
        # comparison below would be meaningless rather than merely wrong.
        assert len(TERMINAL_DUMP) > claude_code.MAX_FIELD_CHARS
        assert payload["tool_output"].startswith(
            TERMINAL_DUMP[: claude_code.MAX_FIELD_CHARS]
        )
        assert "truncated" in payload["tool_output"]

        size = _stored_line_bytes(tmp_path, payload, claude_code.PAYLOAD_TYPE)
        assert size == CLIPPED_TOOL_RESULT_BYTES, (
            f"the clipped tool result now stores {size} B, not "
            f"{CLIPPED_TOOL_RESULT_BYTES} B — sources/rotation.py quotes this "
            "number twice and both citations need re-deriving"
        )

    def test_the_spread_is_one_order_of_magnitude_not_two(self) -> None:
        """The receipt the "~100x" claim never had.

        SPEC section 20.2 and `sources/rotation.py` both said stored entry
        sizes differ by roughly 100x, naming a prompt line against a clipped
        terminal dump. Measured through the real append path, that pair is
        ~10x apart. What by-count triggering was rejected for still holds — a
        count still says almost nothing about bytes at 10x — but the number
        attached to it was off by an order of magnitude.
        """
        spread = CLIPPED_TOOL_RESULT_BYTES / MINIMAL_PROMPT_BYTES
        assert 9.0 < spread < 11.0, (
            f"measured spread is {spread:.1f}x — a '~100x' figure would need "
            "an entry near 65 KB, which MAX_FIELD_CHARS forbids for any single "
            "field"
        )

    def test_the_envelope_floor_is_what_caps_the_spread(self, tmp_path: Path) -> None:
        """Why 100x is not reachable by picking a better fixture.

        Every entry pays a fixed envelope — two 64-char hashes, the
        fingerprint, the timestamp, the payload type — before a single byte of
        payload. That floor is most of a minimal entry, so the ratio between
        two entries is always far smaller than the ratio between their
        payloads.
        """
        empty = _stored_line_bytes(tmp_path, {}, claude_code.PAYLOAD_TYPE)
        assert empty > MINIMAL_PROMPT_BYTES / 2
        payload_spread = len(
            json.dumps(claude_code.build_payload(CLIPPED_TOOL_RESULT_EVENT))
        ) / len(json.dumps(claude_code.build_payload(MINIMAL_PROMPT_EVENT)))
        assert payload_spread > CLIPPED_TOOL_RESULT_BYTES / MINIMAL_PROMPT_BYTES


class TestSegmentCapacityIsARange:
    """`DEFAULT_MAX_SEGMENT_BYTES` in entries is a range, not a number.

    The comment on that constant used to read "at the measured 1.9 KB per
    stored hook entry this is roughly 8.8k entries per segment". 1.9 KB named
    no fixture, and no fixture in this tree produces it. What 16 MiB holds
    depends entirely on the workload, so the comment now cites both ends and
    this pins them.
    """

    def test_capacity_at_the_floor(self) -> None:
        assert DEFAULT_MAX_SEGMENT_BYTES // MINIMAL_PROMPT_BYTES == 25_811

    def test_capacity_at_the_ceiling(self) -> None:
        assert DEFAULT_MAX_SEGMENT_BYTES // CLIPPED_TOOL_RESULT_BYTES == 2_632

    def test_the_old_8800_figure_sits_inside_the_range_but_names_no_fixture(
        self,
    ) -> None:
        # Not wrong so much as unattributable: 8.8k entries implies a ~1.9 KB
        # average, which lands between the two measured ends without any
        # measured workload behind it. Recorded so the range is understood as
        # replacing a point estimate, not contradicting a measurement.
        implied_avg = DEFAULT_MAX_SEGMENT_BYTES / 8_800
        assert MINIMAL_PROMPT_BYTES < implied_avg < CLIPPED_TOOL_RESULT_BYTES


class TestTheOlderCitedFigures:
    def test_the_synthetic_test_event_line_is_462_bytes(self, tmp_path: Path) -> None:
        """462 B is real — for `{"i": 0}` under a test payload type.

        It is the number `tests/test_sources_rotation.py` sizes its threshold
        against, and it is NOT a hook entry: the smallest real hook event is
        650 B. Citing it as "a stored entry" is how it ended up in a commit
        message arguing about hook trail growth.
        """
        size = _stored_line_bytes(
            tmp_path, SYNTHETIC_TEST_PAYLOAD, SYNTHETIC_TEST_PAYLOAD_TYPE
        )
        assert size == SYNTHETIC_TEST_EVENT_BYTES

    def test_the_rotation_binding_line_depends_on_the_directory_name(
        self, tmp_path: Path
    ) -> None:
        """624 B is real too, and it is not a constant.

        `chain_id` is `<directory name>/<segment identity>`, so the binding
        line carries the directory's name verbatim. The cited 624 B holds
        for a directory name of 9 to 11 characters and for nothing else --
        which is how a number measured under one `tmp_path` came to be
        written down as if it were a property of the format.
        """
        directory = tmp_path / BINDING_DIR_NAME
        directory.mkdir()
        base = directory / "trail.jsonl"

        log = AuditLog.open(base, now_fn=lambda: FIXED_TS)
        while not base.exists() or base.stat().st_size <= 5_000:
            log.append(payload={"i": 0}, payload_type=SYNTHETIC_TEST_PAYLOAD_TYPE)

        before = base.stat().st_size
        open_segmented(
            base,
            max_segment_bytes=5_000,
            notice=lambda _message: None,
            now_fn=lambda: FIXED_TS,
        )
        rotated = directory / "trail.00000.jsonl"
        assert base.stat().st_size == before  # sealed, never rewritten (rule 4)
        assert rotated.stat().st_size == ROTATION_BINDING_BYTES

        record = json.loads(rotated.read_text().splitlines()[0])
        assert record["header"]["payload_type"] == ROTATION_PAYLOAD_TYPE
        # The directory name is IN the line, which is the point.
        binding = json.loads(base64.b64decode(record["payload_b64"]))
        assert binding["chain_id"] == segment_chain_id(BINDING_DIR_NAME, "trail")

        longer = tmp_path / (BINDING_DIR_NAME + "-and-then-some-more")
        longer.mkdir()
        base2 = longer / "trail.jsonl"
        log2 = AuditLog.open(base2, now_fn=lambda: FIXED_TS)
        while not base2.exists() or base2.stat().st_size <= 5_000:
            log2.append(payload={"i": 0}, payload_type=SYNTHETIC_TEST_PAYLOAD_TYPE)
        open_segmented(
            base2,
            max_segment_bytes=5_000,
            notice=lambda _message: None,
            now_fn=lambda: FIXED_TS,
        )
        wider = (longer / "trail.00000.jsonl").stat().st_size
        assert wider > ROTATION_BINDING_BYTES
