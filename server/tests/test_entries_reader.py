"""Reading a trail's entries for display.

Displaying an entry is not a verdict, so this one read goes through the
`AuditLog` facade rather than the CLI — the CLI's `tail` prints a human summary
line, not the envelope a viewer needs. It stays on the facade (`log.entries()`)
and never touches backend internals, which is the same boundary `sources/` is
held to.

What is displayed is what is stored, and what is stored was redacted BEFORE it
was hashed. There is no un-redaction step here and there must never be one.
"""

from __future__ import annotations

import base64
from pathlib import Path

import pytest
from conftest import PAYLOAD_TYPE
from waxseal_server.runtime.entries import read_entries_for_display

from waxseal import AuditLog
from waxseal.adapters.redactors import RegexRedactor


@pytest.fixture
def trail(tmp_path: Path) -> Path:
    path = tmp_path / "trail.jsonl"
    log = AuditLog.open(path)
    for i in range(5):
        log.append(payload={"i": i}, payload_type=PAYLOAD_TYPE)
    return path


class TestReadEntriesForDisplay:
    def test_it_yields_the_stored_envelope_shape(self, trail: Path) -> None:
        entries = read_entries_for_display(trail, limit=10)
        assert set(entries[0]) == {"header", "entry_hash", "payload_b64"}

    def test_entries_come_back_in_storage_order(self, trail: Path) -> None:
        entries = read_entries_for_display(trail, limit=10)
        assert [e["header"]["seq"] for e in entries] == [0, 1, 2, 3, 4]

    def test_the_limit_is_honoured(self, trail: Path) -> None:
        assert len(read_entries_for_display(trail, limit=2)) == 2

    def test_the_payload_round_trips_through_base64(self, trail: Path) -> None:
        entries = read_entries_for_display(trail, limit=1)
        assert base64.b64decode(entries[0]["payload_b64"]) == b'{"i":0}'

    def test_a_sqlite_trail_reads_the_same_way(self, tmp_path: Path) -> None:
        path = tmp_path / "trail.db"
        log = AuditLog.open(path)
        log.append(payload={"i": 0}, payload_type=PAYLOAD_TYPE)
        assert read_entries_for_display(path, limit=10)[0]["header"]["seq"] == 0

    def test_an_empty_trail_reads_as_nothing(self, tmp_path: Path) -> None:
        empty = tmp_path / "empty.jsonl"
        empty.write_text("")
        assert read_entries_for_display(empty, limit=10) == []

    def test_a_redacted_payload_stays_redacted(self, tmp_path: Path) -> None:
        # Redaction ran before the hash; the cleartext never reached disk, so
        # there is nothing for a viewer to reveal. The assertion is that the
        # display path adds no step that could try.
        path = tmp_path / "redacted.jsonl"
        log = AuditLog.open(path, redactor=RegexRedactor())
        log.append(
            payload={"token": "sk-ant-api03-SUPERSECRETVALUE0123456789"},
            payload_type=PAYLOAD_TYPE,
        )
        rendered = base64.b64decode(read_entries_for_display(path, limit=1)[0]["payload_b64"])
        assert b"SUPERSECRETVALUE" not in rendered

    def test_an_unopenable_suffix_raises_rather_than_returning_nothing(
        self, tmp_path: Path
    ) -> None:
        # Empty and unreadable are different answers. Returning [] for a file
        # waxseal cannot open would render "no entries" over a trail nobody read.
        bad = tmp_path / "trail.txt"
        bad.write_text("x")
        with pytest.raises(ValueError):
            read_entries_for_display(bad, limit=10)
