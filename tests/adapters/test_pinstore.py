"""FilePinStore: where a verifier keeps what it already confirmed.

The store is deliberately thin — reading and writing one small file — but two
of its properties are load-bearing and tested here rather than assumed:

- a save is atomic, so a crash mid-write can never leave a torn pin that the
  next run would read as malformed and treat as a break;
- a pin state this build cannot read is raised, never swallowed. Returning
  ``None`` for an unreadable file would be indistinguishable from "no pin
  yet", and the caller would silently re-pin whatever it was just served.
"""

from __future__ import annotations

import json
import stat
import sys
from pathlib import Path

import pytest

from waxseal.adapters.pinstore import FilePinStore
from waxseal.domain.checkpoint import Checkpoint
from waxseal.domain.pinning import PIN_STATE_VERSION, PinMalformed, PinState, PinVersionUnknown


def state(seq: int = 2, *, target: str = "/trail.jsonl") -> PinState:
    return PinState(
        target=target,
        chain_id=None,
        checkpoint=Checkpoint(seq=seq, entry_hash="a" * 64, root="b" * 64),
        pinned_ts="2026-08-23T09:00:00+00:00",
    )


class TestRoundTrip:
    def test_save_then_load(self, tmp_path: Path) -> None:
        store = FilePinStore(tmp_path / "pin.json")
        store.save(state())
        assert store.load() == state()

    def test_save_overwrites_the_previous_pin(self, tmp_path: Path) -> None:
        store = FilePinStore(tmp_path / "pin.json")
        store.save(state(1))
        store.save(state(4))
        loaded = store.load()
        assert loaded is not None
        assert loaded.checkpoint.seq == 4

    def test_creates_missing_parent_directories(self, tmp_path: Path) -> None:
        store = FilePinStore(tmp_path / "nested" / "deeper" / "pin.json")
        store.save(state())
        assert store.load() == state()

    def test_expands_user_in_path(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("USERPROFILE", str(tmp_path))
        store = FilePinStore("~/pin.json")
        store.save(state())
        assert (tmp_path / "pin.json").exists()


class TestAbsence:
    def test_missing_file_is_none_not_an_error(self, tmp_path: Path) -> None:
        # "No pin yet" is a real state — the first run of any pinned verify.
        assert FilePinStore(tmp_path / "absent.json").load() is None


class TestUnreadableStates:
    def test_malformed_bytes_raise(self, tmp_path: Path) -> None:
        path = tmp_path / "pin.json"
        path.write_text("{not json", encoding="utf-8")
        with pytest.raises(PinMalformed):
            FilePinStore(path).load()

    def test_unknown_version_raises_its_own_type(self, tmp_path: Path) -> None:
        path = tmp_path / "pin.json"
        path.write_text(
            json.dumps(
                {
                    "v": PIN_STATE_VERSION + 1,
                    "target": "/t",
                    "chain_id": None,
                    "seq": 0,
                    "entry_hash": "a" * 64,
                    "root": "b" * 64,
                    "pinned_ts": "t",
                }
            ),
            encoding="utf-8",
        )
        with pytest.raises(PinVersionUnknown):
            FilePinStore(path).load()

    def test_undecodable_bytes_are_malformed_not_a_crash(self, tmp_path: Path) -> None:
        path = tmp_path / "pin.json"
        path.write_bytes(b"\xff\xfe\x00 not utf-8")
        with pytest.raises(PinMalformed):
            FilePinStore(path).load()


class TestFilePermissions:
    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX mode bits")
    def test_pin_file_is_0600(self, tmp_path: Path) -> None:
        # Same posture as every other sidecar: a pin names a chain and its
        # head, which is as sensitive as the trail it describes.
        path = tmp_path / "pin.json"
        FilePinStore(path).save(state())
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


class TestAtomicity:
    def test_a_failing_save_leaves_the_previous_pin_intact(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Falsifiability receipt for the atomic-write claim: with a direct
        # open()/write() this assertion fails, because the old pin is
        # truncated before the failure happens.
        path = tmp_path / "pin.json"
        store = FilePinStore(path)
        store.save(state(1))
        before = path.read_bytes()

        import waxseal.adapters.pinstore as pinstore

        def boom(*args: object, **kwargs: object) -> None:
            raise OSError("disk full")

        monkeypatch.setattr(pinstore, "atomic_write_bytes", boom)
        with pytest.raises(OSError, match="disk full"):
            store.save(state(9))
        assert path.read_bytes() == before

    def test_no_temporary_files_are_left_behind(self, tmp_path: Path) -> None:
        path = tmp_path / "pin.json"
        FilePinStore(path).save(state())
        assert [p.name for p in tmp_path.iterdir()] == ["pin.json"]
