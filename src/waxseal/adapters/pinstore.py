"""FilePinStore: the verifier's pin state on local disk.

Not a sidecar of the trail. Every other file this package writes next to a
trail (`.attest`, `.anchors`, `.drops`) describes the log and belongs to
whoever owns it; a pin describes what THIS verifier already confirmed, and its
entire value is that it lives somewhere the trail's writer cannot reach. The
caller chooses the path for exactly that reason, and this class never derives
one from the trail's own location.

Written through `atomic_write_bytes` at 0600: a torn pin would read as
malformed on the next run, and malformed is a break — a crash during a save
must not be able to manufacture one.
"""

from __future__ import annotations

from pathlib import Path

from waxseal.adapters.atomic import atomic_write_bytes
from waxseal.domain.pinning import PinMalformed, PinState, parse_pin_state, render_pin_state


class FilePinStore:
    def __init__(self, path: Path | str) -> None:
        self._path = Path(path).expanduser()

    def load(self) -> PinState | None:
        """The stored pin, or ``None`` when there is none yet.

        ``None`` means only "nothing pinned" — the genuine first-use case. A
        file that exists but cannot be read raises (``PinMalformed`` /
        ``PinVersionUnknown`` from the domain), because returning ``None``
        for it would let a caller re-pin whatever it was just served and call
        that trust-on-first-use.
        """
        try:
            text = self._path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return None
        except UnicodeDecodeError as e:
            raise PinMalformed(f"pin state is not UTF-8 text: {e}") from e
        return parse_pin_state(text)

    def save(self, state: PinState) -> None:
        atomic_write_bytes(self._path, render_pin_state(state).encode("utf-8"), mode=0o600)
