"""Terminal animation for the demo's opening data-flow walkthrough.

Purely presentational. Nothing here participates in hashing, recording, or
verification — if this module were deleted the PoC would produce the identical
trail, byte for byte. It exists because "redaction happens before the hash" is
a sentence people nod at and a picture people remember.

Degrades on purpose rather than assuming a capable terminal: without a TTY
(piped output, CI, a log file) it prints each stage as a plain line and moves
on, because a redraw animation written into a pipe is unreadable noise. On
Windows it asks the console for VT processing first and falls back to plain
text if the console refuses, instead of spraying escape codes at it.
"""

from __future__ import annotations

import os
import sys
import time
from dataclasses import dataclass

RESET = "\033[0m"
DIM = "\033[2m"
BOLD = "\033[1m"
CYAN = "\033[1;36m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
GREY = "\033[90m"

def _encodable(probe: str) -> bool:
    """Can this console actually render these characters?

    Windows consoles still default to a legacy codepage; writing box-drawing
    characters at cp1252 produces either a crash or mojibake. A demo whose
    whole job is to be legible must check rather than hope.
    """
    encoding = getattr(sys.stdout, "encoding", None) or "ascii"
    try:
        probe.encode(encoding)
    except (UnicodeEncodeError, LookupError):
        return False
    return True


@dataclass(frozen=True, slots=True)
class Glyphs:
    tl: str
    tr: str
    bl: str
    br: str
    h: str
    v: str
    arrow: str
    check: str
    node: str
    tip: str
    link: str
    ellipsis: str
    spinner: str


UNICODE = Glyphs(
    tl="┌", tr="┐", bl="└", br="┘", h="─", v="│", arrow="▶", check="✓",
    node="●", tip="◍", link="───", ellipsis="…", spinner="⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏",
)
ASCII = Glyphs(
    tl="+", tr="+", bl="+", br="+", h="-", v="|", arrow=">", check="*",
    node="o", tip="@", link="---", ellipsis="...", spinner="|/-\\",
)


def glyphs() -> Glyphs:
    return UNICODE if _encodable(UNICODE.h + UNICODE.arrow + UNICODE.spinner) else ASCII


G = glyphs()
SPINNER = G.spinner


@dataclass(frozen=True, slots=True)
class Stage:
    """One box in the pipeline: a short label and the real value it produced."""

    label: str
    detail: str


def supports_ansi(stream: object = None) -> bool:
    """True only when redraw escapes will actually render."""
    out = stream or sys.stdout
    if os.environ.get("NO_COLOR") or os.environ.get("WAXSEAL_DEMO_PLAIN"):
        return False
    if not hasattr(out, "isatty") or not out.isatty():  # type: ignore[union-attr]
        return False
    if os.name != "nt":
        return True
    return _enable_windows_vt()


def _enable_windows_vt() -> bool:
    """Ask conhost for VT processing. Modern Windows Terminal has it on;
    older consoles need the flag set and some refuse outright."""
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        # 0x0004 = ENABLE_VIRTUAL_TERMINAL_PROCESSING
        return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))
    except Exception:
        return False


class FlowAnimator:
    """Draws the append pipeline, lighting each box as its stage completes."""

    def __init__(self, *, enabled: bool = True, frame_delay: float = 0.055) -> None:
        self.enabled = enabled and supports_ansi()
        self.frame_delay = frame_delay
        self._lines_drawn = 0

    def play(self, title: str, stages: list[Stage], *, dwell: float = 0.30) -> None:
        if not self.enabled:
            self._plain(title, stages)
            return
        for active in range(len(stages) + 1):
            spins = max(1, int(dwell / self.frame_delay)) if active < len(stages) else 1
            for tick in range(spins):
                self._draw(title, stages, active, tick)
                time.sleep(self.frame_delay)
        print()

    def _plain(self, title: str, stages: list[Stage]) -> None:
        print(f"\n{title}")
        for i, stage in enumerate(stages, 1):
            print(f"  {i}. {stage.label:<8} {stage.detail}")
        print()

    def _draw(self, title: str, stages: list[Stage], active: int, tick: int) -> None:
        width = 8
        tops, mids, bots = [], [], []
        for i, stage in enumerate(stages):
            if i < active:
                colour, mark = GREEN, G.check
            elif i == active:
                colour, mark = CYAN, SPINNER[tick % len(SPINNER)]
            else:
                colour, mark = GREY + DIM, " "
            body = f"{mark} {stage.label}".ljust(width)
            tops.append(f"{colour}{G.tl}{G.h * width}{G.tr}{RESET}")
            mids.append(f"{colour}{G.v}{body}{G.v}{RESET}")
            bots.append(f"{colour}{G.bl}{G.h * width}{G.br}{RESET}")

        arrow_done = f"{GREEN}{G.arrow}{RESET}"
        arrow_todo = f"{GREY}{DIM}{G.arrow}{RESET}"
        joins = [arrow_done if i < active else arrow_todo for i in range(len(stages) - 1)]

        def row(cells: list[str], filler: str) -> str:
            out = cells[0]
            for i, cell in enumerate(cells[1:]):
                out += (joins[i] if filler == "arrow" else " ") + cell
            return "  " + out

        detail = stages[active].detail if active < len(stages) else "entry committed"
        label = stages[active].label if active < len(stages) else "done"
        lines = [
            f"  {BOLD}{title}{RESET}",
            "",
            row(tops, "space"),
            row(mids, "arrow"),
            row(bots, "space"),
            "",
            f"  {YELLOW}{label}{RESET} {DIM}·{RESET} {detail}",
        ]
        self._render(lines)

    def _render(self, lines: list[str]) -> None:
        if self._lines_drawn:
            # Move up over the previous frame and clear each line, rather than
            # clearing the whole screen — the demo's earlier output stays put.
            sys.stdout.write(f"\033[{self._lines_drawn}A")
        for line in lines:
            sys.stdout.write("\033[2K" + line + "\n")
        sys.stdout.flush()
        self._lines_drawn = len(lines)


def draw_chain(entry_hashes: list[str], *, enabled: bool = True) -> None:
    """A one-line picture of the chain after the walkthrough: each entry is a
    node, each link is a prev_hash the next entry commits to."""
    if not entry_hashes:
        return
    colour = GREEN if (enabled and supports_ansi()) else ""
    reset = RESET if colour else ""
    dim = DIM if colour else ""
    nodes = f"{colour}{G.link}{reset}".join(f"{colour}{G.node}{reset}" for _ in entry_hashes[:-1])
    tip = f"{colour}{G.tip}{reset}"
    link = f"{colour}{G.link}{reset}" if nodes else ""
    print(f"  chain  {nodes}{link}{tip}")
    labels = "   ".join(str(i) for i in range(len(entry_hashes)))
    print(f"         {dim}{labels}{reset}   head = {entry_hashes[-1][:12]}{G.ellipsis}")
    print()
