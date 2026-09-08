#!/usr/bin/env python3
"""Generate the README risk-PoC terminal animation, one GIF per language.

Same two-stage pipeline as `gen_workflow_animation.py`: stdlib-only SVG frames,
then `--render` rasterises them with macOS `qlmanage` and encodes a GIF with
`ffmpeg`. The square-frame trick and the BAND_Y crop are inherited for the same
reason they exist there — `qlmanage` fits an SVG to a square thumbnail by its
longer side and crops the rest away.

What separates this asset from the workflow one: **nothing on the terminal is
written by hand.** Every line comes from running the real thing at generation
time — `examples/risk-poc/simulate.py` for the report, the example's own
`stages_for()` for the pipeline boxes and their hashes, `waxseal.cli.main` for
the two verify runs and their exit codes. A frame cannot drift from the code
because there is no copy of the code's output to drift from.

Two presentational liberties, and only two. Absolute temp paths are rewritten
to `poc-out/…` so the reader sees the path they would type, and a line wider
than the terminal is wrapped rather than clipped, the way a terminal wraps it.
Neither invents a character the program did not print.

The terminal body stays English in all three languages, following the rule the
workflow animation already sets for commands and identifiers: this is what the
reader's own machine prints. Only the caption under the window is translated.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
EXAMPLE = REPO / "examples" / "risk-poc"

W, H = 1600, 900
SQ = 1600
BAND_Y = (SQ - H) // 2

BG = "#0d1117"
PANEL = "#161b22"
BAR = "#1c2128"
BORDER = "#30363d"
TEXT = "#e6edf3"
MUTED = "#8b949e"
DIM = "#586069"
GREEN = "#3fb950"
RED = "#f85149"
AMBER = "#d29922"
BLUE = "#58a6ff"
PURPLE = "#bc8cff"
CYAN = "#39c5cf"

MONO = "ui-monospace,SFMono-Regular,Menlo,'PingFang SC',monospace"
SANS = "-apple-system,BlinkMacSystemFont,'Helvetica Neue','PingFang SC',Arial,sans-serif"

TX, TY, TW, TH = 40, 26, 1520, 762
TITLEBAR = 46
FS = 19.0
CW = FS * 0.6
LEAD = 25.5
X0 = TX + 28
BODY_TOP = TY + TITLEBAR + 34
ROWS = 26
COLS = int((TW - 62) // CW)


def esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def rect(x, y, w, h, *, rx=0, fill="none", stroke=None, sw=2) -> str:
    s = f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}" fill="{fill}"'
    if stroke:
        s += f' stroke="{stroke}" stroke-width="{sw}"'
    return s + "/>"


def mono(x, y, s, fill, *, cells: int | None = None) -> str:
    """`cells` pins a run to the character grid.

    The rendering font's advance is not exactly 0.6em, so a long run laid out
    by multiplying CW drifts off the grid and out through the right border.
    `textLength` makes the grid the authority instead of the font metric;
    `spacingAndGlyphs` keeps box-drawing runs contiguous, which plain
    `spacing` would tear apart.
    """
    out = (
        f'<text x="{x:.1f}" y="{y:.1f}" xml:space="preserve" font-family="{MONO}" '
        f'font-size="{FS}" fill="{fill}"'
    )
    if cells:
        out += f' textLength="{cells * CW:.1f}" lengthAdjust="spacingAndGlyphs"'
    return out + f">{esc(s)}</text>"


def sans(x, y, s, *, size=24, fill=TEXT, anchor="start", weight=None) -> str:
    out = (
        f'<text x="{x}" y="{y}" font-family="{SANS}" font-size="{size}" fill="{fill}" '
        f'text-anchor="{anchor}"'
    )
    if weight:
        out += f' font-weight="{weight}"'
    return out + f">{esc(s)}</text>"


# --- the screen model ------------------------------------------------------
#
# A row is a list of (text, colour) runs laid out on a fixed character grid, so
# a colour change never shifts a column. Rows past ROWS scroll off the top,
# exactly as they would in a real window.

Row = list[tuple[str, str]]


class Term:
    def __init__(self) -> None:
        self.rows: list[Row] = []

    def add(self, *runs: tuple[str, str]) -> None:
        self.rows.append(list(runs))

    def blank(self, n: int = 1) -> None:
        for _ in range(n):
            self.rows.append([])

    def wrapped(self, text: str, colour: str, *, indent: str = "  ") -> None:
        """Wrap on width the way the terminal would, never clipping."""
        width = COLS - len(indent)
        words, line = text.split(" "), ""
        for word in words:
            if line and len(line) + 1 + len(word) > width:
                self.add((indent + line, colour))
                line = word
            else:
                line = f"{line} {word}" if line else word
        if line:
            self.add((indent + line, colour))

    def snapshot(self) -> list[Row]:
        return [r[:] for r in self.rows]


def render(rows: list[Row], title: str) -> str:
    out = rect(0, 0, W, H, fill=BG)
    out += rect(TX, TY, TW, TH, rx=14, fill=PANEL, stroke=BORDER, sw=2)
    out += rect(TX, TY, TW, TITLEBAR, rx=14, fill=BAR)
    out += rect(TX, TY + TITLEBAR - 14, TW, 14, fill=BAR)
    for i, colour in enumerate((RED, AMBER, GREEN)):
        out += f'<circle cx="{TX + 30 + i * 26}" cy="{TY + 23}" r="7" fill="{colour}"/>'
    out += sans(TX + TW / 2, TY + 30, title, size=18, fill=MUTED, anchor="middle")
    out += (
        f'<line x1="{TX}" y1="{TY + TITLEBAR}" x2="{TX + TW}" y2="{TY + TITLEBAR}" '
        f'stroke="{BORDER}" stroke-width="2"/>'
    )
    for i, runs in enumerate(rows[-ROWS:]):
        y = BODY_TOP + i * LEAD
        col = 0
        for txt, colour in runs:
            if txt.strip():
                out += mono(X0 + col * CW, y, txt, colour, cells=len(txt))
            col += len(txt)
    return out


def frame(rows: list[Row], title: str, cap: str, sub: str) -> str:
    out = render(rows, title)
    if cap:
        out += sans(TX, 838, cap, size=25, fill=TEXT)
    if sub:
        out += mono(TX, 872, sub, MUTED)
    return out


def document(body: str) -> str:
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{SQ}" height="{SQ}" '
        f'viewBox="0 0 {SQ} {SQ}"><rect width="{SQ}" height="{SQ}" fill="{BG}"/>'
        f'<g transform="translate(0,{BAND_Y})">{body}</g></svg>'
    )


class Timeline:
    def __init__(self) -> None:
        self.frames: list[str] = []

    def add(self, body: str, hold: int = 1) -> None:
        self.frames.extend([body] * hold)


# --- capture ---------------------------------------------------------------


class Capture:
    """Everything the frames display, obtained by running the real thing."""

    def __init__(self, work: Path) -> None:
        sys.path.insert(0, str(EXAMPLE))
        import _animate  # noqa: PLC0415
        import simulate  # noqa: PLC0415

        from waxseal import DecisionRecord  # noqa: PLC0415
        from waxseal.adapters.redactors import RegexRedactor  # noqa: PLC0415
        from waxseal.sources.decisions import commit_input  # noqa: PLC0415

        self.glyphs = _animate.G
        self.out = work / "poc-out"
        report = _run_script(EXAMPLE / "simulate.py", ["--out", str(self.out), "--no-animation"])
        self.report = _clean(report, self.out)
        _run_script(EXAMPLE / "tamper_demo.py", ["--out", str(self.out)])

        # The pipeline boxes for the one transaction that carries a credential:
        # the redaction stage is the whole reason this animation exists.
        redactor = RegexRedactor()
        txn = simulate.transactions()[3]
        verdict = simulate.screen(txn)
        record = DecisionRecord(
            decision_id=f"DEC-{txn.txn_id}",
            decision_type=verdict.decision_type,
            system_id=simulate.SYSTEM_ID,
            model=simulate.MODEL,
            input_commitment=commit_input(simulate.model_input(txn), redactor=redactor),
            outcome=verdict.outcome,
            rationale=verdict.rationale,
            policy_version=simulate.POLICY_VERSION,
            confidence=verdict.confidence,
            human_oversight=verdict.oversight,
            subject_ref=txn.subject_ref,
            trace_id=f"trace-{txn.txn_id.lower()}",
        )
        self.txn_id = txn.txn_id
        self.stages = simulate.stages_for(txn, verdict, record, redactor, 3)
        self.trail = self.out / "decisions.jsonl"
        self.edited = self.out / "tamper-cases" / "01-edit" / "decisions.jsonl"
        self.head = _head_hash(self.trail)
        self.ok_out, self.ok_code = _cli("verify", "--anchors", str(self.trail))
        self.broken_out, self.broken_code = _cli("verify", str(self.edited))

    def report_block(self, heading: str) -> list[str]:
        """The section verbatim, so a report that changes shape changes the frame."""
        lines = self.report.splitlines()
        start = lines.index(heading)
        end = next(
            (i for i in range(start + 1, len(lines)) if lines[i].startswith("## ")), len(lines)
        )
        return [ln.rstrip() for ln in lines[start:end]]

    def report_line(self, needle: str) -> str:
        for line in self.report.splitlines():
            if needle in line:
                return line.strip()
        raise SystemExit(
            f"the demo no longer prints {needle!r}; the frames are the thing "
            f"that is wrong, not the code"
        )


def _run_script(script: Path, args: list[str]) -> str:
    proc = subprocess.run(  # noqa: S603
        [sys.executable, str(script), *args],
        cwd=REPO,
        check=True,
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin", "WAXSEAL_DEMO_PLAIN": "1", "PYTHONPATH": str(REPO / "src")},
    )
    return proc.stdout


def _cli(*args: str) -> tuple[str, int]:
    from waxseal.cli import main  # noqa: PLC0415

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        code = main(list(args))
    return buf.getvalue(), code


def _clean(text: str, out: Path) -> str:
    return text.replace(str(out), "poc-out").replace(str(REPO) + "/", "")


def _head_hash(trail: Path) -> str:
    from waxseal import AuditLog  # noqa: PLC0415

    entries = list(AuditLog.open(trail).entries())
    return entries[-1].entry_hash


# --- copy ------------------------------------------------------------------

EN = {
    "title": "risk PoC — a verifiable AI decision log",
    "caps": [
        (
            "A risk-scanning agent screens six payments. Every decision lands on the chain.",
            "examples/risk-poc/simulate.py",
        ),
        (
            "Redaction runs before the hash — the credential never reaches disk.",
            "stage 2 of 7, and it cannot be moved later",
        ),
        (
            "Six decisions, one chain, one report an auditor can read.",
            "oversight not recorded is counted apart from automated",
        ),
        (
            "The chain verifies. Every check it did not run says so.",
            "$ waxseal verify --anchors  ·  exit 0",
        ),
        (
            "Flip one approval. The row is named, and nothing is repaired.",
            "$ waxseal verify  ·  exit 1",
        ),
    ],
}

VI = {
    "title": "risk PoC — nhật ký quyết định AI kiểm chứng được",
    "caps": [
        (
            "Agent quét rủi ro sàng lọc sáu giao dịch. Mỗi quyết định đều lên chain.",
            "examples/risk-poc/simulate.py",
        ),
        (
            "Redact chạy trước khi hash — credential không bao giờ chạm đĩa.",
            "bước 2 trên 7, và không thể dời xuống sau",
        ),
        (
            "Sáu quyết định, một chain, một report kiểm toán viên đọc được.",
            "không ghi giám sát được đếm tách khỏi automated",
        ),
        (
            "Chain verify sạch. Mọi kiểm tra chưa chạy đều tự nói ra.",
            "$ waxseal verify --anchors  ·  exit 0",
        ),
        (
            "Sửa một phê duyệt. Đúng dòng đó bị gọi tên, và không gì được sửa lại.",
            "$ waxseal verify  ·  exit 1",
        ),
    ],
}

ZH = {
    "title": "risk PoC — 可验证的 AI 决策日志",
    "caps": [
        ("风险扫描 Agent 筛查六笔支付，每次决策都进入链中。", "examples/risk-poc/simulate.py"),
        ("脱敏在哈希之前执行 —— 凭据永远不落盘。", "七步中的第二步，而且不能挪到后面"),
        ("六次决策，一条链，一份审计人员读得懂的报告。", "未记录人工监督与自动处理分开计数"),
        ("链验证通过，而没有跑过的检查都会自己说出来。", "$ waxseal verify --anchors  ·  exit 0"),
        ("改掉一次批准。那一行会被指名，而且什么都不会被修复。", "$ waxseal verify  ·  exit 1"),
    ],
}

LANGS = {"en": EN, "vi": VI, "zh": ZH}


# --- scenes ----------------------------------------------------------------


def type_command(tl: Timeline, term: Term, cmd: str, L, scene: int, *, step: int = 4) -> None:
    base = term.snapshot()
    for i in range(0, len(cmd) + step, step):
        rows = base + [[("$ ", GREEN), (cmd[:i], TEXT), ("█", GREEN)]]
        tl.add(frame(rows, L["title"], *L["caps"][scene]), 1)
    term.add(("$ ", GREEN), (cmd, TEXT))
    tl.add(frame(term.snapshot(), L["title"], *L["caps"][scene]), 4)


def flow_block(cap: Capture, active: int, tick: int) -> list[Row]:
    """The frame `_animate.FlowAnimator._draw` puts on the screen, in SVG."""
    g = cap.glyphs
    width = 8
    tops: Row = [("  ", TEXT)]
    mids: Row = [("  ", TEXT)]
    bots: Row = [("  ", TEXT)]
    for i, stage in enumerate(cap.stages):
        if i < active:
            colour, mark = GREEN, g.check
        elif i == active:
            colour, mark = CYAN, g.spinner[tick % len(g.spinner)]
        else:
            colour, mark = DIM, " "
        if i:
            join = GREEN if i - 1 < active else DIM
            tops.append((" ", TEXT))
            mids.append((g.arrow, join))
            bots.append((" ", TEXT))
        tops.append((f"{g.tl}{g.h * width}{g.tr}", colour))
        mids.append((f"{g.v}{f'{mark} {stage.label}'.ljust(width)}{g.v}", colour))
        bots.append((f"{g.bl}{g.h * width}{g.br}", colour))
    done = active >= len(cap.stages)
    label = "done" if done else cap.stages[active].label
    detail = "entry committed" if done else cap.stages[active].detail
    return [
        [(f"  waxseal · decision 4/6 · {cap.txn_id}", TEXT)],
        [],
        tops,
        mids,
        bots,
        [],
        [(f"  {label} ", AMBER), (f"· {detail}", MUTED)],
    ]


def scene_simulate(tl: Timeline, term: Term, cap: Capture, L) -> None:
    type_command(tl, term, "python examples/risk-poc/simulate.py --out poc-out", L, 0)
    term.blank()
    term.add(("  Writing a verifiable AI decision log to poc-out/decisions.jsonl", MUTED))
    term.blank()
    tl.add(frame(term.snapshot(), L["title"], *L["caps"][0]), 6)

    base = term.snapshot()
    redact_step = 1
    for active in range(len(cap.stages) + 1):
        scene = 1 if active >= redact_step else 0
        spins = 3 if active in (redact_step, 2) else 2
        for tick in range(spins):
            tl.add(
                frame(base + flow_block(cap, active, tick), L["title"], *L["caps"][scene]),
                4 if active == redact_step else 2,
            )
    tl.add(frame(base + flow_block(cap, len(cap.stages), 0), L["title"], *L["caps"][1]), 10)

    term.rows = base
    term.add(("  chain  ", MUTED), (f"{g_link(cap, 5)}{cap.glyphs.tip}", GREEN))
    term.add(
        ("         0   1   2   3   4   5   ", DIM),
        (f"head = {cap.head[:12]}{cap.glyphs.ellipsis}", MUTED),
    )
    term.blank()
    tl.add(frame(term.snapshot(), L["title"], *L["caps"][2]), 10)


def g_link(cap: Capture, n: int) -> str:
    g = cap.glyphs
    return g.link.join(g.node for _ in range(n)) + g.link


def scene_report(tl: Timeline, term: Term, cap: Capture, L) -> None:
    for line in cap.report_block("## AI decisions"):
        if not line:
            term.blank()
            continue
        if "not recorded" in line:
            term.wrapped(line, AMBER, indent="")
            tl.add(frame(term.snapshot(), L["title"], *L["caps"][2]), 16)
            continue
        term.add((line, BLUE if line.startswith("## ") else TEXT))
        tl.add(frame(term.snapshot(), L["title"], *L["caps"][2]), 2)
    term.blank()
    term.add((f"  {cap.report_line('Cleartext secret present')}", GREEN))
    term.blank()
    tl.add(frame(term.snapshot(), L["title"], *L["caps"][2]), 14)


def scene_verify(
    tl: Timeline, term: Term, cap: Capture, L, *, scene: int, cmd: str, output: str, code: int
) -> None:
    type_command(tl, term, cmd, L, scene)
    colour = GREEN if code == 0 else RED
    for line in output.splitlines():
        if not line.strip():
            continue
        verdict = line.startswith(("ok ", "anchors ok", "BROKEN", "ANCHOR BROKEN"))
        term.wrapped(line, colour if verdict else MUTED, indent="")
        tl.add(frame(term.snapshot(), L["title"], *L["caps"][scene]), 3)
    term.add((f"exit {code}", colour))
    tl.add(frame(term.snapshot(), L["title"], *L["caps"][scene]), 22)


def build_timeline(cap: Capture, L) -> Timeline:
    tl, term = Timeline(), Term()
    scene_simulate(tl, term, cap, L)
    scene_report(tl, term, cap, L)
    scene_verify(
        tl,
        term,
        cap,
        L,
        scene=3,
        cmd="waxseal verify --anchors poc-out/decisions.jsonl",
        output=cap.ok_out,
        code=cap.ok_code,
    )
    term.blank()
    scene_verify(
        tl,
        term,
        cap,
        L,
        scene=4,
        cmd="waxseal verify poc-out/tamper-cases/01-edit/decisions.jsonl",
        output=cap.broken_out,
        code=cap.broken_code,
    )
    return tl


def write_frames(out_dir: Path, cap: Capture, L) -> int:
    tl = build_timeline(cap, L)
    out_dir.mkdir(parents=True, exist_ok=True)
    for old in out_dir.glob("f*.svg"):
        old.unlink()
    for i, body in enumerate(tl.frames):
        (out_dir / f"f{i:04d}.svg").write_text(document(body), encoding="utf-8")
    return len(tl.frames)


def render_gif(svg_dir: Path, png_dir: Path, gif: Path, *, fps, width, colors) -> None:
    for tool in ("qlmanage", "ffmpeg"):
        if shutil.which(tool) is None:
            raise SystemExit(f"{tool} not found; frames were written, GIF was not encoded")
    if png_dir.exists():
        shutil.rmtree(png_dir)
    png_dir.mkdir(parents=True)
    svgs = sorted(str(p) for p in svg_dir.glob("f*.svg"))
    subprocess.run(
        ["qlmanage", "-t", "-s", str(SQ), "-o", str(png_dir), *svgs],  # noqa: S603
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    made = len(list(png_dir.glob("*.png")))
    if made != len(svgs):
        raise SystemExit(f"qlmanage rendered {made}/{len(svgs)} frames")
    vf = (
        f"crop={W}:{H}:0:{BAND_Y},scale={width}:-1:flags=lanczos,split[a][b];"
        f"[a]palettegen=max_colors={colors}:stats_mode=diff[p];"
        f"[b][p]paletteuse=dither=none:diff_mode=rectangle"
    )
    gif.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            "ffmpeg",
            "-y",
            "-hide_banner",
            "-loglevel",
            "error",  # noqa: S603
            "-framerate",
            str(fps),
            "-pattern_type",
            "glob",
            "-i",
            str(png_dir / "*.png"),
            "-vf",
            vf,
            "-loop",
            "0",
            str(gif),
        ],
        check=True,
    )


GIF_NAME = {"en": "risk-poc.gif", "vi": "risk-poc.vi.gif", "zh": "risk-poc.zh.gif"}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Build the README risk-PoC terminal animation.")
    ap.add_argument("--lang", choices=[*LANGS, "all"], default="all")
    ap.add_argument("--build", type=Path, default=Path("build/poc-anim"))
    ap.add_argument("--assets", type=Path, default=Path("docs/assets"))
    ap.add_argument("--fps", type=int, default=12)
    ap.add_argument("--width", type=int, default=1200)
    ap.add_argument("--colors", type=int, default=32)
    ap.add_argument("--render", action="store_true")
    args = ap.parse_args(argv)

    with tempfile.TemporaryDirectory() as tmp:
        cap = Capture(Path(tmp))
        for lang in LANGS if args.lang == "all" else [args.lang]:
            svg_dir = args.build / lang / "svg"
            n = write_frames(svg_dir, cap, LANGS[lang])
            print(f"{lang}: {n} frames ({n / args.fps:.1f}s)", end="")
            if args.render:
                gif = args.assets / GIF_NAME[lang]
                render_gif(
                    svg_dir,
                    args.build / lang / "png",
                    gif,
                    fps=args.fps,
                    width=args.width,
                    colors=args.colors,
                )
                print(f" -> {gif} {gif.stat().st_size / 1_048_576:.2f} MiB", end="")
            print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
