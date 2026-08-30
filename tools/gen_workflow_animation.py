#!/usr/bin/env python3
"""Generate the README workflow animation, one GIF per README language.

Emits one SVG per frame. Passing `--render` then rasterises those frames with
macOS `qlmanage` and encodes a GIF with `ffmpeg`. The SVG half is stdlib-only,
so anyone can regenerate the frames; only the render half shells out, and only
when it is asked to.

The frames are square for a reason. `qlmanage` fits an SVG to a square thumbnail
by its LONGER side and crops away the rest, so a 16:9 document quietly loses its
right-hand third. Each frame is therefore authored at 1600x1600 with the
1600x900 design band translated down by BAND_Y, and ffmpeg crops that band back
out at the end.

No version number appears anywhere in the animation, because the asset will
outlive any release it might name.

Every panel is reproducible from a real command or a real test in this
repository. If a frame and the code ever disagree, the frame is the thing that
is wrong.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

W, H = 1600, 900
SQ = 1600
BAND_Y = (SQ - H) // 2

BG = "#0d1117"
PANEL = "#161b22"
PANEL2 = "#1c2128"
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


def esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def text_width(s: str, size: float) -> float:
    """Rough advance width. CJK glyphs are full-width, latin is not — without
    this, Chinese chips come out half the size of their contents."""
    return sum(1.0 if ord(c) > 0x2E7F else 0.6 for c in s) * size


def _op(opacity: float | None) -> str:
    return "" if opacity is None else f' opacity="{opacity:.3f}"'


def rect(x, y, w, h, *, rx=0, fill="none", stroke=None, sw=2, opacity=None, dash=None) -> str:
    s = f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}" fill="{fill}"'
    if stroke:
        s += f' stroke="{stroke}" stroke-width="{sw}"'
    if dash:
        s += f' stroke-dasharray="{dash}"'
    return s + _op(opacity) + "/>"


def text(x, y, s, *, size=24, fill=TEXT, anchor="start", family=MONO, weight=None,
         opacity=None, spacing=None) -> str:
    out = (f'<text x="{x}" y="{y}" font-family="{family}" font-size="{size}" '
           f'fill="{fill}" text-anchor="{anchor}"')
    if weight:
        out += f' font-weight="{weight}"'
    if spacing:
        out += f' letter-spacing="{spacing}"'
    return out + _op(opacity) + f">{esc(s)}</text>"


def line(x1, y1, x2, y2, *, stroke=BORDER, sw=2, dash=None, opacity=None) -> str:
    s = f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{stroke}" stroke-width="{sw}"'
    if dash:
        s += f' stroke-dasharray="{dash}"'
    return s + _op(opacity) + "/>"


def arrow(x1, y1, x2, y2, *, stroke=MUTED, sw=2.5, dash=None, opacity=None) -> str:
    head = 11.0
    dx, dy = x2 - x1, y2 - y1
    length = max((dx * dx + dy * dy) ** 0.5, 1e-6)
    ux, uy = dx / length, dy / length
    bx, by = x2 - ux * head, y2 - uy * head
    px, py = -uy * head * 0.55, ux * head * 0.55
    pts = f"{x2},{y2} {bx + px},{by + py} {bx - px},{by - py}"
    return (line(x1, y1, bx, by, stroke=stroke, sw=sw, dash=dash, opacity=opacity)
            + f'<polygon points="{pts}" fill="{stroke}"' + _op(opacity) + "/>")


def panel(x, y, w, h, *, fill=PANEL, stroke=BORDER, sw=2, opacity=None) -> str:
    return rect(x, y, w, h, rx=14, fill=fill, stroke=stroke, sw=sw, opacity=opacity)


def chip(x, y, label, *, color=MUTED, fill=PANEL2, size=20, pad=16, family=MONO):
    w = text_width(label, size) + pad * 2
    h = size * 1.9
    return (rect(x, y, w, h, rx=h / 2, fill=fill, stroke=color, sw=1.6)
            + text(x + w / 2, y + h * 0.69, label, size=size, fill=color, anchor="middle",
                   family=family), w)


def chip_row(x, y, items, *, gap=12, size=20, family=MONO) -> str:
    out, cx = "", x
    for label, color in items:
        s, w = chip(cx, y, label, color=color, size=size, family=family)
        out += s
        cx += w + gap
    return out


def chip_row_width(items, *, gap=12, size=20, pad=16) -> float:
    return sum(text_width(t, size) + pad * 2 for t, _ in items) + gap * (len(items) - 1)


def lines(x, y, items, *, size=17, leading=26, family=MONO) -> str:
    return "".join(text(x, y + i * leading, s, size=size, fill=c, family=family)
                   for i, (s, c) in enumerate(items))


BLOCK_W, BLOCK_H = 96, 74
MINI_W, MINI_H, MINI_GAP = 44, 42, 8

STATE_COLORS = {
    "idle": (PANEL, BORDER, MUTED),
    "ok": (PANEL, GREEN, GREEN),
    "broken": ("#3d1518", RED, RED),
    "unverifiable": ("#33270a", AMBER, AMBER),
    "pending": (PANEL, BLUE, BLUE),
    "ghost": (BG, DIM, DIM),
    "handoff": ("#241a33", PURPLE, PURPLE),
    "rewritten": ("#3d1518", RED, RED),
}


def block(x, y, seq, *, state="idle", tag=None, tag_color=None) -> str:
    fill, stroke, fg = STATE_COLORS[state]
    dash = "6 5" if state == "ghost" else None
    out = rect(x, y, BLOCK_W, BLOCK_H, rx=10, fill=fill, stroke=stroke, sw=2.5, dash=dash)
    out += text(x + BLOCK_W / 2, y + 33, f"#{seq}", size=25, fill=fg, anchor="middle")
    if tag:
        out += text(x + BLOCK_W / 2, y + 58, tag, size=15, fill=tag_color or fg,
                    anchor="middle", family=SANS)
    return out


def chain(x, y, states, *, start=0, gap=26, tags=None, link_color=BORDER) -> str:
    out = ""
    for i, st in enumerate(states):
        bx = x + i * (BLOCK_W + gap)
        if i:
            out += line(bx - gap + 2, y + BLOCK_H / 2, bx - 2, y + BLOCK_H / 2,
                        stroke=link_color, sw=2.5)
        tag = (tags or {}).get(i)
        out += block(bx, y, start + i, state=st, tag=tag[0] if tag else None,
                     tag_color=tag[1] if tag else None)
    return out


def chain_width(n, gap=26) -> float:
    return n * BLOCK_W + (n - 1) * gap


def mini_chain(x, y, states) -> str:
    out = ""
    for i, st in enumerate(states):
        fill, stroke, fg = STATE_COLORS[st]
        bx = x + i * (MINI_W + MINI_GAP)
        out += rect(bx, y, MINI_W, MINI_H, rx=7, fill=fill, stroke=stroke, sw=2)
        out += text(bx + MINI_W / 2, y + 28, str(i), size=17, fill=fg, anchor="middle")
    return out


# --- copy ------------------------------------------------------------------
#
# One dict per README language. Layout code never contains a display string, so
# a translation is a data change and can never drift out of the frame it sits
# in. Commands and identifiers stay untranslated on purpose: they are what the
# reader will actually type.

TEST_PATH = "tests/domain/test_schema_evolution_experiment.py"

EN = {
    "scenes": ["append", "tamper", "schema", "coverage", "anchor", "agents", "verdict"],
    "tagline": "tamper-evident audit chain for AI agents",
    "hook": "unverifiable   is not   tampered",
    "chips": ["0 dependencies", "Python 3.11+", "MIT"],
    "s1_titles": ["1 · event", "2 · redact", "3 · payload_hash", "4 · header", "5 · entry_hash"],
    "s1_caps": [
        ("An agent logs a decision. It carries a secret.", "sources/decisions.py"),
        ("Redaction runs before the hash.", "the chain commits to redacted bytes"),
        ("The payload is hashed once.", ""),
        ("Only these six fields are chained.", ""),
        ("Hash the header. That is the link.", "entry_hash = sha256(lp64 frame)"),
    ],
    "s1_secret": "cleartext never reaches disk",
    "s1_note": "append-only",
    "s1_appended": "appended",
    "s2_caps": [
        ("Seven entries, each linked to the last hash.", ""),
        ("Someone edits entry 3.", ""),
        ("verify recomputes every row.", "$ waxseal verify trail.jsonl"),
        ("The first break is reported. Nothing is repaired.", ""),
    ],
    "s2_edited": "edited",
    "s3_caps": [
        ("The schema describes itself, and that description is the version.", ""),
        ("Add one field and the fingerprint moves on its own.", ""),
        ("Rows 0-3 were written under A. Rows 4-6 under B.", ""),
        ("Roll the binary back. It knows A only.", ""),
        ("Ordinal versions: unknown is fatal. Nothing verifies.", "beads v1.2.2"),
        ("Recompute under A: three untouched rows called tampered.", "migration 060"),
        ("waxseal: intact rows intact, unknown rows unverifiable.", "exit 2"),
        ("", ""),
    ],
    "s3_desc": "descriptor",
    "s3_banner": "binary rolled back: this build knows A only",
    "s3_p1": ("ordinal version",
              ["trail    v2", "binary   v1", "", "FATAL", "schema version mismatch", "",
               "0 / 7 verified"], "beads v1.2.2"),
    "s3_p2": ("recompute under A", "3 broken", "migration 060"),
    "s3_p3": ("waxseal", ["4 ok · 3 unverifiable", "0 broken · exit 2"],
              "unverifiable is a verdict"),
    "s3_card": ["one trail, three designs", TEST_PATH,
                "ordinal refuses · recompute: 3 false alarms · waxseal: 3 unverifiable, 0 broken"],
    "s4_caps": [
        ("The chain verifies clean.", "exit 0"),
        ("A write dropped before storage leaves no gap.", ""),
        ("So completeness is measured separately.", ""),
        ("Tickets from an outside issuer turn a silent drop into a detection.",
         "$ waxseal reconcile-tickets"),
    ],
    "s4_ghost": "never arrived",
    "s4_left": "completeness",
    "s4_neq": "None  is not  0",
    "s4_neq_sub": "not measured is not measured-zero",
    "s4_right": "admission tickets",
    "s4_detected": "ticket 4 missing, drop detected",
    "s4_blind": "still blind: 3 in the open lease",
    "s5_caps": [
        ("A checkpoint commits the whole trail to one root.", ""),
        ("One run publishes it to independent authorities.",
         "$ waxseal anchor --tsa-url ... --ots-calendar ..."),
        ("Each independent authority raises τ by one.", ""),
        ("The verifier's own policy is what makes a missing anchor visible.",
         "all of these are exit 2"),
    ],
    "s5_cp": "checkpoint",
    "s5_cp_sub": "Merkle root over heads",
    "s5_sinks": [("RFC 3161 authority", "attested time"),
                 ("OpenTimestamps", "long-horizon proof"),
                 ("witness", "consistent / inconsistent / unreachable")],
    "s5_tau": "τ · separation degree",
    "s5_tau_note": "same crypto, different τ, not the same security",
    "s5_not": ("anchoring does not claim",
               ["the CMS signature is not verified in-library", "it does not close coverage"]),
    "s5_pin": "pin policy, held by the verifier:",
    "s6_caps": [
        ("Three agents. Three separate trails.", ""),
        ("B records where A's history stood at handoff.", "record_handoff()"),
        ("C does the same with B.", ""),
        ("Anyone can re-check a hop, read-only.",
         "$ waxseal verify-handoff trail-b.jsonl --origin trail-a.jsonl"),
        ("Rewrite A from seq 12. A still verifies clean.",
         "a re-chained trail is self-consistent"),
        ("But B pinned A's hash at seq 12, and it is gone.", ""),
    ],
    "s6_agents": ["agent A · planner", "agent B · coder", "agent C · reviewer"],
    "s6_binding": "binding",
    "s6_rewritten": "rewritten",
    "s6_a_ok": "verify trail-a.jsonl: ok",
    "s6_holds": "2 bindings hold · exit 0",
    "s6_holds_sub": "read-only: appends nothing to either trail",
    "s6_fails": "binding to A#12 DOES NOT HOLD · exit 1",
    "s6_fails_sub": "rewriting one agent's history breaks the next agent's binding",
    "s6_pin": "pins A#12",
    "s7_caps": [
        ("Four exit codes over three evidential states.", ""),
        ("", ""),
        ("The same rule, in six places.", ""),
        ("", ""),
    ],
    "s7_exits": ["intact", "broken", "unverifiable", "no trail"],
    "s7_neq": ["unverifiable  is not  tampered", "None  is not  0",
               "unmeasured  is not  absent"],
    "s7_sites": ["verdict: ok / broken / unverifiable", "dropped_writes: int | None",
                 "human_oversight: 'unrecorded'", "ModelRef.digest: None = unpinned",
                 "witness: ... / unreachable", "RFC 3161 nonce absent: skipped"],
    "s7_chips": ["0 dependencies", "1907 tests · 100% coverage", "MIT"],
}

VI = {
    "scenes": ["ghi", "giả mạo", "schema", "bao phủ", "neo", "đa agent", "kết luận"],
    "tagline": "audit chain chống giả mạo cho AI agent",
    "hook": "không kiểm được   ≠   bị giả mạo",
    "chips": ["0 dependency", "Python 3.11+", "MIT"],
    "s1_titles": ["1 · sự kiện", "2 · redact", "3 · payload_hash", "4 · header",
                  "5 · entry_hash"],
    "s1_caps": [
        ("Agent ghi một quyết định. Trong đó có secret.", "sources/decisions.py"),
        ("Redact chạy trước khi hash.", "chain cam kết trên bytes đã redact"),
        ("Payload được hash đúng một lần.", ""),
        ("Chỉ sáu trường này được nối chain.", ""),
        ("Hash header. Đó là mắt xích.", "entry_hash = sha256(lp64 frame)"),
    ],
    "s1_secret": "cleartext không chạm đĩa",
    "s1_note": "chỉ ghi thêm",
    "s1_appended": "đã nối",
    "s2_caps": [
        ("Bảy entry, mỗi cái nối vào hash trước đó.", ""),
        ("Có người sửa entry 3.", ""),
        ("verify tính lại từng dòng.", "$ waxseal verify trail.jsonl"),
        ("Báo break đầu tiên. Không sửa gì cả.", ""),
    ],
    "s2_edited": "bị sửa",
    "s3_caps": [
        ("Schema tự mô tả, và chính mô tả đó là version.", ""),
        ("Thêm một trường, fingerprint tự đổi.", ""),
        ("Dòng 0-3 ghi dưới A. Dòng 4-6 dưới B.", ""),
        ("Rollback binary. Nó chỉ biết A.", ""),
        ("Version theo số: không biết là chết. Không dòng nào verify được.", "beads v1.2.2"),
        ("Tính lại theo A: ba dòng lành lặn bị gọi là giả mạo.", "migration 060"),
        ("waxseal: dòng lành báo lành, dòng lạ báo không kiểm được.", "exit 2"),
        ("", ""),
    ],
    "s3_desc": "descriptor",
    "s3_banner": "binary đã rollback: bản này chỉ biết A",
    "s3_p1": ("version theo số",
              ["trail    v2", "binary   v1", "", "LỖI NẶNG", "schema version mismatch", "",
               "0 / 7 dòng verify"], "beads v1.2.2"),
    "s3_p2": ("tính lại theo A", "3 broken", "migration 060"),
    "s3_p3": ("waxseal", ["4 ok · 3 không kiểm được", "0 broken · exit 2"],
              "không kiểm được là một verdict"),
    "s3_card": ["cùng một trail, ba thiết kế", TEST_PATH,
                "ordinal: từ chối · tính lại: 3 báo động giả · waxseal: 3 không kiểm được, "
                "0 broken"],
    "s4_caps": [
        ("Chain verify sạch.", "exit 0"),
        ("Một write rơi trước khi tới storage không để lại khoảng trống.", ""),
        ("Nên độ bao phủ phải đo riêng.", ""),
        ("Ticket từ bên phát hành ngoài biến drop im lặng thành phát hiện.",
         "$ waxseal reconcile-tickets"),
    ],
    "s4_ghost": "không tới nơi",
    "s4_left": "độ bao phủ",
    "s4_neq": "None  ≠  0",
    "s4_neq_sub": "chưa đo không phải là đo ra số 0",
    "s4_right": "ticket phát hành",
    "s4_detected": "thiếu ticket 4, phát hiện drop",
    "s4_blind": "vẫn mù: 3 trong cửa sổ lease đang mở",
    "s5_caps": [
        ("Checkpoint cam kết cả trail vào một root.", ""),
        ("Một lần chạy publish nó tới các authority độc lập.",
         "$ waxseal anchor --tsa-url ... --ots-calendar ..."),
        ("Mỗi authority độc lập làm τ tăng một.", ""),
        ("Chính policy của verifier mới làm một anchor thiếu trở nên thấy được.",
         "tất cả đều là exit 2"),
    ],
    "s5_cp": "checkpoint",
    "s5_cp_sub": "Merkle root trên các head",
    "s5_sinks": [("RFC 3161 authority", "thời gian được chứng thực"),
                 ("OpenTimestamps", "bằng chứng dài hạn"),
                 ("witness", "khớp / lệch / không liên lạc được")],
    "s5_tau": "τ · mức độ tách biệt",
    "s5_tau_note": "cùng crypto, khác τ, không cùng mức bảo mật",
    "s5_not": ("anchoring không tuyên bố",
               ["chữ ký CMS không được verify trong thư viện",
                "nó không đóng được độ bao phủ"]),
    "s5_pin": "pin policy do verifier tự giữ:",
    "s6_caps": [
        ("Ba agent. Ba trail riêng biệt.", ""),
        ("B ghi lại lịch sử của A đang ở đâu lúc bàn giao.", "record_handoff()"),
        ("C làm y hệt với B.", ""),
        ("Ai cũng kiểm lại được một chặng, chỉ đọc.",
         "$ waxseal verify-handoff trail-b.jsonl --origin trail-a.jsonl"),
        ("Viết lại A từ seq 12. A vẫn tự verify sạch.",
         "trail được nối lại vẫn tự nhất quán"),
        ("Nhưng B đã ghim hash của A tại seq 12, và nó không còn.", ""),
    ],
    "s6_agents": ["agent A · lập kế hoạch", "agent B · viết code", "agent C · review"],
    "s6_binding": "binding",
    "s6_rewritten": "bị viết lại",
    "s6_a_ok": "verify trail-a.jsonl: ok",
    "s6_holds": "2 binding còn giữ · exit 0",
    "s6_holds_sub": "chỉ đọc: không ghi thêm gì vào cả hai trail",
    "s6_fails": "binding tới A#12 KHÔNG CÒN GIỮ · exit 1",
    "s6_fails_sub": "viết lại lịch sử một agent là làm gãy binding của agent kế tiếp",
    "s6_pin": "ghim A#12",
    "s7_caps": [
        ("Bốn exit code trên ba trạng thái bằng chứng.", ""),
        ("", ""),
        ("Cùng một luật, ở sáu chỗ.", ""),
        ("", ""),
    ],
    "s7_exits": ["nguyên vẹn", "bị gãy", "không kiểm được", "không có trail"],
    "s7_neq": ["không kiểm được  ≠  bị giả mạo", "None  ≠  0", "chưa đo  ≠  không có"],
    "s7_sites": ["verdict: ok / broken / unverifiable", "dropped_writes: int | None",
                 "human_oversight: 'unrecorded'", "ModelRef.digest: None = chưa ghim",
                 "witness: ... / unreachable", "nonce RFC 3161 vắng: bỏ qua"],
    "s7_chips": ["0 dependency", "1907 test · 100% coverage", "MIT"],
}

ZH = {
    "scenes": ["追加", "篡改", "schema", "完整性", "锚定", "多 Agent", "裁决"],
    "tagline": "面向 AI Agent 的防篡改审计链",
    "hook": "无法验证   ≠   被篡改",
    "chips": ["零依赖", "Python 3.11+", "MIT"],
    "s1_titles": ["1 · 事件", "2 · 脱敏", "3 · payload_hash", "4 · header", "5 · entry_hash"],
    "s1_caps": [
        ("Agent 记录一次决策，其中带有密钥。", "sources/decisions.py"),
        ("脱敏在哈希之前执行。", "链承诺的是脱敏后的字节"),
        ("载荷只被哈希一次。", ""),
        ("只有这六个字段进入链。", ""),
        ("哈希这个头部，它就是链接。", "entry_hash = sha256(lp64 frame)"),
    ],
    "s1_secret": "明文不落盘",
    "s1_note": "只追加",
    "s1_appended": "已追加",
    "s2_caps": [
        ("七条记录，每条都链到上一条的哈希。", ""),
        ("有人改了第 3 条。", ""),
        ("verify 重算每一行。", "$ waxseal verify trail.jsonl"),
        ("只报告第一个断点，什么都不修复。", ""),
    ],
    "s2_edited": "被修改",
    "s3_caps": [
        ("schema 描述自身，而这份描述就是版本。", ""),
        ("加一个字段，指纹自己就变了。", ""),
        ("第 0-3 行写于 A，第 4-6 行写于 B。", ""),
        ("把程序回滚。它只认识 A。", ""),
        ("序号版本：不认识就是致命错误，一行都验不了。", "beads v1.2.2"),
        ("按 A 重算：三行没被动过的记录被判为篡改。", "migration 060"),
        ("waxseal：完好的报完好，不认识的报无法验证。", "exit 2"),
        ("", ""),
    ],
    "s3_desc": "descriptor",
    "s3_banner": "程序已回滚 —— 这个构建只认识 A",
    "s3_p1": ("序号版本",
              ["trail    v2", "binary   v1", "", "致命错误", "schema version mismatch", "",
               "0 / 7 行通过"], "beads v1.2.2"),
    "s3_p2": ("按 A 重算", "3 条判为篡改", "migration 060"),
    "s3_p3": ("waxseal", ["4 条通过 · 3 条无法验证", "0 条篡改 · exit 2"],
              "无法验证也是一种结论"),
    "s3_card": ["同一条轨迹，三种设计", TEST_PATH,
                "序号版本：拒绝运行 · 重算：3 次误报 · waxseal：3 条无法验证，0 条篡改"],
    "s4_caps": [
        ("链验证通过。", "exit 0"),
        ("在写入存储之前丢掉的记录不会留下空缺。", ""),
        ("所以完整性要单独度量。", ""),
        ("来自外部签发方的票据把静默丢失变成阳性检出。", "$ waxseal reconcile-tickets"),
    ],
    "s4_ghost": "从未到达",
    "s4_left": "完整性",
    "s4_neq": "None  ≠  0",
    "s4_neq_sub": "未度量不等于度量出来是零",
    "s4_right": "准入票据",
    "s4_detected": "缺少票据 4 —— 检出丢失",
    "s4_blind": "仍有盲区：租约窗口内的 3 条",
    "s5_caps": [
        ("检查点把整条轨迹承诺到一个根。", ""),
        ("一次运行把它发布到互相独立的权威方。",
         "$ waxseal anchor --tsa-url ... --ots-calendar ..."),
        ("每多一个独立权威方，τ 就加一。", ""),
        ("是验证方自己的策略，让缺失的锚定变得可见。", "这些都是 exit 2"),
    ],
    "s5_cp": "checkpoint",
    "s5_cp_sub": "对各链头的 Merkle 根",
    "s5_sinks": [("RFC 3161 权威时间戳", "可证时间"),
                 ("OpenTimestamps", "长周期证据"),
                 ("witness 见证方", "一致 / 不一致 / 联系不上")],
    "s5_tau": "τ · 分离度",
    "s5_tau_note": "密码学相同、τ 不同 —— 安全性并不相同",
    "s5_not": ("锚定并不声称", ["库内不验证 CMS 签名", "它不解决完整性问题"]),
    "s5_pin": "验证方自己持有的 pin 策略：",
    "s6_caps": [
        ("三个 Agent，三条独立轨迹。", ""),
        ("B 记录下交接那一刻 A 的历史停在哪里。", "record_handoff()"),
        ("C 对 B 做同样的事。", ""),
        ("任何人都能只读地复核一跳。",
         "$ waxseal verify-handoff trail-b.jsonl --origin trail-a.jsonl"),
        ("从 seq 12 起改写 A。A 自己仍然验证通过。", "重新链接过的轨迹是自洽的"),
        ("但 B 钉住了 A 在 seq 12 的哈希，那个哈希已经没了。", ""),
    ],
    "s6_agents": ["agent A · 规划", "agent B · 编码", "agent C · 评审"],
    "s6_binding": "绑定",
    "s6_rewritten": "被改写",
    "s6_a_ok": "verify trail-a.jsonl: ok",
    "s6_holds": "2 条绑定成立 · exit 0",
    "s6_holds_sub": "只读 —— 两条轨迹都不写入任何内容",
    "s6_fails": "指向 A#12 的绑定不再成立 · exit 1",
    "s6_fails_sub": "改写一个 Agent 的历史，就必然打断下一个 Agent 的绑定",
    "s6_pin": "钉住 A#12",
    "s7_caps": [
        ("四个退出码，三种证据状态。", ""),
        ("", ""),
        ("同一条规则，用在六个地方。", ""),
        ("", ""),
    ],
    "s7_exits": ["完好", "断裂", "无法验证", "没有轨迹"],
    "s7_neq": ["无法验证  ≠  被篡改", "None  ≠  0", "未度量  ≠  不存在"],
    "s7_sites": ["verdict: ok / broken / unverifiable", "dropped_writes: int | None",
                 "human_oversight: 'unrecorded'", "ModelRef.digest: None = 未固定",
                 "witness: ... / unreachable", "RFC 3161 nonce 缺失：跳过"],
    "s7_chips": ["零依赖", "1907 项测试 · 100% 覆盖", "MIT"],
}

LANGS = {"en": EN, "vi": VI, "zh": ZH}


def chrome(L, scene: int, cap: str = "", sub: str = "") -> str:
    out = rect(0, 0, W, H, fill=BG)
    out += line(0, 92, W, 92, stroke=BORDER, sw=2)
    out += text(56, 46, "waxseal", size=34, fill=TEXT, family=SANS, weight="700")
    out += text(56, 74, L["tagline"], size=18, fill=MUTED, family=SANS)
    px = W - 56
    for i in range(len(L["scenes"]) - 1, -1, -1):
        on = i == scene
        px -= 14 if on else 12
        out += (f'<circle cx="{px}" cy="42" r="{6 if on else 4.5}" '
                f'fill="{GREEN if on else "none"}" stroke="{GREEN if on else DIM}" '
                f'stroke-width="1.8"/>')
        px -= 10
    out += text(W - 56, 78, L["scenes"][scene], size=19, fill=MUTED, anchor="end", family=SANS)
    out += line(0, H - 82, W, H - 82, stroke=BORDER, sw=2)
    if cap:
        out += text(56, H - 46, cap, size=24, fill=TEXT, family=SANS)
    if sub:
        out += text(56, H - 18, sub, size=18, fill=MUTED)
    return out


def document(body: str) -> str:
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{SQ}" height="{SQ}" '
            f'viewBox="0 0 {SQ} {SQ}"><rect width="{SQ}" height="{SQ}" fill="{BG}"/>'
            f'<g transform="translate(0,{BAND_Y})">{body}</g></svg>')


class Timeline:
    """Holds are repeated frames. Identical consecutive frames cost almost
    nothing in a GIF, so a long hold is cheap."""

    def __init__(self) -> None:
        self.frames: list[str] = []

    def add(self, body: str, hold: int = 1) -> None:
        self.frames.extend([body] * hold)


def scene_title(tl: Timeline, L) -> None:
    def build(step: int) -> str:
        out = rect(0, 0, W, H, fill=BG)
        out += text(W / 2, 356, "waxseal", size=124, fill=TEXT, anchor="middle",
                    family=SANS, weight="800", spacing=-2)
        if step >= 1:
            out += text(W / 2, 424, L["tagline"], size=33, fill=MUTED, anchor="middle",
                        family=SANS)
        if step >= 2:
            items = [(t, c) for t, c in zip(L["chips"], (GREEN, BLUE, MUTED), strict=True)]
            out += chip_row((W - chip_row_width(items)) / 2, 500, items)
        if step >= 3:
            out += text(W / 2, 656, L["hook"], size=34, fill=AMBER, anchor="middle",
                        family=SANS)
        return out

    for s in range(4):
        tl.add(build(s), 4 if s < 3 else 16)


S1_X, S1_W, S1_GAP, S1_Y, S1_H = 66, 260, 42, 168, 244


def _sx(i: int) -> float:
    return S1_X + i * (S1_W + S1_GAP)


def scene_append(tl: Timeline, L) -> None:
    colors = [PURPLE, GREEN, CYAN, AMBER, GREEN]

    def body(i: int, x: float) -> str:
        if i == 0:
            return lines(x + 18, S1_Y + 88, [
                ('{"action": "transfer",', TEXT), ('  "amount": 25000,', TEXT),
                ('  "api_key": "sk-live"', RED), ("}", TEXT)], size=15, leading=26)
        if i == 1:
            return lines(x + 18, S1_Y + 88, [
                ('{"action": "transfer",', TEXT), ('  "amount": 25000,', TEXT),
                ('  "api_key": "[REDACTED]"', GREEN), ("}", TEXT)], size=15, leading=26) \
                + text(x + 18, S1_Y + 210, L["s1_secret"], size=15, fill=GREEN, family=SANS)
        if i == 2:
            return lines(x + 18, S1_Y + 110, [("sha256(payload)", MUTED), ("", TEXT),
                                              ("9c1f7d2e...", CYAN)], size=17, leading=32)
        if i == 3:
            return lines(x + 16, S1_Y + 82, [
                ("seq           3", TEXT), ("ts            ...", TEXT),
                ("hash_version  a3f1c8", AMBER), ("payload_type  ...", TEXT),
                ("payload_hash  9c1f7d", CYAN), ("prev_hash     e04b91", TEXT)],
                size=14, leading=24)
        return lines(x + 18, S1_Y + 110, [("sha256(header)", MUTED), ("", TEXT),
                                          ("7f3a55c0...", GREEN)], size=17, leading=32)

    def build(upto: int, tail: int = 0) -> str:
        cap, sub = L["s1_caps"][min(upto, 4)]
        out = chrome(L, 0, cap, sub)
        for i, title in enumerate(L["s1_titles"]):
            live = i <= upto
            x = _sx(i)
            out += panel(x, S1_Y, S1_W, S1_H, stroke=colors[i] if live else BORDER,
                         sw=3 if live else 2, fill=PANEL if live else BG)
            out += text(x + 18, S1_Y + 34, title, size=17,
                        fill=colors[i] if live else DIM, family=SANS)
            out += line(x + 18, S1_Y + 48, x + S1_W - 18, S1_Y + 48, stroke=BORDER, sw=1.5)
            if live:
                out += body(i, x)
        for i in range(min(upto, 4)):
            ax = _sx(i) + S1_W
            out += arrow(ax + 8, S1_Y + S1_H / 2, ax + S1_GAP - 8, S1_Y + S1_H / 2)
        if tail:
            tip = _sx(4) + S1_W / 2
            cx0 = tip - 3 * (BLOCK_W + 26) - BLOCK_W / 2
            out += chain(cx0, 560, ["ok", "ok", "ok"] + (["pending"] if tail > 1 else []))
            out += text(cx0, 678, L["s1_note"], size=20, fill=MUTED, family=SANS)
            if tail > 1:
                out += arrow(tip, S1_Y + S1_H + 12, tip, 548, stroke=GREEN)
                out += text(tip - 14, 505, L["s1_appended"], size=17, fill=GREEN,
                            anchor="end", family=SANS)
        return out

    for i in range(5):
        tl.add(build(i), 8 if i in (1, 3) else 6)
    tl.add(build(4, 1), 4)
    tl.add(build(4, 2), 12)


def scene_tamper(tl: Timeline, L) -> None:
    n, cy = 7, 260
    cx = (W - chain_width(n)) / 2

    def build(scanned: int, *, edited: bool, verdict: bool) -> str:
        idx = 3 if verdict else (2 if scanned else (1 if edited else 0))
        out = chrome(L, 1, *L["s2_caps"][idx])
        states = [("broken" if edited and i == 3 else "ok") if scanned and i < scanned
                  else "idle" for i in range(n)]
        out += chain(cx, cy, states, tags={i: (None, None) for i in ()})
        if edited:
            bx = cx + 3 * (BLOCK_W + 26)
            out += text(bx + BLOCK_W / 2, cy - 32, L["s2_edited"], size=19, fill=RED,
                        anchor="middle", family=SANS)
            out += arrow(bx + BLOCK_W / 2, cy - 24, bx + BLOCK_W / 2, cy - 6, stroke=RED)
        if scanned and not verdict:
            sx = cx + scanned * (BLOCK_W + 26) - 13
            out += line(sx, cy - 14, sx, cy + BLOCK_H + 14, stroke=BLUE, sw=3)
        if verdict:
            out += panel(cx, 470, chain_width(n), 170, stroke=RED, sw=2.5)
            out += lines(cx + 32, 522, [("broken_seq   3", RED),
                                        ("reason       payload_hash_mismatch", RED),
                                        ("exit         1", RED)], size=23, leading=40)
        return out

    tl.add(build(0, edited=False, verdict=False), 8)
    tl.add(build(0, edited=True, verdict=False), 10)
    for k in range(1, 5):
        tl.add(build(k, edited=True, verdict=False), 4)
    tl.add(build(4, edited=True, verdict=True), 20)


def scene_schema(tl: Timeline, L) -> None:
    fields = ["seq", "ts", "hash_version", "payload_type", "payload_hash", "prev_hash"]

    def descriptor(y, extra, label, fp, color) -> str:
        out = text(56, y + 6, L["s3_desc"], size=17, fill=DIM)
        items = [(f, MUTED) for f in fields] + ([(extra, AMBER)] if extra else [])
        out += chip_row(176, y - 18, items, size=16)
        out += arrow(1104, y + 4, 1150, y + 4)
        out += rect(1166, y - 24, 380, 56, rx=10, fill=PANEL, stroke=color, sw=2)
        out += text(1186, y + 12, f"{label}   {fp}", size=22, fill=color)
        return out

    def build(step: int) -> str:
        out = chrome(L, 2, *L["s3_caps"][min(step, 7)])
        out += descriptor(150, None, "A", "a3f1c8...", GREEN)
        if step >= 1:
            out += descriptor(232, "actor", "B", "9c02e5...", AMBER)
        if step >= 2:
            tags = {i: (("A", GREEN) if i < 4 else ("B", AMBER)) for i in range(7)}
            out += chain((W - chain_width(7)) / 2, 300, ["idle"] * 7, tags=tags)
        if step >= 3:
            out += rect(56, 408, W - 112, 46, rx=10, fill="#2b1a05", stroke=AMBER, sw=2)
            out += text(W / 2, 439, L["s3_banner"], size=23, fill=AMBER, anchor="middle",
                        family=SANS)
        pw, pgap = 480, 30
        px0 = (W - (3 * pw + 2 * pgap)) / 2
        for i, need in enumerate((4, 5, 6)):
            px = px0 + i * (pw + pgap)
            if step < need:
                out += panel(px, 478, pw, 296, fill=BG, stroke=BORDER)
                continue
            color = GREEN if need == 6 else RED
            title, foot = (L["s3_p1"][0], L["s3_p1"][2]) if need == 4 else (
                (L["s3_p2"][0], L["s3_p2"][2]) if need == 5 else (L["s3_p3"][0], L["s3_p3"][2]))
            out += panel(px, 478, pw, 296, stroke=color, sw=3)
            out += text(px + 24, 516, title, size=22, fill=color, family=SANS)
            out += line(px + 24, 530, px + pw - 24, 530, stroke=BORDER, sw=1.5)
            if need == 4:
                out += lines(px + 24, 568, [(s, RED if s.isupper() or "致命" in s or
                                             "LỖI" in s else MUTED)
                                            for s in L["s3_p1"][1]], size=19, leading=28)
            elif need == 5:
                out += mini_chain(px + 24, 580, ["ok"] * 4 + ["broken"] * 3)
                out += text(px + 24, 670, L["s3_p2"][1], size=24, fill=RED, family=SANS)
            else:
                out += mini_chain(px + 24, 580, ["ok"] * 4 + ["unverifiable"] * 3)
                out += text(px + 24, 668, L["s3_p3"][1][0], size=21, fill=GREEN, family=SANS)
                out += text(px + 24, 700, L["s3_p3"][1][1], size=21, fill=AMBER, family=SANS)
            out += text(px + 24, 752, foot, size=16, fill=DIM, family=SANS)
        if step >= 7:
            out += rect(px0, 478, 3 * pw + 2 * pgap, 296, rx=14, fill=PANEL, stroke=GREEN, sw=3)
            out += text(W / 2, 570, L["s3_card"][0], size=27, fill=MUTED, anchor="middle",
                        family=SANS)
            out += text(W / 2, 630, L["s3_card"][1], size=27, fill=GREEN, anchor="middle")
            out += text(W / 2, 690, L["s3_card"][2], size=20, fill=TEXT, anchor="middle",
                        family=SANS)
        return out

    for s, hold in enumerate([8, 12, 8, 10, 12, 12, 14, 18]):
        tl.add(build(s), hold)


def scene_completeness(tl: Timeline, L) -> None:
    cx = (W - chain_width(6)) / 2

    def build(step: int) -> str:
        out = chrome(L, 3, *L["s4_caps"][min(step, 3)])
        out += chain(cx, 150, ["ok"] * 6)
        if step >= 1:
            gx = cx + chain_width(6) + 40
            out += block(gx, 150, 6, state="ghost")
            out += text(gx + BLOCK_W / 2, 140, L["s4_ghost"], size=16, fill=DIM,
                        anchor="middle", family=SANS)
        if step >= 2:
            out += panel(56, 320, 700, 288, stroke=BORDER)
            out += text(80, 364, L["s4_left"], size=21, fill=MUTED, family=SANS)
            out += line(80, 378, 732, 378, stroke=BORDER, sw=1.5)
            out += text(80, 442, "dropped_writes:  None", size=30, fill=AMBER)
            out += rect(80, 480, 620, 60, rx=10, fill="#33270a", stroke=AMBER, sw=2)
            out += text(390, 519, L["s4_neq"], size=27, fill=AMBER, anchor="middle")
            out += text(80, 578, L["s4_neq_sub"], size=17, fill=DIM, family=SANS)
        if step >= 3:
            out += panel(800, 320, 744, 288, stroke=BORDER)
            out += text(824, 364, L["s4_right"], size=21, fill=MUTED, family=SANS)
            out += line(824, 378, 1520, 378, stroke=BORDER, sw=1.5)
            tx = 824
            for i in range(1, 7):
                miss = i == 4
                out += rect(tx, 404, 96, 54, rx=9, fill="#3d1518" if miss else PANEL2,
                            stroke=RED if miss else GREEN, sw=2,
                            dash="5 4" if miss else None)
                out += text(tx + 48, 438, f"T{i}", size=21, fill=RED if miss else GREEN,
                            anchor="middle")
                tx += 112
            out += text(824, 512, L["s4_detected"], size=24, fill=RED, family=SANS)
            out += text(824, 552, "exit 1", size=20, fill=MUTED)
            out += text(824, 586, L["s4_blind"], size=17, fill=AMBER, family=SANS)
        return out

    for s, hold in enumerate([8, 12, 14, 18]):
        tl.add(build(s), hold)


def scene_anchoring(tl: Timeline, L) -> None:
    colors = (BLUE, PURPLE, CYAN)

    def build(step: int) -> str:
        out = chrome(L, 4, *L["s5_caps"][min(step, 3)])
        out += chain(56, 168, ["ok"] * 3)
        out += arrow(56 + chain_width(3) + 14, 205, 470, 205)
        out += panel(486, 150, 330, 116, stroke=GREEN, sw=2.5)
        out += text(510, 190, L["s5_cp"], size=22, fill=GREEN, family=SANS)
        out += text(510, 222, "root 4e9b71c2...", size=19, fill=TEXT)
        out += text(510, 248, L["s5_cp_sub"], size=15, fill=MUTED, family=SANS)
        for i, (name, what) in enumerate(L["s5_sinks"]):
            y = 130 + i * 104
            live = step >= 1
            out += panel(940, y, 604, 88, stroke=colors[i] if live else BORDER,
                         sw=2.5 if live else 2, fill=PANEL if live else BG)
            out += text(964, y + 36, name, size=21, fill=colors[i] if live else DIM,
                        family=SANS)
            out += text(964, y + 62, what, size=16, fill=MUTED if live else DIM, family=SANS)
            if live:
                out += arrow(824, 208, 928, y + 44, stroke=colors[i], sw=2)
        if step >= 1:
            title, notes = L["s5_not"]
            out += panel(940, 470, 604, 150, stroke=BORDER)
            out += text(964, 508, title, size=19, fill=MUTED, family=SANS)
            out += line(964, 522, 1520, 522, stroke=BORDER, sw=1.5)
            out += lines(964, 558, [(n, MUTED) for n in notes], size=17, leading=30,
                         family=SANS)
        if step >= 2:
            out += panel(56, 470, 820, 150, stroke=AMBER, sw=2.5)
            out += text(80, 510, L["s5_tau"], size=21, fill=AMBER, family=SANS)
            out += line(80, 524, 852, 524, stroke=BORDER, sw=1.5)
            out += text(80, 566, "writer 1 + anchors 2 + witness 1 + pin 1", size=21, fill=TEXT)
            out += text(80, 602, "τ = 5", size=27, fill=AMBER)
            out += text(300, 602, L["s5_tau_note"], size=17, fill=DIM, family=SANS)
        if step >= 3:
            out += text(56, 670, L["s5_pin"], size=18, fill=MUTED, family=SANS)
            out += chip_row(56, 692, [("anchor_stale", AMBER),
                                      ("anchor_policy_downgrade", AMBER),
                                      ("separation_shortfall", AMBER),
                                      ("exit 2", GREEN)], size=18)
        return out

    for s, hold in enumerate([10, 14, 14, 18]):
        tl.add(build(s), hold)


def scene_cross_agent(tl: Timeline, L) -> None:
    geom = [(PURPLE, 150, 10, 5), (BLUE, 330, 40, 5), (CYAN, 510, 70, 4)]
    lane_x = 330

    def build(step: int, *, attacked: bool = False) -> str:
        out = chrome(L, 5, *L["s6_caps"][min(step, 5)])
        for li, (color, y, start, count) in enumerate(geom):
            if li and step < li:
                continue
            out += text(56, y + 30, L["s6_agents"][li], size=22, fill=color, family=SANS)
            out += text(56, y + 58, f"trail-{chr(97 + li)}.jsonl", size=16, fill=DIM)
            states = ["ok"] * count
            if attacked and li == 0:
                states = ["ok", "ok", "rewritten", "rewritten", "rewritten"]
            tags = {}
            if li and step >= li:
                states[0] = "handoff"
                tags[0] = (L["s6_binding"], PURPLE if li == 1 else BLUE)
            if attacked and li == 0:
                tags = {i: (L["s6_rewritten"], RED) for i in (2, 3, 4)}
            out += chain(lane_x, y, states, start=start, tags=tags)
            if attacked and li == 0:
                out += text(lane_x + chain_width(count) + 24, y + 44, L["s6_a_ok"],
                            size=18, fill=MUTED)
            if li and step >= li:
                px = lane_x + BLOCK_W / 2
                ox = lane_x + 2 * (BLOCK_W + 26) + BLOCK_W / 2
                bad = attacked and li == 1
                ac = RED if bad else (PURPLE if li == 1 else BLUE)
                out += arrow(px, y - 6, ox, geom[li - 1][1] + BLOCK_H + 6, stroke=ac, sw=2.5,
                             dash="7 5")
                label = L["s6_pin"] if li == 1 else L["s6_pin"].replace("A#12", "B#42")
                out += text(ox + 18, geom[li - 1][1] + BLOCK_H + 36, label, size=16, fill=ac,
                            family=SANS)
        if step >= 3 and not attacked:
            out += panel(56, 646, 1488, 116, stroke=GREEN, sw=2.5)
            out += text(80, 694, L["s6_holds"], size=25, fill=GREEN, family=SANS)
            out += text(80, 732, L["s6_holds_sub"], size=18, fill=MUTED, family=SANS)
        if attacked:
            out += panel(56, 646, 1488, 116, stroke=RED, sw=2.5)
            out += text(80, 694, L["s6_fails"], size=25, fill=RED, family=SANS)
            out += text(80, 732, L["s6_fails_sub"], size=18, fill=MUTED, family=SANS)
        return out

    for s, hold in enumerate([8, 14, 14, 18]):
        tl.add(build(s), hold)
    tl.add(build(4, attacked=True), 16)
    tl.add(build(5, attacked=True), 22)


def scene_verdict(tl: Timeline, L) -> None:
    colors = (GREEN, RED, AMBER, DIM)

    def build(step: int) -> str:
        out = chrome(L, 6, *L["s7_caps"][min(step, 3)])
        bw, bgap = 350, 24
        bx0 = (W - (4 * bw + 3 * bgap)) / 2
        for i, label in enumerate(L["s7_exits"]):
            bx = bx0 + i * (bw + bgap)
            out += panel(bx, 150, bw, 150, stroke=colors[i], sw=3)
            out += text(bx + bw / 2, 216, f"exit {i}", size=38, fill=colors[i], anchor="middle")
            out += text(bx + bw / 2, 260, label, size=24, fill=TEXT, anchor="middle",
                        family=SANS)
        if step >= 1:
            for i, s in enumerate(L["s7_neq"]):
                out += text(W / 2, 380 + i * 46, s, size=28 if i == 0 else 24,
                            fill=AMBER if i == 0 else MUTED, anchor="middle", family=SANS)
        if step >= 2:
            for i, s in enumerate(L["s7_sites"]):
                col, row = i % 2, i // 2
                out += text(150 + col * 720, 546 + row * 40, "·  " + s, size=19, fill=TEXT)
        if step >= 3:
            out += rect(0, 92, W, H - 174, fill=BG)
            out += text(W / 2, 330, "waxseal", size=104, fill=TEXT, anchor="middle",
                        family=SANS, weight="800", spacing=-2)
            out += text(W / 2, 400, "pip install waxseal", size=33, fill=GREEN, anchor="middle")
            items = [(t, c) for t, c in zip(L["s7_chips"], (GREEN, BLUE, MUTED), strict=True)]
            out += chip_row((W - chip_row_width(items)) / 2, 456, items)
            out += text(W / 2, 590, "github.com/cuongbphv/waxseal", size=26, fill=MUTED,
                        anchor="middle", family=SANS)
        return out

    for s, hold in enumerate([12, 14, 16, 26]):
        tl.add(build(s), hold)


def build_timeline(L) -> Timeline:
    tl = Timeline()
    for scene in (scene_title, scene_append, scene_tamper, scene_schema,
                  scene_completeness, scene_anchoring, scene_cross_agent, scene_verdict):
        scene(tl, L)
    return tl


def write_frames(out_dir: Path, L) -> int:
    tl = build_timeline(L)
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
    subprocess.run(["qlmanage", "-t", "-s", str(SQ), "-o", str(png_dir), *svgs],  # noqa: S603
                   check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    made = len(list(png_dir.glob("*.png")))
    if made != len(svgs):
        raise SystemExit(f"qlmanage rendered {made}/{len(svgs)} frames")
    vf = (f"crop={W}:{H}:0:{BAND_Y},scale={width}:-1:flags=lanczos,split[a][b];"
          f"[a]palettegen=max_colors={colors}:stats_mode=diff[p];"
          f"[b][p]paletteuse=dither=bayer:bayer_scale=4:diff_mode=rectangle")
    gif.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["ffmpeg", "-y", "-hide_banner", "-loglevel", "error",  # noqa: S603
                    "-framerate", str(fps), "-pattern_type", "glob",
                    "-i", str(png_dir / "*.png"), "-vf", vf, "-loop", "0", str(gif)],
                   check=True)


GIF_NAME = {"en": "waxseal-workflow.gif", "vi": "waxseal-workflow.vi.gif",
            "zh": "waxseal-workflow.zh.gif"}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Build the README workflow animation.")
    ap.add_argument("--lang", choices=[*LANGS, "all"], default="all")
    ap.add_argument("--build", type=Path, default=Path("build/anim"))
    ap.add_argument("--assets", type=Path, default=Path("docs/assets"))
    ap.add_argument("--fps", type=int, default=10)
    ap.add_argument("--width", type=int, default=1200)
    ap.add_argument("--colors", type=int, default=64)
    ap.add_argument("--render", action="store_true")
    args = ap.parse_args(argv)

    for lang in (LANGS if args.lang == "all" else [args.lang]):
        svg_dir = args.build / lang / "svg"
        n = write_frames(svg_dir, LANGS[lang])
        print(f"{lang}: {n} frames ({n / args.fps:.1f}s)", end="")
        if args.render:
            gif = args.assets / GIF_NAME[lang]
            render_gif(svg_dir, args.build / lang / "png", gif, fps=args.fps,
                       width=args.width, colors=args.colors)
            print(f" -> {gif} {gif.stat().st_size / 1_048_576:.2f} MiB", end="")
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
