"""Opaque entry-page cursors (REMOTE.md section 4).

A cursor from some other server, or a hand-typed integer, is rejected rather
than silently interpreted as an offset into this one. A cursor also names the
SEGMENT it was issued against: without that, a reader whose chain rotated
mid-page would resume at its offset in a file it never saw the start of.
"""

from __future__ import annotations

from typing import Final

_CURSOR_PREFIX: Final = "e"
_CURSOR_SEGMENT_SEPARATOR: Final = "~"


def encode_cursor(index: int, identity: str) -> str:
    return f"{_CURSOR_PREFIX}{index}{_CURSOR_SEGMENT_SEPARATOR}{identity}"


def decode_cursor(cursor: str | None) -> tuple[int, str | None]:
    """`(offset, segment identity)`.

    The identity is `None` only for "no cursor at all" — the first page, which
    is about whatever segment is active when it is asked for. It is never a
    guessed segment: a cursor that carries no identity is refused rather than
    aimed at the active file, because the one thing a resumed read must not do
    is silently continue in a different file.
    """
    if cursor is None:
        return 0, None
    if not cursor.startswith(_CURSOR_PREFIX):
        raise ValueError(f"unrecognized cursor {cursor!r}")
    offset, _, identity = cursor[len(_CURSOR_PREFIX) :].partition(_CURSOR_SEGMENT_SEPARATOR)
    if not offset.isdigit() or not identity:
        raise ValueError(f"unrecognized cursor {cursor!r}")
    return int(offset), identity
