"""Parsing an anchor/witness checkpoint (REMOTE.md sections 7 and 9).

`{seq, entry_hash, root}`, optionally carrying the forward-secure aggregate
binding. Section 9's rule is that `agg_commit` and `agg_epoch` appear together
or not at all: half a binding is not a weaker binding, it is an unreadable one,
so it is rejected rather than partially stored.
"""

from __future__ import annotations

from typing import Any

from waxseal_server.domain.errors import MalformedEnvelope
from waxseal_server.domain.identifiers import is_hex64

REQUIRED_FIELDS = ("seq", "entry_hash", "root")
AGGREGATE_FIELDS = ("agg_commit", "agg_epoch")


def parse_checkpoint(body: Any) -> dict[str, Any]:
    if not isinstance(body, dict):
        raise MalformedEnvelope("checkpoint must be a JSON object")
    for name in REQUIRED_FIELDS:
        if name not in body:
            raise MalformedEnvelope(f"checkpoint is missing {name}")

    seq = body["seq"]
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
        raise MalformedEnvelope(f"checkpoint.seq must be a non-negative integer, got {seq!r}")
    for name in ("entry_hash", "root"):
        if not is_hex64(body[name]):
            raise MalformedEnvelope(f"checkpoint.{name} must be 64 lowercase hex characters")

    checkpoint: dict[str, Any] = {
        "seq": seq,
        "entry_hash": body["entry_hash"],
        "root": body["root"],
    }

    present = [name for name in AGGREGATE_FIELDS if name in body]
    if len(present) == 1:
        raise MalformedEnvelope("agg_commit and agg_epoch appear together or not at all")
    if present:
        commit, epoch = body["agg_commit"], body["agg_epoch"]
        if not is_hex64(commit):
            raise MalformedEnvelope("checkpoint.agg_commit must be 64 lowercase hex characters")
        if not isinstance(epoch, int) or isinstance(epoch, bool):
            raise MalformedEnvelope("checkpoint.agg_epoch must be an integer")
        checkpoint["agg_commit"] = commit
        checkpoint["agg_epoch"] = epoch
    return checkpoint
