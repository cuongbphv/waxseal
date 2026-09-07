"""S3 backend: object per entry, forks prevented by conditional writes.

The client is INJECTED (any boto3-compatible object): waxseal keeps zero
runtime dependencies (CLAUDE.md rule 1) and never imports boto3 at module
scope. The one place boto3 is imported at all is inside
``_resolve_client``, and its absence is a reported state, never a crash.

Serialization point: `PUT entries/{seq}.json` with `IfNoneMatch="*"`, which S3
conditional writes (GA since 2024) reject the second writer of the same seq
with 412 PreconditionFailed, so a lost race is retried on a fresh tail
instead of forking the chain (CLAUDE.md rule 7). `head.json` is only a
tail-discovery hint; correctness never depends on it.
"""

from __future__ import annotations

import contextlib
import json
from collections.abc import Callable, Iterator
from typing import Any

from waxseal.adapters._envelope import from_obj, to_obj
from waxseal.adapters.s3._errors import _is_not_found, _is_precondition_failed
from waxseal.domain.header import GENESIS_PREV_HASH, Entry

_MAX_RACE_RETRIES = 32
_SEQ_WIDTH = 20  # zero-padded so lexicographic key order == numeric seq order


class S3Backend:
    def __init__(self, client: Any, *, bucket: str, prefix: str) -> None:
        self._client = client
        self._bucket = bucket
        self._prefix = prefix.rstrip("/")

    # -- keys -----------------------------------------------------------------
    def _entry_key(self, seq: int) -> str:
        return f"{self._prefix}/entries/{seq:0{_SEQ_WIDTH}d}.json"

    def _head_key(self) -> str:
        return f"{self._prefix}/head.json"

    # -- backend protocol -----------------------------------------------------
    def append(self, build: Callable[[int, str], Entry]) -> Entry:
        for _ in range(_MAX_RACE_RETRIES):
            next_seq, prev_hash = self._tail()
            entry = build(next_seq, prev_hash)
            body = json.dumps(to_obj(entry, backend="S3"), sort_keys=True, separators=(",", ":"))
            try:
                self._client.put_object(
                    Bucket=self._bucket,
                    Key=self._entry_key(next_seq),
                    Body=body.encode("utf-8"),
                    IfNoneMatch="*",
                )
            except Exception as exc:
                if _is_precondition_failed(exc):
                    continue  # lost the race: re-read the tail and rebuild
                raise
            # Best-effort hint only: a stale head is corrected by probing.
            with contextlib.suppress(Exception):
                self._client.put_object(
                    Bucket=self._bucket,
                    Key=self._head_key(),
                    Body=json.dumps(
                        {"seq": entry.header.seq, "entry_hash": entry.entry_hash}
                    ).encode("utf-8"),
                )
            return entry
        raise RuntimeError(
            f"append lost the conditional-write race {_MAX_RACE_RETRIES} times; "
            "writer contention is pathological"
        )

    def entries(self) -> Iterator[Entry]:
        prefix = f"{self._prefix}/entries/"
        token: str | None = None
        while True:
            kwargs: dict[str, Any] = {"Bucket": self._bucket, "Prefix": prefix}
            if token is not None:
                kwargs["ContinuationToken"] = token
            page = self._client.list_objects_v2(**kwargs)
            for item in page.get("Contents", []):
                body = self._client.get_object(Bucket=self._bucket, Key=item["Key"])
                yield from_obj(json.loads(body["Body"].read()))
            if not page.get("IsTruncated"):
                return
            token = page["NextContinuationToken"]

    # -- tail discovery ---------------------------------------------------------
    def _tail(self) -> tuple[int, str]:
        candidate = -1
        entry_hash = GENESIS_PREV_HASH
        try:
            head = json.loads(
                self._client.get_object(Bucket=self._bucket, Key=self._head_key())[
                    "Body"
                ].read()
            )
            candidate, entry_hash = int(head["seq"]), str(head["entry_hash"])
        except Exception:  # noqa: S110 - no head yet, or unreadable: probe from genesis
            pass
        # The head hint may lag behind winners of earlier races: probe forward.
        seq = candidate
        while True:
            try:
                body = self._client.get_object(Bucket=self._bucket, Key=self._entry_key(seq + 1))
            except Exception as exc:
                if _is_not_found(exc):
                    return seq + 1, entry_hash
                raise
            obj = json.loads(body["Body"].read())
            seq += 1
            entry_hash = str(obj["entry_hash"])

