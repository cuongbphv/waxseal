"""Checkpoints deposited with a witness, one append-only file per witness id.

A witness answers what it was told, in the order it was told. It never re-sorts
and never de-duplicates: two identical checkpoints posted twice are two
observations, and collapsing them would let the witness quietly answer a
question it was never asked.

Running a witness in the same process as the chain it witnesses proves nothing
(REMOTE.md sections 7 and 8), and no code here can make it prove something. It
exists so an operator can host a witness for *someone else's* chain.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

from waxseal_server.domain.identifiers import require_witness_id


class WitnessStore:
    def __init__(self, root: Path | str) -> None:
        self._root = Path(root).expanduser()

    def path(self, witness_id: str) -> Path:
        return self._root / f"{require_witness_id(witness_id)}.jsonl"

    def record(self, witness_id: str, checkpoint: dict[str, Any]) -> str:
        path = self.path(witness_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        receipt = uuid.uuid4().hex
        stored = {**checkpoint, "receipt": receipt}
        with open(path, "a", encoding="utf-8", newline="") as handle:
            handle.write(json.dumps(stored, sort_keys=True, separators=(",", ":")) + "\n")
            handle.flush()
        return receipt

    def checkpoints(self, witness_id: str) -> list[dict[str, Any]]:
        path = self.path(witness_id)
        if not path.exists():
            return []
        return [
            json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
