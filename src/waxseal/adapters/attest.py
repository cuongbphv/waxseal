"""FileAttestor: sidecar attestation storage + epoch key management.

Attestations live OUTSIDE the entry envelope, in `<trail>.attest` (one JSON
object per line), so no backend schema changes and mixed old/new logs stay
readable. The evolving seal key lives in `<trail>.sealkey` (0600), atomically
replaced on every append so only the CURRENT epoch key exists on disk —
forward security rests on old keys being gone.

Signature frame: signers sign SEAL_FRAME_PREFIX + entry_hash bytes — the same
domain-separated frame the HMAC seals use.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from pathlib import Path

from waxseal.adapters.atomic import atomic_write_bytes
from waxseal.domain.sealing import (
    FS_HMAC_SCHEME,
    SEAL_FRAME_PREFIX,
    Attestation,
    evolve_key,
    seal_entry,
)
from waxseal.ports.sign import Signer


class FileAttestor:
    def __init__(
        self,
        trail_path: Path | str,
        *,
        initial_key: bytes | None = None,
        signer: Signer | None = None,
    ) -> None:
        if (initial_key is None) == (signer is None):
            raise ValueError("provide exactly one of initial_key (fs-hmac) or signer")
        trail = Path(trail_path).expanduser()
        self._attest_path = trail.with_name(trail.name + ".attest")
        self._key_path = trail.with_name(trail.name + ".sealkey")
        self._signer = signer
        if initial_key is not None and not self._key_path.exists():
            self._write_key(0, initial_key)

    # -- called by AuditLog after a successful append --------------------------
    def attest(self, seq: int, entry_hash: str) -> Attestation:
        if self._signer is not None:
            frame = SEAL_FRAME_PREFIX + entry_hash.encode("ascii")
            att = Attestation(
                seq=seq,
                entry_hash=entry_hash,
                scheme=f"sig-{self._signer.algorithm}-v1",
                value=self._signer.sign(frame).hex(),
                key_id=self._signer.key_id,
            )
        else:
            epoch, key = self._read_key()
            if epoch != seq:
                # A gap means seals and entries desynced (e.g. a crash between
                # append and attest). Refuse to silently re-align: sealing a
                # different epoch than the key's would forge history.
                raise RuntimeError(
                    f"seal epoch {epoch} != entry seq {seq}; attestation sidecar "
                    "is out of sync with the trail — operator decision required"
                )
            att = Attestation(
                seq=seq,
                entry_hash=entry_hash,
                scheme=FS_HMAC_SCHEME,
                value=seal_entry(key, entry_hash),
            )
            self._write_key(epoch + 1, evolve_key(key))
        obj: dict[str, object] = {
            "seq": att.seq,
            "entry_hash": att.entry_hash,
            "scheme": att.scheme,
            "value": att.value,
        }
        if att.key_id is not None:
            obj["key_id"] = att.key_id
        line = json.dumps(obj, sort_keys=True, separators=(",", ":"))
        # 0600 like the trail and the sealkey — a default umask would expose
        # the sidecar to every local user.
        fd = os.open(self._attest_path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8", newline="") as f:
            f.write(line + "\n")
            f.flush()
        return att

    def attestations(self) -> Iterator[Attestation]:
        if not self._attest_path.exists():
            return
        with open(self._attest_path, encoding="utf-8", newline="") as f:
            for line in f:
                if line.strip():
                    obj = json.loads(line)
                    yield Attestation(
                        seq=int(obj["seq"]),
                        entry_hash=str(obj["entry_hash"]),
                        scheme=str(obj["scheme"]),
                        value=str(obj["value"]),
                        key_id=obj.get("key_id"),
                    )

    def check_continuity(self, initial_key: bytes, attestation_count: int) -> str | None:
        """Truncation detection (Ma-Tsudik attack): the keyfile epoch is
        one-way, so an attacker who truncates trail+sidecar cannot roll the
        keyfile back — A_{t'} is not computable from A_t. Returns a reason
        string on mismatch, None when continuous."""
        if self._signer is not None:
            return None  # signer mode has no evolving keyfile
        if not self._key_path.exists():
            return "keyfile_missing"
        epoch, key = self._read_key()
        if epoch != attestation_count:
            return "keyfile_epoch_mismatch"
        expected = initial_key
        for _ in range(epoch):
            expected = evolve_key(expected)
        if expected != key:
            return "keyfile_key_mismatch"
        return None

    # -- key file ---------------------------------------------------------------
    def _read_key(self) -> tuple[int, bytes]:
        obj = json.loads(self._key_path.read_text(encoding="utf-8"))
        return int(obj["epoch"]), bytes.fromhex(obj["key"])

    def _write_key(self, epoch: int, key: bytes) -> None:
        # Atomic replace so a crash never leaves a half-written key, and the
        # old epoch key does not linger in the visible file. (Python cannot
        # zeroize memory or guarantee the old file's blocks are unrecoverable
        # at the storage layer — documented limit, DESIGN.md §6.)
        atomic_write_bytes(
            self._key_path, json.dumps({"epoch": epoch, "key": key.hex()}).encode("ascii")
        )
