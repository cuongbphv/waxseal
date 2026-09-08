from __future__ import annotations

import sys
from pathlib import Path


def _receipt_export(trail: Path, *, seq: int | None, out: Path) -> int:
    """Write each stored receipt, and the frame it attests, to files.

    waxseal refuses on principle to verify a CMS signature or an
    OpenTimestamps proof (SPEC.md sections 17/18), so `openssl ts -verify` and
    `ots verify` are the delegated verifiers, and both want FILES. Without
    this command the extraction recipe is hand-written Python against
    internal APIs, which is exactly the kind of incident-hour typing this
    CLI exists to remove.
    """
    from waxseal.adapters.anchors import read_anchor_records
    from waxseal.domain import ots, rfc3161
    from waxseal.domain.checkpoint import checkpoint_frame

    sidecar_file = trail.with_name(trail.name + ".anchors")
    if not sidecar_file.exists():
        # Same contract as a missing trail: nothing read, nothing created,
        # not even --out, so a typo'd path leaves no empty directory that
        # reads as "extraction ran and found nothing".
        print(f"error: no anchor sidecar: {sidecar_file}", file=sys.stderr)
        return 3
    try:
        sidecar = read_anchor_records(trail)
    except (ValueError, KeyError, TypeError):
        # The sidecar is this project's own format: unreadable bytes in it
        # are a break, never a foreign format (`verify --anchors` asymmetry).
        print("error: malformed_anchor — the sidecar could not be read", file=sys.stderr)
        return 1

    written = 0
    used: set[str] = set()
    for record in sidecar.records:
        rseq = record.checkpoint.seq
        if record.receipt is None or (seq is not None and rseq != seq):
            continue
        der = rfc3161.decode_receipt(record.receipt)
        if der is not None:
            payload, ext, kind = der, ".tsr", "RFC 3161 timestamp token"
        else:
            proof = ots.decode_receipt(record.receipt)
            if proof is None:
                # Skipped but never silently (CLAUDE.md rule 6): a receipt
                # type from a newer build, or bytes this build cannot
                # decode, is opaque rather than an error (RFC 6962 section 4.6).
                prefix = record.receipt.split(":", 1)[0]
                print(
                    f"seq={rseq}: receipt type {prefix!r} is not extractable by "
                    "this build — unverifiable by name, NOT evidence of tampering"
                )
                continue
            payload, ext, kind = proof, ".ots", "pending OpenTimestamps proof"

        # Duplicate records at one seq are a supported race (adapters/
        # anchors.py) but their receipts differ, and overwriting one would
        # discard evidence, so collisions get a numbered suffix.
        base, n = f"seq-{rseq}", 2
        while base in used:
            base, n = f"seq-{rseq}-{n}", n + 1
        used.add(base)
        out.mkdir(parents=True, exist_ok=True)
        receipt_path = out / (base + ext)
        receipt_path.write_bytes(payload)
        print(f"wrote {receipt_path} ({kind}, seq={rseq})")
        frame_path = out / (base + ".frame")
        frame_path.write_bytes(checkpoint_frame(record.checkpoint))
        print(f"wrote {frame_path} (checkpoint frame the receipt attests, seq={rseq})")
        written += 1

    if sidecar.unreadable_versions:
        print(
            f"note: {len(sidecar.unreadable_versions)} record(s) in an unreadable "
            "format version — unverifiable by name, NOT evidence of tampering"
        )
    if written == 0:
        # Absence, not success and not a break: no receipt means no
        # third-party evidence was stored, which is unmeasured coverage.
        print(
            "nothing to extract: no stored receipts match — absent receipts are "
            "unmeasured coverage, NOT success and NOT evidence of tampering"
        )
        return 2
    return 0
