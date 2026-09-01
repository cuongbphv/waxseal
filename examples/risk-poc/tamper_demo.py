"""Tamper walkthrough: seven attacks, and what each one costs the attacker.

Run `simulate.py` first to produce a trail, then this. Each scenario takes a
fresh copy of that trail, damages it in one specific way, runs the real
verification commands against the copy, and prints the verdict and exit code.
The original is never modified.

The scenarios escalate deliberately. The first four are caught by the chain
alone. The fifth is not — a consistent rewrite of the whole trail is exactly
what a hash chain cannot resist — and needs the anchor. The sixth is not
caught by either and needs the forward-secure seal. The seventh is not an
attack at all, and the point is that it is not reported as one.

    python examples/risk-poc/tamper_demo.py --out examples/poc-out
"""

from __future__ import annotations

import argparse
import base64
import json
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parents[2] / "src"))

from _animate import G, supports_ansi  # noqa: E402

from waxseal.cli import main as waxseal  # noqa: E402

BOLD = "\033[1m"
RESET = "\033[0m"
RED = "\033[31m"
GREEN = "\033[32m"
CYAN = "\033[36m"
DIM = "\033[2m"


@dataclass(frozen=True, slots=True)
class Outcome:
    name: str
    expected: int
    actual: int
    caught_by: str


def colour(text: str, code: str) -> str:
    return f"{code}{text}{RESET}" if supports_ansi() else text


def banner(n: int, title: str, what: str, caught_by: str) -> None:
    print()
    print(colour(f"  {G.h * 68}", DIM))
    print(colour(f"  {n}. {title}", BOLD))
    print(f"     attack     : {what}")
    print(f"     caught by  : {caught_by}")


def run_cmd(argv: list[str]) -> int:
    print(colour(f"     $ waxseal {' '.join(argv)}", CYAN))
    code = waxseal(argv)
    print(colour(f"     exit {code}", GREEN if code else GREEN))
    return code


def load(trail: Path) -> list[dict]:
    return [json.loads(line) for line in trail.read_text().splitlines() if line.strip()]


def save(trail: Path, rows: list[dict]) -> None:
    trail.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")


def copy_case(src_dir: Path, work: Path, name: str) -> Path:
    """A fresh copy per scenario, sidecars included — the original stays intact.

    Copies the flat files only, not the tree: the scenario directories live
    under src_dir themselves, so a recursive copy would descend into the
    copies it is making.
    """
    case = work / name
    if case.exists():
        shutil.rmtree(case)
    case.mkdir(parents=True)
    for path in sorted(src_dir.iterdir()):
        if path.is_file():
            shutil.copy2(path, case / path.name)
    return case / "decisions.jsonl"


def edit_payload(trail: Path, seq: int, old: bytes, new: bytes) -> None:
    """Rewrite stored payload bytes, leaving the envelope itself well-formed."""
    rows = load(trail)
    payload = base64.b64decode(rows[seq]["payload_b64"]).replace(old, new)
    rows[seq]["payload_b64"] = base64.b64encode(payload).decode("ascii")
    save(trail, rows)


def rebuild_chain(rows: list[dict]) -> list[dict]:
    """Relink and re-hash every row so the chain is internally consistent —
    the rewrite an attacker with write access can always perform.

    The frame is dispatched per row by its own `hash_version`, exactly as
    `verify_chain` does: a real attacker re-signs each row under the encoding
    that row declares. Assuming one frame for the whole trail would produce a
    chain whose rows disagree with their own fingerprints — caught instantly
    as `entry_hash_mismatch`, which would make this scenario prove the
    opposite of its point (that a full-write attacker DOES defeat the chain,
    and only the external anchor catches them).
    """
    from waxseal.domain.hashing import compute_entry_hash
    from waxseal.domain.header import GENESIS_PREV_HASH, EntryHeader
    from waxseal.domain.registry import VersionRegistry

    registry = VersionRegistry()
    prev = GENESIS_PREV_HASH
    for seq, row in enumerate(rows):
        row["header"]["seq"] = seq
        row["header"]["prev_hash"] = prev
        row["header"]["payload_hash"] = __import__("hashlib").sha256(
            base64.b64decode(row["payload_b64"])
        ).hexdigest()
        header = EntryHeader(**row["header"])
        frame = registry.encoder_for(header.hash_version)
        row["entry_hash"] = compute_entry_hash(header, frame=frame)
        prev = row["entry_hash"]
    return rows


def scenario_edit(src: Path, work: Path) -> Outcome:
    banner(1, "Edit one decision", "flip a denial into an approval", "the chain")
    trail = copy_case(src, work, "01-edit")
    edit_payload(trail, 2, b'"deny"', b'"allow"')
    return Outcome("edit a decision", 1, run_cmd(["verify", str(trail)]), "chain")


def scenario_delete(src: Path, work: Path) -> Outcome:
    banner(2, "Delete a decision", "remove the escalated row entirely", "the chain (seq gap)")
    trail = copy_case(src, work, "02-delete")
    rows = load(trail)
    save(trail, rows[:3] + rows[4:])
    return Outcome("delete a decision", 1, run_cmd(["verify", str(trail)]), "chain")


def scenario_reorder(src: Path, work: Path) -> Outcome:
    banner(3, "Reorder history", "swap two decisions to change the story",
           "the chain (prev_hash)")
    trail = copy_case(src, work, "03-reorder")
    rows = load(trail)
    rows[2], rows[3] = rows[3], rows[2]
    save(trail, rows)
    return Outcome("reorder history", 1, run_cmd(["verify", str(trail)]), "chain")


def scenario_insert(src: Path, work: Path) -> Outcome:
    banner(4, "Insert a decision after the fact",
           "back-date an approval that was never made", "the chain (prev_hash)")
    trail = copy_case(src, work, "04-insert")
    rows = load(trail)
    rows = rows[:2] + [json.loads(json.dumps(rows[1]))] + rows[2:]
    # Renumber so the seq column is contiguous again. Without this the
    # insertion is caught by the cheaper seq check and never exercises the
    # link itself — an attacker who can insert can certainly count.
    for seq, row in enumerate(rows):
        row["header"]["seq"] = seq
    save(trail, rows)
    return Outcome("insert a decision", 1, run_cmd(["verify", str(trail)]), "chain")


def scenario_whole_rewrite(src: Path, work: Path) -> Outcome:
    banner(
        5, "Rewrite the WHOLE trail consistently",
        "edit a row, then recompute every hash after it so the chain re-links",
        "the anchor (a root published before the edit)",
    )
    trail = copy_case(src, work, "05-rewrite")
    rows = load(trail)
    payload = base64.b64decode(rows[2]["payload_b64"]).replace(b'"deny"', b'"allow"')
    rows[2]["payload_b64"] = base64.b64encode(payload).decode("ascii")
    save(trail, rebuild_chain(rows))

    print(colour("     the chain alone now reports intact — as it must:", DIM))
    chain_only = run_cmd(["verify", str(trail)])
    print(colour("     the anchored root is what the attacker could not rewrite:", DIM))
    with_anchor = run_cmd(["verify", "--anchors", str(trail)])
    return Outcome(
        f"whole-trail rewrite (chain alone: exit {chain_only})",
        1, with_anchor, "anchor",
    )


def scenario_truncate(src: Path, work: Path) -> Outcome:
    banner(
        6, "Truncate the tail, sidecar and all",
        "drop the last decisions and the seals that covered them",
        "the forward-secure seal (a one-way key epoch cannot be rolled back)",
    )
    trail = copy_case(src, work, "06-truncate")
    rows = load(trail)
    save(trail, rows[:3])
    attest = trail.with_suffix(trail.suffix + ".attest")
    lines = attest.read_text().splitlines()
    attest.write_text("\n".join(lines[:3]) + "\n", encoding="utf-8")

    print(colour("     chain + sidecar agree with each other after the cut:", DIM))
    chain_only = run_cmd(["verify", str(trail)])

    from waxseal import AuditLog
    from waxseal.adapters.attest import FileAttestor

    key = (trail.parent / "sealkey.escrow").read_bytes()
    log = AuditLog.open(trail, attestor=FileAttestor(trail, initial_key=key))
    attest_result = log.verify_attestations(initial_key=key)
    print(colour("     $ log.verify_attestations(initial_key=A_0)   # escrowed off-host", CYAN))
    print(f"     ok={attest_result.ok} reason={attest_result.reason}")
    return Outcome(
        f"tail truncation (chain alone: exit {chain_only})",
        1, 0 if attest_result.ok else 1, "forward-secure seal",
    )


def scenario_unknown_schema(src: Path, work: Path) -> Outcome:
    banner(
        7, "A row from a NEWER version of the software",
        "not an attack — a rollback leaves rows this build cannot recompute",
        "nothing: it must be reported unverifiable, NOT tampered (exit 2)",
    )
    trail = copy_case(src, work, "07-unknown-schema")
    from waxseal.domain.hashing import compute_entry_hash
    from waxseal.domain.header import EntryHeader

    rows = load(trail)
    last = rows[-1]  # the tail: nothing downstream depends on its hash
    last["header"]["hash_version"] = "f" * 64
    last["entry_hash"] = compute_entry_hash(EntryHeader(**last["header"]))
    save(trail, rows)
    return Outcome("unknown schema fingerprint", 2, run_cmd(["verify", str(trail)]),
                   "reported as unverifiable, not tampering")


def scenario_proof_bundle(src: Path, work: Path) -> Outcome:
    banner(
        8, "Disclose ONE decision to an auditor",
        "not an attack — answer a question about one customer",
        "a proof bundle: checkable offline, without the rest of the trail",
    )
    trail = copy_case(src, work, "08-proof")
    bundle = trail.parent / "proof-seq3.json"

    import contextlib
    import io

    captured = io.StringIO()
    print(colour(f"     $ waxseal export-proof {trail.name} 3 > proof-seq3.json", CYAN))
    with contextlib.redirect_stdout(captured):
        waxseal(["export-proof", str(trail), "3"])
    bundle.write_text(captured.getvalue(), encoding="utf-8")
    print(f"     bundle: {len(captured.getvalue())} bytes, one entry + its Merkle path")

    trail.unlink()  # the auditor holds the bundle and nothing else
    print(colour("     (trail deleted — the bundle stands on its own)", DIM))
    good = run_cmd(["verify-proof", str(bundle)])

    obj = json.loads(bundle.read_text())
    obj["payload_b64"] = base64.b64encode(b'{"outcome":"approve"}').decode()
    bundle.write_text(json.dumps(obj), encoding="utf-8")
    print(colour("     now tamper with the bundle itself:", DIM))
    bad = run_cmd(["verify-proof", str(bundle)])
    return Outcome(f"proof bundle (valid: exit {good})", 1, bad, "membership proof")


SCENARIOS = [
    scenario_edit,
    scenario_delete,
    scenario_reorder,
    scenario_insert,
    scenario_whole_rewrite,
    scenario_truncate,
    scenario_unknown_schema,
    scenario_proof_bundle,
]


def run(src: Path) -> int:
    trail = src / "decisions.jsonl"
    if not trail.exists():
        print(f"error: no trail at {trail} — run simulate.py --out {src} first", file=sys.stderr)
        return 3
    work = src / "tamper-cases"
    if work.exists():
        shutil.rmtree(work)
    work.mkdir()

    print(colour("\n  waxseal · what each attack costs the attacker", BOLD))
    outcomes = [scenario(src, work) for scenario in SCENARIOS]

    print()
    print(colour(f"  {G.h * 68}", DIM))
    print(colour("  Summary", BOLD))
    failures = 0
    for i, o in enumerate(outcomes, 1):
        ok = o.actual == o.expected
        failures += not ok
        mark = colour(G.check, GREEN) if ok else colour("x", RED)
        print(f"   {mark} {i}. {o.name:<48} exit {o.actual}  ({o.caught_by})")
    print()
    if failures:
        print(colour(f"  {failures} scenario(s) did not behave as documented", RED))
    else:
        print("  Every scenario behaved exactly as the documentation claims.")
    print(
        "\n  What this does NOT show: waxseal is tamper-EVIDENT, not tamper-proof.\n"
        "  An attacker with write access can rewrite the trail; scenarios 5 and 6\n"
        "  are caught only because a root was anchored, and a seal key evolved,\n"
        "  outside that attacker's reach. Anchor somewhere you do not control.\n"
    )
    return 1 if failures else 0


def main(argv: list[str] | None = None) -> int:
    from waxseal.cli import _survive_a_narrow_console

    _survive_a_narrow_console()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("examples/poc-out"),
                        help="the directory simulate.py wrote its trail into")
    args = parser.parse_args(argv)
    return run(args.out.expanduser())


if __name__ == "__main__":
    raise SystemExit(main())
