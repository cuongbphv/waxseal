"""Hard 500-line ceiling on production modules, after the 0.1.6 split.

PEP 8 does not set a line count. Soft 400 is review policy in CONTRIBUTING.md
and is deliberately not a failing test: a module at 400 lines is a question
for the reviewer (one bounded context, or a second seam that landed without
an extract), not an alarm.

Hard 500 is this file. After the split, a production module over 500 lines
fails unless that exact path is on the allowlist with a bounded-context
rationale. The allowlist is a ratchet: a file that drops to 500 or under
must leave it. Named exception kinds: a protocol codec, the argparse table,
a CLI command whose exit semantics are frozen. Remaining entries are
bounded contexts the split left intact because tearing them would fork a
table or an exit mapping.

The scan is recursive (`rglob`) over the library, the server, and the Vue
sources. Tests, generated static, and node_modules are out of scope.
"""

from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
HARD_LIMIT = 500

# Exact paths, POSIX, relative to the repo root. Reasons are the whole
# point: a bare path with no bounded-context rationale is a silent cap.
OVER_LIMIT: dict[str, str] = {
    "src/waxseal/adapters/s3/worm.py": (
        "WORM (subject, state, strength) renderer is one table. Splitting "
        "the table from the parser printed a bucket-level LOCKED as an "
        "object-level guarantee (CLAUDE.md ternary instance 8)."
    ),
    "src/waxseal/cli/_anchors.py": (
        "CLI verify-adjacent checks (anchors, witnesses, receipts) share "
        "one exit mapping. Forking it would let one check print exit 1 "
        "while another prints 2 for the same unread sidecar."
    ),
    "src/waxseal/cli/ledger.py": (
        "ledger-status / registry / bond share reconcile-tickets' exit "
        "convention (0 clean, 1 positively detected, 2 unmeasured). One "
        "CLI surface, frozen by the CLI contract."
    ),
    "src/waxseal/cli/_parser.py": (
        "Argparse table: every subcommand and frozen help string in one "
        "build_parser() artifact."
    ),
    "src/waxseal/cli/pin.py": (
        "CLI pin command: exit 2 advances the pin because unverifiable is "
        "not tampered. Splitting the advance from the comparisons would "
        "fork that contract."
    ),
    "src/waxseal/cli/preflight.py": (
        "CLI preflight: always exit 0 except trail-absent 3. The rung "
        "table is one reading, not a verdict."
    ),
    "src/waxseal/domain/incident.py": (
        "Domain scan/window after the render extract. One evidence "
        "dimension (Decree reporting window); splitting it would fork the "
        "window arithmetic from the record."
    ),
}

_TREES = (
    REPO / "src" / "waxseal",
    REPO / "server" / "waxseal_server",
    REPO / "server" / "web" / "src",
)

_SOURCE_SUFFIXES = {".py", ".ts", ".vue"}


def production_files() -> list[Path]:
    files: list[Path] = []
    for tree in _TREES:
        if not tree.is_dir():
            continue
        for path in tree.rglob("*"):
            if not path.is_file() or path.suffix not in _SOURCE_SUFFIXES:
                continue
            if "node_modules" in path.parts:
                continue
            if path.name.endswith(".spec.ts"):
                continue
            files.append(path)
    return files


def line_count(path: Path) -> int:
    return len(path.read_text(encoding="utf-8").splitlines())


def _rel(path: Path) -> str:
    return path.relative_to(REPO).as_posix()


def test_no_production_module_exceeds_500_without_an_allowlist_entry() -> None:
    offenders: list[str] = []
    for path in production_files():
        n = line_count(path)
        if n <= HARD_LIMIT:
            continue
        rel = _rel(path)
        if rel not in OVER_LIMIT:
            offenders.append(f"{rel}: {n}")
    assert offenders == [], (
        "production module over 500 lines with no allowlist rationale "
        "(add an exact-path entry with a bounded-context reason, or split):\n"
        + "\n".join(offenders)
    )


def test_allowlist_entries_still_exceed_the_hard_limit() -> None:
    stale: list[str] = []
    for rel, reason in OVER_LIMIT.items():
        path = REPO / rel
        assert path.is_file(), f"allowlist names a missing file: {rel}"
        assert reason.strip(), f"{rel} has an empty rationale"
        n = line_count(path)
        if n <= HARD_LIMIT:
            stale.append(f"{rel}: {n}")
    assert stale == [], (
        "allowlist is a ratchet: a file at or under 500 must leave it:\n"
        + "\n".join(stale)
    )
