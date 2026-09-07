# Contributing to waxseal

[CLAUDE.md](CLAUDE.md) is the engineering constitution for this repository. It is
authoritative; this file is the short version. When in doubt, CLAUDE.md wins.

## Dev setup

```bash
uv sync --extra dev
uv run pytest --cov=waxseal
```

## Rules that will get a PR rejected

- **TDD is mandatory** (CLAUDE.md): no production code without a failing test first.
  Bug fix = failing repro test first, in the same PR.
- **Coverage floor: 100%** line and branch coverage over `src/waxseal`
  (`fail_under = 100`). It is a ratchet: it may go up, never down.
  The floor is a ratchet - it may go up, never down.
- **Zero runtime dependencies.** `[project] dependencies` stays `[]`. Optional
  clients (boto3, psycopg) are injected by the caller, never imported by waxseal.
- **Frozen paths** - do not edit without explicit owner instruction:
  - `SPEC.md` (after v1 freeze)
  - `tests/vectors/**`
  - `src/waxseal/domain/fingerprint.py`
  - `CLAUDE.md`
  - `LICENSE`
- **Append-only registry and vectors.** A new field set = a new descriptor = a new
  fingerprint entry; never edit a released descriptor. Golden vectors may be added,
  never edited or deleted - a frozen-hash test failure means stop, not "update the
  vector".

## Before opening a PR

```bash
uv run pytest --cov=waxseal   # all green, coverage 100%
uv run mypy                   # strict mode, configured in pyproject
uv run ruff check .
```

Commit messages: conventional and plain - say what changed and why, one change per
commit where practical.
