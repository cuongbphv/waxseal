## What / why

<!-- One or two sentences. -->

## Checklist

- [ ] Failing test written first (TDD — see CLAUDE.md)
- [ ] `uv run pytest --cov=waxseal` green, coverage 100%
- [ ] `uv run mypy` and `uv run ruff check .` clean
- [ ] No new runtime dependencies (`[project] dependencies` stays `[]`)
- [ ] No edits to frozen paths (SPEC.md after freeze, tests/vectors/**,
      src/waxseal/domain/fingerprint.py, CLAUDE.md, LICENSE)
