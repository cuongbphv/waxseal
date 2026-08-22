# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.2] - 2026-08-22

### Added

- `RemoteBackend`: an HTTP peer to JSONL/SQLite/S3 speaking a small wire contract
  (`REMOTE.md`) over an injected `Transport` (stdlib `urllib` by default, zero new
  runtime dependencies). `AuditLog.open("http://...")`/`"https://..."` dispatches to
  it automatically; the CLI accepts a URL target for `verify`, `tail`, `inspect`,
  `head`, and `checkpoint` (`anchor` is refused for a URL target — no local sidecar
  location to write to). Credentials are read only from `WAXSEAL_API_KEY`, never
  from argv or the URL itself. The server is a trusted writer, not a
  Byzantine-fault-tolerant peer — `REMOTE.md` states this as the wire contract's
  first normative fact, and independent head anchoring is the documented
  mitigation.
- Merkle consistency proofs (RFC 9162 §2.1.4): `consistency_proof`/
  `verify_consistency` in `domain/anchoring.py`, alongside the existing batch-root
  membership proofs — checking that a later chain head extends an earlier one
  without replaying the whole log.
- `Checkpoint(seq, entry_hash, root)` (`domain/checkpoint.py`) and `waxseal
  checkpoint`: a bytes-only snapshot an external anchor sink can witness.
- Automatic anchoring: `AuditLog(anchor_sink=..., anchor_every=N)` publishes a
  checkpoint every `N` entries, best-effort and outside the append critical
  section. `FileAnchorSink` (local `.anchors` sidecar) and `HTTPAnchorSink`
  (POSTs to an external service over the same `Transport`) both implement the new
  `AnchorSink` port. `waxseal anchor` and `waxseal verify --anchors` are new CLI
  commands.
- `fs-hmac-agg-sha256-v1`: an opt-in FssAgg-style aggregate attestation scheme
  (Ma-Tsudik) that folds every per-entry seal into one KEYED running accumulator
  (`.sealagg`, replace-only, latest value only), closing the gap where an
  untrusted keyfile alone cannot prove a truncated tail was never dropped.
- Drop-count completeness measurement: an optional `.drops` sidecar
  (`record_drops=True`) reports a measured minimum of dropped writes independent
  of the current process, surfaced by `verify`/`inspect` as `dropped_writes >= N`
  — never conflating "not measured" (`None`) with "measured zero" (`0`).
- `s3` and `postgres` optional extras in `pyproject.toml` (pull in a compatible
  injected client for callers who want one; waxseal itself still imports neither).

### Fixed

- `__init__.py`'s public-API docstring referenced a nonexistent
  `test_public_api.py`; corrected to `tests/architecture/test_invariants.py`.

## [0.1.1] - 2026-08-21

### Fixed

- Windows: `waxseal install` wrote hook/plugin shims with the locale codec
  (cp1252), which encoded the shims' em dashes as `0x97`; Python requires
  UTF-8 source, so the installed hermes plugin failed to import with a
  `SyntaxError`. Shims are now written and compared as UTF-8 with `\n`
  newlines on every platform.
- Windows: the Claude Code / Codex / Cursor hook scripts resolved the default
  trail location via `Path.home()`, which ignores `HOME` on Windows
  (`USERPROFILE` wins); a host launching the hook with `HOME` set stranded
  the trail in the wrong profile. `HOME` is now honored first.
- Repository: added `.gitattributes` (LF + `tests/vectors/** -text`) so
  `core.autocrlf=true` checkouts no longer rewrite the golden vector bytes
  and trip the write-once freeze guard with a false "vectors changed".

## [0.1.0] - 2026-08-21

### Added

- Envelope-based SHA-256 audit hash chain: only the fixed `EntryHeader` is chained,
  payloads are referenced by `payload_hash`.
- Automatic schema fingerprints (`hash_version`) with an append-only registry;
  unknown fingerprints report as unverifiable-by-name, never as tampered.
- Storage backends: JSONL, SQLite, in-memory, S3 (injected boto3 client),
  PostgreSQL (injected psycopg connection), each with fork-proof concurrent appends.
- Redact-before-hash: redaction runs before `payload_hash` is computed, so cleartext
  secrets never reach disk.
- Forward-secure sealing (key-evolving HMAC, stdlib only) and injected digital
  signatures via the `.attest` attestation sidecar.
- CLI: `waxseal verify` (exit 0/1/2), `tail`, `inspect`, `head`.
- Integrations for seven agent frameworks and coding tools: Claude Code, Codex CLI,
  Cursor, LangChain/LangGraph, CrewAI, OpenAI Agents SDK, hermes-agent.
- `dropped_writes` completeness reporting, separate from chain integrity
  (`None` = not measured, never conflated with `0`).
