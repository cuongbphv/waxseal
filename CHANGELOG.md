# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
