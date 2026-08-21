# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | yes |

## Reporting a vulnerability

Report vulnerabilities privately via GitHub Security Advisories: use
"Report a vulnerability" on this repository's Security tab. Do not open a
public issue for a security report.

You should receive an acknowledgment within 7 days.

## What counts as a vulnerability here

waxseal is a tamper-evidence library, so the bar is specific:

- Anything that makes `verify` report a tampered chain as intact
  (false negative), including edge cases in encoding, framing, or
  fingerprint handling.
- A redaction bypass: any path where cleartext secrets reach disk despite a
  configured redactor (redact-before-hash is the design invariant).
- A chain fork under the documented locking rules (concurrent writers both
  extending the same `prev_hash` on JSONL, SQLite, or any other backend).
- Forgeable or re-sealable attestations within the documented forward-secure
  threat model (compromise at epoch *t* must not allow forging seals from
  before *t*).

Out of scope: attacks requiring write access that the documentation already
declares undetectable-by-design (full suffix rewrite without external
anchoring), and false *positives* (those are bugs, report them as issues).
