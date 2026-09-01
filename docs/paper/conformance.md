# Paper conformance ledger

An independent arXiv-style re-analysis of waxseal (written against v0.1.3) proved a set of
results about this library, proposed a set of constructions, prescribed an eight-item
evaluation protocol, and reported two findings. Release 0.1.4 acted on some of it.

This document says which parts, and — the part that is easy to leave out — which parts not.
It exists because the 0.1.4 changelog's own "Not implemented in this release" section names
three items, and three is not the whole residue. A release note that lists the *declared*
future work but omits the *undeclared* future work reports an absence of coverage as
coverage, which is the one thing this library exists not to do.

The paper's source is deliberately not in this repository (see `.gitignore`: it is an input
to 0.1.4, not something waxseal ships). Rows below cite it by section and by the name it
gives each result, so a reader holding the paper can follow along without it.

## How to read a row

Every row carries a status and, where the status is about code, a path you can open.

| Status | Meaning |
|---|---|
| **[Shipped]** | Implemented, reachable from a shipped command or the frozen public API, with tests |
| **[Partial]** | Implemented in part; the row names exactly what is missing |
| **[Written, unwired]** | The code exists and is tested, but no shipped code path calls it |
| **[Not built]** | No implementation |
| **[Out of scope]** | Deliberately not built; the row names the constraint that decides it |

**[Written, unwired]** is not a synonym for [Shipped] and is the reason this ledger exists
in a repository that already has 100% line and branch coverage. Coverage measures whether a
line ran under test. It does not measure whether any shipped code path reaches it. A
function can sit at 100% and still be unreachable by every operator who installs the wheel.

## 1. Findings

| # | Finding | Status | Evidence |
|---|---|---|---|
| F1 | Canonical encoding conditionally injective — `enc(⊥)` was `\x00NULL\x00`, itself valid UTF-8, so absence and one specific string encoded alike | **[Shipped]** | lp64 puts a type tag inside the length-prefixed region: [`domain/hashing.py`](../../src/waxseal/domain/hashing.py), properties in [`tests/domain/test_properties.py`](../../tests/domain/test_properties.py) |
| F2 | Anchoring-policy downgrade — nothing in the verifier's own authority recorded that a trail was supposed to anchor with an aggregate binding | **[Shipped]** | `expect_anchor_binding` on the pin state, reason `anchor_policy_downgrade` at exit 2; SPEC section 13.1 |

The paper marked F1 **[Code]** and F2 **[Inference]**. F2 is demonstrated as of 0.1.4.

## 2. Formal results

The paper proves these; the question here is only whether this repository asserts them
executably, which is a different and weaker question than whether they are true.

| Result | Executable assertion | Status |
|---|---|---|
| Collapse theorem (ternary evidential state) | Named in `CLAUDE.md`; its instances are tested individually, the theorem itself is doctrine, not a test | **[Shipped]** as doctrine |
| Unique decodability / frame injectivity | Property tests over `lp()` and the frame, including the lone-surrogate case | **[Shipped]** — gap G4 closed |
| Anchored chain determinism | Golden vectors plus their independent cross-check scripts in [`tools/`](../../tools/) | **[Shipped]** |
| Structural vs procedural schema safety | The fingerprint mechanism ships, and the experiment that *separates the three verifier designs on identical data* now runs on every test run | **[Shipped]** — see protocol item 8 |
| Knowledge monotonicity, and the necessity of the linkage clause | Full-subset rollback matrix with a falsifiability receipt | **[Shipped]** — [`tests/domain/test_knowledge_monotonicity.py`](../../tests/domain/test_knowledge_monotonicity.py) |
| Exogeneity necessity, decidability split | Argued in [`docs/security/threat-model.md`](../security/threat-model.md); a negative result has no positive test | **[Shipped]** as prose |
| Tightness, and the cost of "absolute" | τ is computed and reported (`waxseal verify`, `waxseal report`) | **[Shipped]** — gap G1 closed |
| Truncation and the aggregate residual | Sealing and anchored-aggregate tests | **[Shipped]** |
| Coverage impossibility | `dropped_writes: int \| None` and the `.drops` sidecar | **[Shipped]**; the positive-detection construction (admission tickets) is now **[Shipped]** too — see section 3 |
| Liveness separation of a contract from a timestamp | `anchor_stale` gives the verifier-side half; `AnchoringLiveness.sol` + `waxseal ledger-status` give the publicly-checkable half | **[Shipped]** — see section 3 |
| Optimal cadence, flatness, fleet dividend | `domain/cadence.py`'s closed form, wired into `waxseal cadence` | **[Shipped]** — see section 3 |

## 3. Constructions

| Construction | Paper section | Status | Note |
|---|---|---|---|
| Exogenous admission tickets | Coverage | **[Shipped]** | The only mechanism in the paper that turns a dropped write into a *positively detected* one. [`domain/tickets.py`](../../src/waxseal/domain/tickets.py) (`Ticket`, `scan_tickets`, `reconcile_tickets`, `render_reconciliation`) is wired read-only into `waxseal reconcile-tickets <trail> --issuer NAME --lease-size L [--issued SPEC]` (waxseal-sv1): a missing issued ticket is reported *positively detected*, never a measured minimum; the still-open lease window's blind-spot bound (`L-1`) is always stated, never silently read as "clean"; an unreachable issuer (`--issued` omitted) reports `measured=False`, distinct from "0 drops" (rule 5). The issuer itself is the operator's to run — waxseal only carries and reconciles tickets, never mints them |
| Anchoring liveness contract | Contract layer | **[Shipped]** | `ports/ledger.py` + `domain/liveness.py` (F1, `26b074c`); `contracts/src/AnchoringLiveness.sol` — writer-signed heads only, strictly increasing `seq`, an RFC 9162 consistency proof gating every submit after the first so a rewritten history cannot keep anchoring (F2, `c21e0e6`); `adapters/evm.py::EvmLedgerReader`/`EvmLedgerSink`/`EvmAnchorSink` over stdlib JSON-RPC (F3, `20f2762`); `waxseal ledger-status --liveness`, `verify`/`report --liveness`, `anchor --evm-liveness` (F4, `26e3e91`). An UNINVOLVED third party can now evaluate delinquency without the operator's cooperation, closing exactly the half this row used to name as missing — real end-to-end evidence against two live anvil chains: [`tests/adapters/test_evm_anvil.py`](../../tests/adapters/test_evm_anvil.py) (adapter-level) and, driving the actual `waxseal` CLI as a subprocess, [`tests/test_cli_ledger_e2e_anvil.py`](../../tests/test_cli_ledger_e2e_anvil.py) (F5, this ledger). **Gap stated at ship time, since closed** (waxseal-fg4.45, closed by `b63c461` + `83d51a2`): F4 shipped the ledger dimension as an independent `_Check` — the same shape `_anchor_check`/`_receipts_check` already have, with faithful exit-2 CLI semantics — rather than wiring it into `SeparationTopology`/`declared_topology` as the original plan's prose describes, so a configured `--liveness` check did not, at F4 time, raise τ. Closed: `SeparationTopology.ledger: bool | None` now counts toward τ and `waxseal preflight` reports it, `--declare-topology` accepts a `ledger=` subfield, and SPEC §13.1's grammar was appended for it in `8acffda` |
| Bonded equivocation contract | Contract layer | **[Shipped]** | `domain/bond.py` (`EquivocationProof`, `NonExtensionProof`, `checkpoint_signing_digest` — F1); `contracts/src/BondedCheckpoints.sol` slashes on two `ecrecover`s for equivocation (self-contained positive evidence) and on a POSITIVE divergent leaf for non-extension, deliberately never on a consistency proof that merely fails to verify — a design departure from the original plan's signature, accepted because slashing on a failing proof would let anyone empty an honest writer's bond for the price of gas (F2, `c21e0e6`); `EvmLedgerSink.submit_fraud_proof`/`submit_non_extension` (F3); `waxseal bond deposit`/`bond prove` (F4). Real end-to-end evidence: [`tests/adapters/test_evm_anvil.py::TestTheBond`](../../tests/adapters/test_evm_anvil.py) and, driving `bond deposit` then `bond prove` on a fabricated equivocation as real CLI subprocesses against two live anvil chains, [`tests/test_cli_ledger_e2e_anvil.py::TestBondViaCli::test_deposit_then_prove_equivocation_slashes_the_bond`](../../tests/test_cli_ledger_e2e_anvil.py) — asserts both the raw on-chain `bondOf` state (slashed, amount zeroed) and the same fact read back through `ledger-status --bond` (exit 1, reason `bond_slashed`). Scope unchanged from the paper: this makes ONE specific dishonesty expensive once caught; it does not make equivocation impossible and does not detect a writer that simply never contradicts itself |
| On-chain append-only fingerprint registry | Contract layer | **[Shipped]** | `contracts/src/FingerprintRegistry.sol` computes `fp = sha256(descriptor)` ON CHAIN and refuses a duplicate — no owner, no constructor, no update/pause/upgrade path, verified against the DEPLOYED bytecode (an opcode walk for `DELEGATECALL`/`CALLCODE`/`SELFDESTRUCT`), not merely the source (F2, `c21e0e6`); `domain/registry.py::RegistryCrossCheck`/`descriptor_frame`/`decode_descriptor` (F1); `EvmLedgerReader.registry_lookup`/`registry_agreement` (F3); `waxseal registry publish`, `ledger-status --registry`, `verify`/`report --registry` (F4). Real end-to-end evidence: [`tests/adapters/test_evm_anvil.py::TestTheRegistry`](../../tests/adapters/test_evm_anvil.py) and, publishing via a real CLI subprocess and producing a genuine two-endpoint eclipse-shaped disagreement between two live anvil chains, [`tests/test_cli_ledger_e2e_anvil.py::TestRegistryPublishAndCrossCheckViaCli`](../../tests/test_cli_ledger_e2e_anvil.py). Removes exactly the caveat this row used to name: poisoning an entry now needs a SHA-256 collision or control of the chain, not merely local file write access. **Gap stated at ship time, since closed** (waxseal-fg4.44, closed by `081eab3` + `608775c`): `domain/registry.py`'s vocabulary at F-time merged "the fingerprint is absent from the registry" and "the registry was unreachable" into one status (`REGISTRY_UNREACHABLE`, reason `registry_absent_or_unreachable`), so `ledger-status`/`verify --registry` could not report the two as the distinct facts they are — flagged independently by both F3 and F4, who each correctly declined to work around a domain-level vocabulary decision in adapter/CLI code. Closed: the domain now reports four statuses (`agrees`/`disagrees`/`absent`/`unreachable`), with `registry_fingerprint_not_registered` and `registry_could_not_be_read` as distinct reasons, folded into Ternary instance 13 |
| Cost-optimal anchoring | Cost | **[Shipped]** | Closed form, convexity, the flatness bound, and the √M fleet dividend are arithmetic over operator-supplied parameters in [`domain/cadence.py`](../../src/waxseal/domain/cadence.py) ([`tests/domain/test_cadence.py`](../../tests/domain/test_cadence.py)), wired read-only into `waxseal cadence` — no positional trail argument, opens no trail — which prints `N*`, the clamped `N_opt`, the `[lam*delta, lam*t_max]` clamp bounds, the balance-property terms, a recommended *band* around `N_opt` (not a bare point, per `flatness_bound`), and a labelled "wrong anchor technology, not cadence" message when `delta > t_max` ([`tests/test_cli_cadence.py`](../../tests/test_cli_cadence.py), waxseal-8nw) |
| Cross-trail handoff binding, transitive anchoring | Multi-agent chains | **[Shipped]** | [`domain/handoff.py`](../../src/waxseal/domain/handoff.py) (`HandoffBinding`, `binding_holds`) and [`sources/handoff.py`](../../src/waxseal/sources/handoff.py) (`record_handoff`) are built and fully tested (waxseal-otj) — see gap G5, now closed by waxseal-9al.2. `record_handoff` calls `log.append`, so per CLAUDE.md's CLI contract ("the CLI never appends chain entries") it can never be CLI-wired — the same convention that already keeps `record_decision`/`record_file`/`generate_key` CLI-unwired; README.md/.vi.md/.zh.md's "Cross-trail handoff binding" section now documents `record_handoff` as a library call the operator's own code imports directly, matching those three's existing treatment. `binding_holds` is pure and read-only, so it CAN be CLI-wired without touching that rule: `waxseal verify-handoff <delegate-trail> --origin <origin-trail>` (`tests/test_cli_verify_handoff.py`) now scans a delegate trail for handoff-binding entries and checks each against an origin trail's current `entry_hashes()`, the same pattern `verify_membership`/`verify_consistency` already established via `waxseal consistency` |

Two of the three [Out of scope] rows the 0.1.4 changelog originally declared, plus the one [Partial]
contract-layer row, are now [Shipped]: 0.1.5's Workstream F built all three on-chain constructions the
paper described as "designed and analysed, not implemented" — chain-agnostic behind `ports/ledger.py`,
EVM the first adapter, read path stdlib-only (`eth_call`), write path through an operator-injected
`Signer` (CLAUDE.md rule 1 untouched). Real Foundry contracts, real anvil end-to-end evidence at both
the adapter layer and, new in this release, the actual CLI driven as a subprocess against two live
chains — see each row's Note above and section 5's G6 for the two deviations this shipped WITH,
recorded rather than smoothed over. The remaining rows shipped earlier, after 0.1.4's own release,
once this ledger already existed to record each gap: cost-optimal anchoring (waxseal-cmk,
waxseal-8nw) and admission tickets (waxseal-sv1) are fully [Shipped] and reachable from a real CLI
command; cross-trail handoff binding (waxseal-otj) reached [Shipped] in two different ways for its two
halves — `record_handoff` via README documentation of a by-design CLI-unreachable library call,
`binding_holds` via a new read-only CLI command — closing gap G5 (waxseal-9al.2).

## 4. Evaluation protocol

The paper states eight items and says plainly that its empirical half was not executed.
All eight are done.

| # | Item | Status | Evidence |
|---|---|---|---|
| 1 | Independent reimplementation from specification prose, cross-checked on 10⁶ random headers | **[Shipped]** | [`tests/domain/test_differential.py`](../../tests/domain/test_differential.py) drives [`tools/gen_vectors.py`](../../tools/gen_vectors.py)'s independent reimplementation against `domain/hashing.py` over a seeded, reproducible sweep of random `EntryHeader`-shaped inputs on every push/PR, at a REDUCED N documented and printed in-file — a lowered bound stated, not a silent cap (CLAUDE.md rule 6). [`.github/workflows/differential-nightly.yml`](../../.github/workflows/differential-nightly.yml) runs the identical test function at the paper's full N=1,000,000 on a weekly schedule; both tiers share one harness, only N differs. Falsifiability receipt: an ad hoc one-byte mutation of the independent encoder's type tag turned the sweep red at iteration 0; reverting it turned the sweep green again (bead waxseal-jsk) |
| 2 | Property-based tests for the encoding lemma, generators including the sentinel string, lone surrogates, and null bytes | **[Shipped]** | [`tests/domain/test_properties.py`](../../tests/domain/test_properties.py)'s `test_lone_surrogate_raises_named_encoding_error` (waxseal-08c) adds a dedicated lone-surrogate strategy (`_lone_surrogate_char`, `_text_with_lone_surrogate`) alongside the pre-existing sentinel-shape and null-byte generators, and asserts `lp()` raises a named `LpEncodingError` — decided and asserted, not left undefined. Gap G4 closed |
| 3 | Rollback matrix asserting no transition into broken for any registry subset | **[Shipped]** | Full `itertools.combinations`, no sampling, plus a falsifiability receipt |
| 4 | Falsifiability receipts for concurrency and the anchored aggregate | **[Shipped]** | Pre-existing repository practice; the paper regards it as a contribution in its own right |
| 5 | Fault injection between dependent sidecar writes, asserting a labelled mismatch rather than a crash or a silent pass | **[Shipped]** | [`tests/test_sealed_log.py`](../../tests/test_sealed_log.py)'s `TestFaultInjectionBetweenDependentSidecarWrites` and [`tests/test_anchored_aggregate_log.py`](../../tests/test_anchored_aggregate_log.py)'s `TestFaultInjectionBetweenAnchorsAndSealagg` monkeypatch real write calls to crash at each boundary between two dependent sidecar writes and confirm every one converges on the same labelled verdict, never a silent pass and never an unhandled crash. Found and fixed a real bug along the way: a malformed `.sealagg` at anchor-time raised a bare `JSONDecodeError` three frames down; `AuditLog._aggregate_binding` now catches it and re-raises a labelled `RuntimeError` naming `.sealagg` as malformed (CLAUDE.md rule 6) |
| 6 | Adversarial mutation testing over single-record mutations, measuring detection rate and reason accuracy **separately** | **[Shipped]** | [`tests/domain/test_mutation_campaign.py`](../../tests/domain/test_mutation_campaign.py): 53 in-scope single-record mutations across 7 classes (edit/delete/insert/reorder, corrupt `entry_hash`/`prev_hash`, flip a payload bit) at multiple positions, ground truth hardcoded from algorithmic analysis rather than derived from `verify_chain` itself. Detection rate and reason accuracy are two SEPARATE `assert` statements (100%/100%), never collapsed into one pass/fail. 9 documented-limitation instances (tail truncation, whole-trail rewrite) are asserted reported `ok`, labelled and excluded from the 100% floor rather than silently dropped |
| 7 | Never-raise fuzzing of every verifier entry point | **[Shipped]** | [`tests/test_never_raise_sweep.py`](../../tests/test_never_raise_sweep.py) discovers "verifier entry point" by walking `waxseal.domain` + `waxseal.adapters.anchors` via `inspect`/`pkgutil` (name prefix `verify_`/`check_`/`parse_`/`decode_`/`read_`, or a "never raise"/"fails closed" docstring) rather than a hand-typed list, and `TestRegistryCompleteness` asserts the fuzzed registry matches discovery in BOTH directions — proven self-updating: it already caught one real gap (`domain.handoff.binding_holds`, added after a later bead) the moment that function landed. Found and fixed two real never-raise violations: `verify_chain`/`verify_proof_bundle` crashed on a lone-UTF-16-surrogate header field, `verify_checkpoint` crashed on a non-hex `entry_hash` earlier in the prefix; both now report the existing `entry_hash_mismatch`/`anchor_root_mismatch` finding instead of raising |
| 8 | Schema-evolution experiment: write under schema A, evolve to B, roll the binary back, compare three verifier designs on identical data | **[Shipped]** | [`tests/domain/test_schema_evolution_experiment.py`](../../tests/domain/test_schema_evolution_experiment.py) (waxseal-4t1). One trail spans the evolution: 4 rows under the shipped 6-field schema A, then 3 under a widened 7-field schema B carrying the entry_hash a real schema-B writer would have produced (a genuine 7-field lp64 frame, never a placeholder — a made-up hash would make "design 2 calls it broken" true for the boring reason). The rollback is a fresh `VersionRegistry` knowing only A, built the way `test_knowledge_monotonicity.py` builds its subsets, since there is no removal API (rule 2). Four verdicts, each its own assertion, never collapsed: the **ordinal** design (beads v1.2.2) refuses to run and verifies 0 rows — including the 4 it did understand; the **recompute-under-current** design (migration 060) manufactures 3 `entry_hash_mismatch` breaks; **waxseal's shipped `verify_chain`** reports 4 checked, `unverifiable == (4, 5, 6)`, 0 broken; and a **control** modelling the pre-rollback schema-B-aware binary verifies all 7 — without which "design 2 reports broken" would not yet be evidence of a *false* alarm rather than a real one. Two additions beyond the paper's minimum: beads' own escape hatch (`BD_IGNORE_SCHEMA_SKEW=1`) is modelled and shown to verify *nothing* rather than verify safely, and the honest limit is asserted rather than omitted — neither rolled-back design DETECTS a payload tamper on a schema-B row; waxseal's difference is that it never claims to have checked that row. `DesignVerdict.unverifiable` is `None` for the two collapsed designs and a tuple for waxseal, so the collapse theorem is visible in the result type itself. Falsifiability receipt, executed not described: `VersionRegistry.encoder_for` was temporarily made to return the current frame unconditionally (migration 060 injected into shipped code) → 5 tests red, including `assert with_dispatch.broken == ()` failing with `((4, 'entry_hash_mismatch'),)` against a row the control proves intact; reverting the one line turned all 10 green |

## 5. Gaps in detail

### G1 — τ is computed and reported [Shipped]

[`domain/separation.py`](../../src/waxseal/domain/separation.py) defines
`separation_degree()`, `render_separation_degree()`, and (added closing this gap)
`counted_authorities()`/`render_counted_authorities()`. All four are fully tested and are
now called from `domain/report.py` and `cli.py`.

What's checkable now:

- `waxseal verify` (with or without `--pin`) prints a `τ (separation degree): ...` line on
  every run — `not declared` when no `declared_topology` is on the pin, never a bare `0` or
  `1`. Example, from a real run against a demo trail with a `declared_topology` on its pin:
  `τ (separation degree): 6 (writer(1) + seal_escrow(1) + anchor_sinks(2) + witness(1) +
  pin_separate(1) = 6)`.
- `waxseal report --json` carries a `separation` object: `{"tau": ..., "counted_authorities":
  [{"name": ..., "count": ...}, ...]}`, `null`/`null` when undeclared. `waxseal report`'s
  Markdown rendering carries the same information in a `## Separation` section.
- `SeparationTopology`, `separation_degree`, and `Verdict` are now in the frozen public API
  in [`src/waxseal/__init__.py`](../../src/waxseal/__init__.py) — `tests/architecture/
  test_invariants.py::TestPublicApiFrozen` was updated in the same commit, with rationale.

Evidence: [`tests/domain/test_separation.py`](../../tests/domain/test_separation.py),
[`tests/domain/test_report.py`](../../tests/domain/test_report.py),
[`tests/test_cli_audit.py`](../../tests/test_cli_audit.py) (`TestReportSeparationDegree`),
[`tests/test_cli_pin.py`](../../tests/test_cli_pin.py) (the τ tests in
`TestDeclaredTopologyShortfall`) — the CLI tests run `main()` for real and assert on stdout/
JSON, not just `build_report()` directly.

The paper's position is that two deployments with identical cryptography and different τ are
not comparably secure, so a report omitting τ omits the only quantity that varies between
them. That recommendation is met as of waxseal-mfi. `declared_topology` now also has a CLI
flag to write it (`--declare-topology`, waxseal-ekd) — see G2 below, now shipped.

### G2 — the pin's three declarations have no writer [Shipped]

`expect_anchor_binding`, `max_anchor_age_s`, and `declared_topology` are parsed, checked,
preserved across pin advances, and specified in SPEC section 13.1. `verify` and `report` now
each accept `--expect-anchor-binding` (store-true), `--max-anchor-age-s SECONDS`, and
`--declare-topology SPEC` (a comma-separated `key=value` spec carrying all four
`SeparationTopology` subfields together — e.g.
`seal_escrow=true,anchor_sinks=2,witness=true,pin_separate=true`), all only meaningful
alongside `--pin` and enforced as a CLI usage error otherwise. A `--declare-topology` spec
naming some but not all four subfields is rejected at the argparse level (exit 2, printed
before the trail is even opened) — never silently defaulted, matching SPEC 13.1's own
`malformed_pin` rule for a partial object. Each flag only lands in the written pin state on a
run that actually advances the pin (exit 0/2, never exit 1's freeze); an omitted flag
preserves whatever a prior run already declared, exactly as it did before these flags existed.

An operator can still hand-edit the pin state JSON directly — that route and its format
(SPEC 13.1) are unchanged — but it is no longer the only one, and the READMEs now describe
the flags.

Evidence: [`tests/test_cli_pin.py`](../../tests/test_cli_pin.py)'s `TestDeclareViaCLI` —
CLI tests that run `main()` for real, read back the pin state file, and assert the JSON
matches SPEC 13.1's format exactly, including the partial-topology usage error and the
backward-compatible write onto a pin file in the pre-waxseal-ekd shape.

### G3 — one anchor run reaches multiple independent domains [Shipped]

`--tsa-url` and `--ots-calendar` used to sit in a mutually exclusive group on the `anchor`
command, so publishing the *same* checkpoint frame to both — the authority for a
minutes-scale detection window, the calendar for long-horizon non-repudiation — took two
runs back to back. The paper's anchor-selection corollary recommends reaching both from one
run, since τ rises by one per independent domain.

The exclusive group is gone (waxseal-4yk): both flags are accepted together, one checkpoint
is computed once (`AuditLog.anchor()`), and [`adapters/anchors.py`](../../src/waxseal/adapters/anchors.py)'s
new `MultiAnchorSink` fans it out to both sinks, each still filing its own `.anchors` sidecar
record exactly as `RecordingAnchorSink` always has. One sink being unreachable does not cost
the other its record — the failure is collected and printed labelled (`error: external
anchor failed, nothing recorded for <sink>: <reason>`), never swallowed (CLAUDE.md rule 6).

Evidence: [`tests/test_cli_receipts.py`](../../tests/test_cli_receipts.py)'s
`TestAnchorSubcommandSinks` — `test_both_targets_together_write_two_records_over_the_same_checkpoint`
(both flags on one `anchor` run → two sidecar records, same `entry_hash`/`root`/`seq`) and
`test_tsa_unreachable_still_records_the_ots_result_and_labels_the_failure` (TSA unreachable,
OTS calendar reachable → the OTS record still lands, exit 1, the TSA failure named on
stderr) — plus [`tests/adapters/test_rfc3161_sink.py`](../../tests/adapters/test_rfc3161_sink.py)'s
`TestMultiAnchorSink` for the sink-fan-out contract in isolation.

### G4 — the property-test generator excludes the character class the paper named [Shipped]

`st.characters(codec="utf-8")` cannot emit a lone surrogate, because a lone surrogate is not
encodable as UTF-8. That was the correct strategy for *valid* text and the wrong one for the
test the paper prescribed, whose point is to pin down what `lp()` does when handed a string
Python permits and UTF-8 does not.

Closed by waxseal-08c: `lp()` now raises a named `LpEncodingError` — chained from the stdlib
`UnicodeEncodeError` — for a lone surrogate, instead of leaking a bare, unlabelled exception.
`domain/verify.py`, `domain/export.py`, and `domain/checkpoint.py` all had to be taught to
catch it too (found by waxseal-lmv's never-raise sweep, see item 7 above) — a header this
build cannot even encode can never reproduce its stored hash, so this is the existing
`entry_hash_mismatch`/`anchor_root_mismatch` finding, not a crash.

Evidence: [`tests/domain/test_properties.py`](../../tests/domain/test_properties.py)'s
`test_lone_surrogate_raises_named_encoding_error`,
[`tests/domain/test_verify.py`](../../tests/domain/test_verify.py)'s
`test_unencodable_header_field_reports_entry_hash_mismatch_not_a_crash`. No frozen vector
byte changed — the fix only adds a `raise` on a previously-crashing input, never touching a
currently-valid one's output byte.

### G5 — cross-trail handoff binding: one half was by-design, the other half was the real gap [Shipped]

[`domain/handoff.py`](../../src/waxseal/domain/handoff.py) defines `HandoffBinding` (a
frozen, validated pointer triple: `chain_id`, `seq`, `head_hash`), `to_payload`/
`from_payload`, and `binding_holds()` — all fully tested, including 2-level and multi-hop
transitive-anchoring scenarios and a payload-deletion-is-unverifiable-not-broken check
(waxseal-otj). [`sources/handoff.py`](../../src/waxseal/sources/handoff.py) defines
`record_handoff()`, a general-purpose recorder any integration with two separate trails
could call.

This gap was first written up (Z1's audit) as "nothing in `src/` calls either one outside
their own tests" and left `needs-human` on the theory that closing it required an
architecture decision about which integration point should call `record_handoff`. A
second look, corrected on the same day, found that framing was based on an incomplete
comparison: it never checked whether `record_handoff`'s unreachability was actually novel.
It is not — `record_handoff()` calls `log.append()`, and CLAUDE.md's CLI contract is
explicit and absolute: "the CLI never appends chain entries." That already keeps
`record_decision` ([`sources/decisions.py`](../../src/waxseal/sources/decisions.py)),
`record_file` ([`sources/files.py`](../../src/waxseal/sources/files.py)), and
`generate_key` ([`domain/sealing.py`](../../src/waxseal/domain/sealing.py)) CLI-unwired —
all three are documented in README.md/.vi.md/.zh.md as calls the *operator's own
application code* imports and invokes directly, never as CLI subcommands. `record_handoff`
was simply missing that same documentation treatment; it needed no architecture decision,
only the README entry its siblings already had (waxseal-9al.2 Part A — see the new "Cross-
trail handoff binding" section in all three READMEs).

`binding_holds()`, by contrast, is genuinely different in kind: it is pure and read-only —
no I/O, a plain comparison over a `Sequence[str]` — exactly the shape `verify_membership`/
`verify_consistency` (`domain/anchoring.py`) already have, and those two are wired
read-only into `waxseal consistency`. Nothing about the never-appends rule blocks wiring a
read-only function into the CLI; this half of the gap was real, not by-design.
`waxseal verify-handoff <delegate-trail> --origin <origin-trail>` (waxseal-9al.2 Part B)
now closes it: it scans the delegate trail for `HANDOFF_PAYLOAD_TYPE` entries, opens the
origin trail read-only (local path only, no URL/remote support), and calls `binding_holds`
against the origin's current `entry_hashes()` for each one found — appending nothing to
either trail. Exit 0 when there is nothing to check or every binding holds; exit 1 when at
least one no longer holds (a genuinely detected mismatch, never merely "unverifiable" —
`binding_holds` is a deterministic comparison, not a name lookup); exit 3 when a named
trail path does not exist.

Evidence: [`tests/domain/test_handoff.py`](../../tests/domain/test_handoff.py),
[`tests/test_sources_handoff.py`](../../tests/test_sources_handoff.py) (both pre-existing,
waxseal-otj), and [`tests/test_cli_verify_handoff.py`](../../tests/test_cli_verify_handoff.py)
(new, waxseal-9al.2): a valid binding holding against its origin (exit 0), an origin trail
rewritten wholesale so the binding no longer holds (exit 1, naming the failing seq), no
handoff-binding entries on the delegate trail at all (exit 0, "nothing to check" — not an
error), a 2-hop multi-agent delegation (A → B → C, both hops checked), a missing origin
path (exit 3), and a header-only reader's payload unavailable (skipped, not reported as a
failure — rule 5's unmeasured-≠-absent, not this command's job to invent a verdict for
bytes it was never given).

### G6 — the on-chain layer shipped with two known, deliberate deviations [Shipped — both gaps since closed]

Workstream F (F1-F4, `26b074c`/`c21e0e6`/`20f2762`/`26e3e91`) delivered the three contracts section 3
records as [Shipped]. Two places where the shipped code diverges from the plan's exact prose were
flagged by the agents who found them rather than silently absorbed, and both were open as
`needs-human` beads at the time of this entry (both have since been closed — fg4.44 by
`081eab3`+`608775c`, fg4.45 by `b63c461`+`83d51a2`) — this ledger's discipline is to describe what actually
shipped, not the plan's unmodified description of what was intended, so both are recorded here plainly
rather than smoothed into the three [Shipped] rows above.

- **waxseal-fg4.44 — `registry_absent` and `registry_unreachable` are one status, not two.**
  `domain/registry.py`'s `RegistryCrossCheck` reports `REGISTRY_UNREACHABLE` (reason
  `registry_absent_or_unreachable`) for BOTH "the registry contract holds nothing under this
  fingerprint" and "the registry could not be read at all" — two different facts an operator might
  reasonably want distinguished, collapsed into one because `RegistryFinding` was built around the
  input it receives (`onchain_descriptor: bytes | None`), which already cannot tell the two apart by
  the time it reaches that type. Flagged independently by F3 (`waxseal-7yf`'s close-reason) and F4
  (`waxseal-j7b`'s close-reason), both of which correctly declined to invent a third status in
  adapter or CLI code — that is a domain-level verdict-vocabulary decision, and `domain/registry.py`
  is an already-shipped, already-tested module from F1. Open for an owner call: is the distinction
  worth adding a state to an exhaustive mapping this doc's own row above just finished praising for
  being exhaustive. **Since closed** (`081eab3` + `608775c`): the owner call was made — the
  mapping gained the states, and the split was folded into Ternary instance 13.
- **waxseal-fg4.45 — the ledger dimension does not raise τ.** The plan's Workstream F4 prose describes
  wiring a configured `--liveness`/`--registry` check into `domain/separation.py`'s
  `SeparationTopology` (a `ledger: bool` field) so it counts toward τ, the separation-degree number
  `waxseal preflight`/`verify --pin` report (gap G1, above). F4 shipped the ledger check as an
  independent `_Check` instead — the same shape `_anchor_check`/`_receipts_check` already have,
  delivering faithful exit-2 CLI semantics — and stated the scope reduction explicitly rather than
  silently narrowing it. An operator reading `τ (separation degree): N` today gets a number that does
  not credit a configured on-chain check, even though `ledger-status`/`verify --liveness` are
  genuinely checking something real; the gap is in the REPORTED COUNT, not in the underlying check. **Since closed** (`b63c461` + `83d51a2`): τ now credits a
  declared ledger authority, and `preflight` prints the declared-vs-measured split.

Neither gap makes any of section 3's three [Shipped] rows a false claim: the constructions work as
described, tested against real anvil chains including through a real CLI subprocess (F5,
[`tests/test_cli_ledger_e2e_anvil.py`](../../tests/test_cli_ledger_e2e_anvil.py)). Both gaps were about
the EDGES of the shipped surface — a merged vocabulary state, an uncounted τ contribution — the exact
shape [Written, unwired] ≠ [Shipped] exists to keep visible rather than let a ledger like this one
smooth over.

## 6. What cannot become [Proved] here, and why

A conformance program can move every claim *about this codebase* from asserted to executed.
It cannot move these, and a plan that promises otherwise is promising something the work
cannot deliver:

| Claim | Why it stays where it is |
|---|---|
| SHA-256 collision and second-preimage resistance; HMAC-SHA-256 as a secure MAC | Assumptions of the field, not properties of this repository. No test here bears on them |
| Epoch key deletion is effective | **Known false in the strict sense** — CPython cannot zeroise. Already stated in the repository. Testing it would confirm the known limitation, not remove it |
| Anchors and witnesses are under a different administrative authority | Not enforceable by software. It is an operator duty, and τ is a *declaration* of it precisely because waxseal cannot measure it |
| Authorities fail independently | A modelling choice, and an optimistic one |
| Monetary, latency, and regulatory figures | Measurable for one deployment at one time. A measurement is not a proof, and the number does not transfer |
| Novelty assessments against prior art | Needs a systematic literature search. The paper's own search was three queries and it says so |

Everything else — every claim whose subject is code in this repository — can be executed.
That is the achievable target, and it is what the conformance work should be scoped to.
