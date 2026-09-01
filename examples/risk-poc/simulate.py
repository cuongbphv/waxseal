"""Risk PoC: an AI risk-scanning agent writing a verifiable decision log.

Simulates the shape of a real deployment — a model decides on payment
instructions, and every decision lands on a tamper-evident chain with its
input committed, its secrets redacted before hashing, a forward-secure seal
per entry, and a Merkle checkpoint anchored every N entries.

Everything here is synthetic. There is no customer data, no institution, and
no real model: the "agent" is a deterministic rule set, so the demo produces
the same decisions on every run and the trail can be reasoned about. That is
the point — what is being demonstrated is the evidence layer, not the model.

    python examples/risk-poc/simulate.py --out /tmp/poc
    python examples/risk-poc/simulate.py --no-animation   # CI / piped output

Everything it writes goes under --out (default: a temp directory it prints).
"""

from __future__ import annotations

import argparse
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parents[2] / "src"))

from _animate import FlowAnimator, G, Stage, draw_chain  # noqa: E402

from waxseal import AuditLog, DecisionRecord, HumanOversight, ModelRef  # noqa: E402
from waxseal.adapters.anchors import FileAnchorSink  # noqa: E402
from waxseal.adapters.attest import FileAttestor  # noqa: E402
from waxseal.adapters.redactors import REDACTED, RegexRedactor  # noqa: E402
from waxseal.domain.canonical import canonical_json  # noqa: E402
from waxseal.domain.checkpoint import verify_checkpoint  # noqa: E402
from waxseal.domain.decision import to_payload  # noqa: E402
from waxseal.domain.report import CheckSummary, build_report  # noqa: E402
from waxseal.domain.sealing import generate_key  # noqa: E402
from waxseal.sources.decisions import commit_input, record_decision  # noqa: E402

SYSTEM_ID = "risk-scanning-agent"
MODEL = ModelRef(name="risk-scanning-llm", version="2026.08.1", digest="c" * 64)
POLICY_VERSION = "risk-policy-2026.07"
ANCHOR_EVERY = 4

# A large-value reporting threshold, in the same spirit as the ones a
# reporting regime sets. The number is invented for the demo.
LARGE_VALUE = 500_000_000
WATCHLISTED = {"CP-SANCTION-01"}


@dataclass(frozen=True, slots=True)
class Txn:
    txn_id: str
    subject_ref: str
    counterparty: str
    amount_vnd: int
    channel: str
    counterparty_age_days: int
    # Present to prove the point: an operator note that happens to contain a
    # credential. It must never reach disk in cleartext.
    operator_note: str = ""


def transactions() -> list[Txn]:
    """Synthetic instructions, fixed so the demo is reproducible."""
    return [
        Txn("TXN-1001", "cust-7f3a", "CP-RETAIL-88", 2_500_000, "mobile", 900),
        Txn("TXN-1002", "cust-91bd", "CP-RETAIL-12", 145_000_000, "internet", 11),
        Txn("TXN-1003", "cust-7f3a", "CP-SANCTION-01", 30_000_000, "mobile", 400),
        Txn(
            "TXN-1004", "cust-04e2", "CP-CORP-05", 780_000_000, "swift", 2200,
            operator_note="reconciled via ops API, Bearer sk-live-9f2ab7c41de85630",
        ),
        Txn("TXN-1005", "cust-91bd", "CP-RETAIL-12", 9_900_000, "internet", 12),
        Txn("TXN-1006", "cust-c518", "CP-CORP-77", 61_000_000, "swift", 60),
    ]


@dataclass(frozen=True, slots=True)
class Verdict:
    outcome: str
    rationale: str
    confidence: float
    decision_type: str
    oversight: HumanOversight | None


def screen(txn: Txn) -> Verdict:
    """The stand-in for the model. Deterministic on purpose."""
    if txn.counterparty in WATCHLISTED:
        return Verdict(
            outcome="deny",
            rationale="counterparty matches an internal watchlist entry",
            confidence=0.97,
            decision_type="risk_scanning",
            oversight=HumanOversight(
                mode="reviewed", reviewer_ref="analyst-queue-2", action="confirmed"
            ),
        )
    if txn.amount_vnd >= LARGE_VALUE:
        return Verdict(
            outcome="escalate",
            rationale="above the large-value reporting threshold",
            confidence=0.88,
            decision_type="risk_scanning",
            oversight=HumanOversight(
                mode="reviewed", reviewer_ref="analyst-queue-1", action="released"
            ),
        )
    if txn.counterparty_age_days < 30 and txn.amount_vnd > 100_000_000:
        return Verdict(
            outcome="escalate",
            rationale="high value to a counterparty first seen in the last 30 days",
            confidence=0.74,
            decision_type="risk_scanning",
            # Deliberately left unrecorded on one path. The report must show
            # this as "oversight not recorded" and NOT as "automated" — the
            # two are different claims (CLAUDE.md rule 5).
            oversight=None,
        )
    return Verdict(
        outcome="approve",
        rationale="below thresholds, established counterparty",
        confidence=0.93,
        decision_type="transaction_approval",
        oversight=HumanOversight(mode="automated"),
    )


def model_input(txn: Txn) -> dict[str, object]:
    """What the model was shown. Committed by hash, never stored."""
    return {
        "txn_id": txn.txn_id,
        "counterparty": txn.counterparty,
        "amount_vnd": txn.amount_vnd,
        "channel": txn.channel,
        "counterparty_age_days": txn.counterparty_age_days,
        "operator_note": txn.operator_note,
    }


def stages_for(
    txn: Txn, verdict: Verdict, record: DecisionRecord, redactor: RegexRedactor, seq: int
) -> list[Stage]:
    """The real intermediate values, recomputed here purely for display.

    Recomputed rather than captured from the append path on purpose: the
    animation must not be able to influence what gets hashed.
    """
    redacted = redactor.redact(model_input(txn))
    note = str(redacted.get("operator_note") or "")
    payload_bytes = canonical_json(to_payload(record))
    return [
        Stage("decide", f"{txn.txn_id} {G.arrow} {verdict.outcome} "
              f"(confidence {verdict.confidence:.2f})"),
        Stage(
            "redact",
            "secret in operator_note masked BEFORE any hashing"
            if REDACTED in note
            else "no secret pattern in this input",
        ),
        Stage(
            "commit",
            f"input_commitment {record.input_commitment[:16]}{G.ellipsis} - over the "
            "REDACTED input, so it cannot confirm a guess at the secret",
        ),
        Stage("canon", f"payload {G.arrow} {len(payload_bytes)} canonical bytes "
              "(sorted keys, no whitespace)"),
        Stage("hash", f"payload_hash = sha256(payload) = "
              f"{sha256_hex(payload_bytes)[:16]}{G.ellipsis}"),
        Stage("chain", f"header seq={seq}; prev_hash commits to every entry before it"),
        Stage("seal", "forward-secure HMAC seal - the key evolves, the old one is gone"),
    ]


def sha256_hex(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


def anchor_summary(trail: Path, entry_hashes: list[str]) -> CheckSummary:
    """Replay every recorded checkpoint against the trail as it stands now.

    This is what closes the whole-trail-rewrite gap: the chain's own links
    are all recomputable by whoever can write the file, but a root published
    before the edit is not.
    """
    records = list(FileAnchorSink(trail).records())
    if not records:
        # Nothing was anchored, so nothing was covered. Saying "ok" here
        # would report an absence of evidence as evidence.
        return CheckSummary(ok=True, checked=0, reason="no_anchors_recorded")
    for cp in records:
        reason = verify_checkpoint(entry_hashes, cp)
        if reason is not None:
            return CheckSummary(ok=False, checked=0, reason=reason)
    return CheckSummary(ok=True, checked=len(records), reason=None)


def run(out_dir: Path, *, animate: bool) -> int:
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)
    trail = out_dir / "decisions.jsonl"

    # A_0 is escrowed with the verifier, off the writing machine. Written to
    # a file here only because a demo has nowhere else to put it; in a real
    # deployment this is the one secret that must not live beside the trail.
    initial_key = generate_key()
    (out_dir / "sealkey.escrow").write_bytes(initial_key)

    redactor = RegexRedactor()
    log = AuditLog.open(
        trail,
        redactor=redactor,
        attestor=FileAttestor(trail, initial_key=initial_key),
        anchor_sink=FileAnchorSink(trail),
        anchor_every=ANCHOR_EVERY,
        record_drops=True,
    )

    print(f"\n  Writing a verifiable AI decision log to {trail}")
    animator = FlowAnimator(enabled=animate)

    txns = transactions()
    for seq, txn in enumerate(txns):
        verdict = screen(txn)
        record = DecisionRecord(
            decision_id=f"DEC-{txn.txn_id}",
            decision_type=verdict.decision_type,
            system_id=SYSTEM_ID,
            model=MODEL,
            input_commitment=commit_input(model_input(txn), redactor=redactor),
            outcome=verdict.outcome,
            rationale=verdict.rationale,
            policy_version=POLICY_VERSION,
            confidence=verdict.confidence,
            human_oversight=verdict.oversight,
            subject_ref=txn.subject_ref,
            trace_id=f"trace-{txn.txn_id.lower()}",
        )
        animator.play(
            f"waxseal · decision {seq + 1}/{len(txns)} · {txn.txn_id}",
            stages_for(txn, verdict, record, redactor, seq),
            dwell=0.28 if seq == 0 else 0.12,
        )
        record_decision(log, record)

    entries = list(log._backend.entries())
    draw_chain([e.entry_hash for e in entries], enabled=animate)

    # Everything an operator should check before believing any of it. Each
    # check is reported as itself: a report that said "not checked" for
    # things this run did check would understate the evidence, and one that
    # said "ok" for things it skipped would overstate it.
    result = log.verify()
    attest = log.verify_attestations(initial_key=initial_key)
    report = build_report(
        result,
        entries,
        anchors=anchor_summary(trail, [e.entry_hash for e in entries]),
        attestations=CheckSummary(
            ok=attest.ok, checked=attest.checked, reason=attest.reason
        ),
    )
    print(report.to_markdown())

    secret = b"sk-live-9f2ab7c41de85630"
    leaked = secret in trail.read_bytes()
    print(f"  Cleartext secret present anywhere in the trail: {leaked}")

    print(
        "\n  Next:\n"
        f"    waxseal verify --anchors {trail}\n"
        f"    waxseal report {trail}\n"
        f"    waxseal export-proof {trail} 3 > {out_dir / 'proof-seq3.json'}\n"
        f"    waxseal verify-proof {out_dir / 'proof-seq3.json'}\n"
        f"    python {Path(__file__).with_name('tamper_demo.py')} --out {out_dir}\n"
    )
    return 0 if (result.ok and attest.ok and not leaked) else 1


def main(argv: list[str] | None = None) -> int:
    # Same reason the CLI does this: a legacy console codepage must cost a
    # dash, not the whole run.
    from waxseal.cli import _survive_a_narrow_console

    _survive_a_narrow_console()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out", type=Path, default=Path("examples/poc-out"),
        help="directory for the trail and its sidecars (recreated on each run)",
    )
    parser.add_argument(
        "--no-animation", action="store_true",
        help="print each stage as a plain line instead of redrawing",
    )
    args = parser.parse_args(argv)
    return run(args.out.expanduser(), animate=not args.no_animation)


if __name__ == "__main__":
    raise SystemExit(main())
