from __future__ import annotations

import argparse
from pathlib import Path

_TSA_CA_FILE_HELP = (
    "PEM bundle of trust anchors for the TSA that issued the RFC 3161 receipts "
    "in <path>.anchors. Passing it TURNS ON the signature dimension, which "
    "needs the optional extra (`pip install 'waxseal[rfc3161]'`): a receipt "
    "whose CMS signature does not verify, or whose signer does not chain to "
    "this bundle, is signature_invalid, exit 1; anything that could not be "
    "checked at all (extra absent, bundle unreadable, a token shape this build "
    "cannot parse) is signature_unchecked, exit 2, never a silent pass. "
    "Without this flag the receipts are checked STRUCTURALLY only, exactly as "
    "before, and every line says so — waxseal names no default trust anchor, "
    "because choosing one would decide whom you trust on your behalf"
)

_PIN_HELP = (
    "check the trail against a checkpoint this verifier recorded previously, "
    "and record the current head on any run that finds no break "
    "(trust-on-first-use). Keep this "
    "file under a different authority than the trail — that separation is the "
    "entire security argument. See --expect-anchor-binding/--max-anchor-age-s/"
    "--declare-topology to declare what this pin should expect (SPEC 13.1); "
    "each takes effect only on a run that advances the pin"
)

_EXPECT_ANCHOR_BINDING_HELP = (
    "declare (onto --pin's state) that the .anchors sidecar is expected to "
    "carry a section 15 aggregate binding at or after the pinned seq. A run "
    "that finds only unbound records reports anchor_policy_downgrade, exit 2 "
    "— never evidence of tampering. Requires --pin; only takes effect on a "
    "run that advances it"
)

_MAX_ANCHOR_AGE_S_HELP = (
    "declare (onto --pin's state) a silence deadline in seconds: the newest "
    ".anchors record older than this (or no record at all) reports "
    "anchor_stale, exit 2. Requires --pin; only takes effect on a run that "
    "advances it"
)

_DECLARE_TOPOLOGY_HELP = (
    "declare (onto --pin's state) how many independent authorities hold a "
    "binding, as seal_escrow=<bool>,anchor_sinks=<int>,witness=<bool>,"
    "pin_separate=<bool> — all four subfields required together (SPEC 13.1: "
    "a partial declaration is malformed_pin, never silently defaulted). "
    "An optional fifth ledger=<bool> may be added to declare the on-chain "
    "ledger authority; omitting it leaves ledger undeclared (None), never "
    "false, and every spec string written before this subfield existed "
    "keeps parsing unchanged. Requires --pin; only takes effect on a run "
    "that advances it"
)

_TSA_HELP = (
    "timestamp the checkpoint at an RFC 3161 Time-Stamp Authority and store "
    "the token in the sidecar record. Makes the time attested by a third "
    "party rather than asserted by this host. Nothing is recorded if the TSA "
    "is unreachable or answers about other bytes. The token's CMS signature "
    "is NOT verified by waxseal, here or on verify — check it with "
    "`openssl ts -verify`"
)

_OTS_HELP = (
    "submit the checkpoint digest to an OpenTimestamps calendar and store the "
    "PENDING proof. The Bitcoin attestation does not exist until the block "
    "confirms; complete it with `ots upgrade`"
)

_WITNESS_HELP = (
    "witness endpoint URL (repeatable). On `anchor`, publish the checkpoint "
    "there too; on `verify`, check the trail extends everything that witness "
    "saw. Point it at a host that is NOT the chain server — witnessing a "
    "server to itself proves nothing"
)

_PREFLIGHT_PIN_HELP = (
    "read this verifier's pin state file for the declarations it carries "
    "(declared_topology, expect_anchor_binding, max_anchor_age_s). READ-ONLY "
    "here: unlike `verify --pin`/`report --pin`, preflight never writes it "
    "and never advances it"
)

# --------------------------------------------------------------- ledger (F4)
#
# `--rpc`/`--liveness`/`--registry`/`--bond` are shared verbatim across every
# subcommand that reads the on-chain ledger layer (`ledger-status`, `verify`,
# `report`), so one set of help strings, never one copied per parser.

_RPC_HELP = (
    "on-chain JSON-RPC endpoint (repeatable; at least 2 required — "
    "adapters/evm.py refuses a single endpoint because it cannot disagree "
    "with itself, which is exactly the eclipse an operator relying on one "
    "voice would be blind to)"
)

_LIVENESS_HELP = "AnchoringLiveness contract address"

_LEDGER_REGISTRY_HELP = (
    "FingerprintRegistry contract address; cross-checks every schema "
    "fingerprint this trail actually carries against what the contract "
    "holds (agreement is decided by SHA-256, the same computation the "
    "contract performs, never by this build's ability to parse the "
    "descriptor it reads back)"
)

_BOND_HELP = "BondedCheckpoints contract address"

_TRAIL_ID_HELP = (
    "the on-chain trail identifier (hashed to a bytes32 trail id, "
    "domain/bond.py's trail_id_for); default: the resolved local trail "
    "path (or the URL, verbatim) — the same value `--pin` names a trail by. "
    "Anchoring and later reading a trail must agree on this value or they "
    "key two different slots on the same contract"
)

_LEDGER_VERIFY_HELP = (
    "cross-check the trail against an on-chain AnchoringLiveness contract. "
    "A chain disagreement or an unreachable ledger is reported as "
    "unverifiable (exit 2), never as broken (exit 1): the whole point of "
    "the liveness ternary is that punctuality and integrity are different "
    "questions — a trail can be perfectly intact and merely late"
)

_WAXSEAL_EVM_SIGNER_CMD_MISSING = (
    "WAXSEAL_EVM_SIGNER_CMD is not set. A ledger write needs a signer, and "
    "waxseal never takes a private key on argv or in an env var that "
    "carries key material — the same boundary WAXSEAL_API_KEY and "
    "WAXSEAL_WITNESS_API_KEY already draw for credentials. Set "
    "WAXSEAL_EVM_SIGNER_CMD to an executable this CLI can invoke as "
    "`<cmd> address`, `<cmd> sign-digest 0x<64 hex>`, and `<cmd> sign-tx` "
    "(the transaction fields as a JSON object on stdin) — see "
    "ExternalEvmSigner's docstring for the exact three-verb contract, and "
    "tests/adapters/test_evm_anvil.py's CastSigner for the two operations "
    "(`cast wallet sign --no-hash`, `cast mktx`) a real wrapper needs to "
    "perform behind it"
)


def _add_pin_declaration_arguments(p: argparse.ArgumentParser) -> None:
    """`--expect-anchor-binding`/`--max-anchor-age-s`/`--declare-topology`:
    the CLI writers for the three `PinState` declarations SPEC 13.1 defines
    (waxseal-ekd, closing conformance.md gap G2). Shared between `verify`
    and `report` since both already accept `--pin`: one definition so the
    two commands cannot drift apart on flag name or help text.
    """
    from waxseal.cli.pin import _declared_topology_arg

    p.add_argument(
        "--expect-anchor-binding",
        action="store_true",
        default=False,
        help=_EXPECT_ANCHOR_BINDING_HELP,
    )
    p.add_argument(
        "--max-anchor-age-s",
        type=int,
        default=None,
        metavar="SECONDS",
        help=_MAX_ANCHOR_AGE_S_HELP,
    )
    p.add_argument(
        "--declare-topology",
        type=_declared_topology_arg,
        default=None,
        metavar="SPEC",
        help=_DECLARE_TOPOLOGY_HELP,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="waxseal")
    sub = parser.add_subparsers(dest="command", required=True)

    p_verify = sub.add_parser("verify", help="verify chain integrity")
    p_verify.add_argument("path")
    p_verify.add_argument(
        "--anchors",
        action="store_true",
        help="also check the local anchor sidecar (<path>.anchors), if any",
    )
    p_verify.add_argument("--pin", type=Path, default=None, metavar="STATEFILE", help=_PIN_HELP)
    _add_pin_declaration_arguments(p_verify)
    p_verify.add_argument(
        "--witness", action="append", default=None, metavar="URL", help=_WITNESS_HELP
    )
    p_verify.add_argument(
        "--tsa-ca-file", type=Path, default=None, metavar="BUNDLE.PEM", help=_TSA_CA_FILE_HELP
    )
    p_verify.add_argument("--rpc", action="append", default=None, metavar="URL", help=_RPC_HELP)
    p_verify.add_argument("--liveness", default=None, metavar="ADDR", help=_LEDGER_VERIFY_HELP)
    p_verify.add_argument("--registry", default=None, metavar="ADDR", help=_LEDGER_REGISTRY_HELP)
    p_verify.add_argument("--trail-id", default=None, metavar="NAME", help=_TRAIL_ID_HELP)

    p_tail = sub.add_parser("tail", help="print the last entries")
    p_tail.add_argument("path")
    p_tail.add_argument("-n", type=int, default=10)

    p_inspect = sub.add_parser("inspect", help="summarize the trail")
    p_inspect.add_argument("path")

    p_head = sub.add_parser(
        "head", help="print the chain head (seq + entry_hash) for external anchoring"
    )
    p_head.add_argument("path")

    p_checkpoint = sub.add_parser(
        "checkpoint",
        help="print a checkpoint (seq + entry_hash + Merkle root) for an anchor sink",
    )
    p_checkpoint.add_argument("path")

    p_anchor = sub.add_parser(
        "anchor", help="append a checkpoint to the local anchor sidecar (<path>.anchors)"
    )
    p_anchor.add_argument("path")
    p_anchor.add_argument(
        "--witness", action="append", default=None, metavar="URL", help=_WITNESS_HELP
    )
    p_anchor.add_argument("--tsa-url", metavar="URL", help=_TSA_HELP)
    p_anchor.add_argument("--ots-calendar", metavar="URL", help=_OTS_HELP)
    p_anchor.add_argument("--evm-rpc", action="append", default=None, metavar="URL", help=_RPC_HELP)
    p_anchor.add_argument(
        "--evm-liveness",
        default=None,
        metavar="ADDR",
        help="publish this checkpoint to an AnchoringLiveness contract too "
        "(adds a fourth independent anchor domain alongside --tsa-url/"
        "--ots-calendar); requires --evm-rpc and WAXSEAL_EVM_SIGNER_CMD",
    )
    p_anchor.add_argument(
        "--evm-write-rpc",
        default=None,
        metavar="URL",
        help="which --evm-rpc endpoint actually receives the transaction "
        "(default: the first --evm-rpc given)",
    )
    p_anchor.add_argument("--evm-trail-id", default=None, metavar="NAME", help=_TRAIL_ID_HELP)
    p_anchor.add_argument(
        "--evm-consistency-proof-file",
        type=Path,
        default=None,
        metavar="PROOF.JSON",
        help="a JSON array of hex bytes32 strings: the RFC 9162 consistency "
        "proof the contract requires from the SECOND submit onward for this "
        "trail id. Omit only for the very first submit — the contract "
        "reverts NotAnExtension on every one after that without one, which "
        "surfaces here as a labelled error, never a silent no-op",
    )

    p_report = sub.add_parser(
        "report", help="print an auditor report: what the trail holds and what was checked"
    )
    p_report.add_argument("path")
    p_report.add_argument("--json", action="store_true", help="emit JSON instead of Markdown")
    p_report.add_argument(
        "--anchors",
        action="store_true",
        help="also check the local anchor sidecar (<path>.anchors), if any",
    )
    p_report.add_argument("--pin", type=Path, default=None, metavar="STATEFILE", help=_PIN_HELP)
    _add_pin_declaration_arguments(p_report)
    p_report.add_argument(
        "--witness", action="append", default=None, metavar="URL", help=_WITNESS_HELP
    )
    p_report.add_argument(
        "--tsa-ca-file", type=Path, default=None, metavar="BUNDLE.PEM", help=_TSA_CA_FILE_HELP
    )
    p_report.add_argument("--rpc", action="append", default=None, metavar="URL", help=_RPC_HELP)
    p_report.add_argument("--liveness", default=None, metavar="ADDR", help=_LEDGER_VERIFY_HELP)
    p_report.add_argument("--registry", default=None, metavar="ADDR", help=_LEDGER_REGISTRY_HELP)
    p_report.add_argument("--trail-id", default=None, metavar="NAME", help=_TRAIL_ID_HELP)

    p_export = sub.add_parser(
        "export-proof",
        help="print a standalone proof bundle for one entry (stdout; redirect to a file)",
    )
    p_export.add_argument("path")
    p_export.add_argument("seq", type=int)

    p_verify_proof = sub.add_parser(
        "verify-proof", help="check a proof bundle offline — no trail needed"
    )
    p_verify_proof.add_argument("bundle")

    p_consistency = sub.add_parser(
        "consistency",
        help="check the current head extends an earlier recorded state "
        "(RFC 9162 consistency proof; failure is split-view evidence)",
    )
    p_consistency.add_argument("path")
    p_consistency.add_argument(
        "--old-seq",
        type=int,
        required=True,
        metavar="N",
        help="seq of the earlier state, as printed by `waxseal checkpoint`",
    )
    p_consistency.add_argument(
        "--old-root",
        required=True,
        metavar="HEX",
        help="batch root of the earlier state, as printed by `waxseal checkpoint`",
    )

    p_verify_handoff = sub.add_parser(
        "verify-handoff",
        help="check every cross-trail handoff binding recorded on this "
        "(delegate) trail against an origin trail's current history "
        "(SPEC D3; read-only against both trails, appends nothing)",
    )
    p_verify_handoff.add_argument("path")
    p_verify_handoff.add_argument(
        "--origin",
        required=True,
        metavar="PATH",
        help="local path to the origin trail this delegate's handoff "
        "bindings point at (no URL/remote support — read-only, local "
        "path only)",
    )

    p_reconcile = sub.add_parser(
        "reconcile-tickets",
        help="reconcile an exogenous issuer's admission tickets against "
        "tickets present on the trail (positively-detected drops; D2)",
    )
    p_reconcile.add_argument("path")
    p_reconcile.add_argument(
        "--issuer",
        required=True,
        metavar="NAME",
        help="only reconcile tickets recorded under this issuer name",
    )
    p_reconcile.add_argument(
        "--lease-size",
        type=int,
        required=True,
        metavar="L",
        help="the issuer's lease size (no default — this is the issuer's "
        "own parameter, never guessed)",
    )
    p_reconcile.add_argument(
        "--issued",
        default=None,
        metavar="SPEC",
        help="ticket numbers the issuer reports as actually issued, e.g. "
        "'0-99' or '0,1,5-9' (comma-separated ints and inclusive ranges); "
        "omit when the issuer cannot be asked this run — reported as "
        "unmeasured (exit 2), never as zero drops",
    )
    p_reconcile.add_argument("--json", action="store_true", help="emit JSON instead of text")

    p_incidents = sub.add_parser(
        "incidents",
        help="list the incident records on this trail and read each one "
        "against a reporting window (read-only; a reading, never a finding "
        "that an obligation was missed)",
    )
    p_incidents.add_argument("path")
    p_incidents.add_argument(
        "--report-window-h",
        type=float,
        default=72.0,
        metavar="H",
        help="the reporting window in hours, measured from each incident's "
        "recorded confirmation moment (default 72, the preliminary-report "
        "window for an urgent serious incident under Decree 142/2026/ND-CP "
        "Dieu 19(3)(a); Dieu 19(3)(b) gives 5 working days for the rest, "
        "which is an operator parameter this flag does not compute)",
    )
    p_incidents.add_argument(
        "--as-of",
        default=None,
        metavar="TS",
        help="the offset-aware ISO 8601 moment to read the window as of; "
        "omit to use this process's clock. Naming it makes the reading "
        "reproducible, since a window reading depends on when it was taken",
    )
    p_incidents.add_argument(
        "--since",
        default=None,
        metavar="TS",
        help="list only incidents whose confirmation moment is at or after "
        "this offset-aware ISO 8601 moment; a row whose own timestamp this "
        "build cannot read is still listed, labelled, and never dropped by "
        "the filter",
    )
    p_incidents.add_argument("--json", action="store_true", help="emit JSON instead of text")

    p_receipt = sub.add_parser(
        "receipt",
        help="extract stored anchor receipts to files for the external "
        "verifiers waxseal delegates to (openssl ts -verify, ots verify)",
    )
    p_receipt.add_argument("path")
    p_receipt.add_argument(
        "--seq",
        type=int,
        default=None,
        metavar="N",
        help="only receipts anchored at this seq (default: every record with one)",
    )
    p_receipt.add_argument(
        "--out",
        type=Path,
        required=True,
        metavar="DIR",
        help="directory to write receipt and frame files into (created if missing)",
    )

    p_cadence = sub.add_parser(
        "cadence",
        help="print the cost-optimal anchoring cadence for operator-supplied "
        "parameters (pure arithmetic; opens no trail at all)",
    )
    p_cadence.add_argument(
        "--lam",
        type=float,
        required=True,
        metavar="RATE",
        help="entry arrival rate (entries per unit time)",
    )
    p_cadence.add_argument(
        "--c",
        type=float,
        required=True,
        metavar="COST",
        help="marginal cost of one anchor operation (operator measurement, no default)",
    )
    p_cadence.add_argument(
        "--w",
        type=float,
        required=True,
        metavar="HARM",
        help="expected harm per rewritable record if compromised "
        "(operator measurement, no default)",
    )
    p_cadence.add_argument(
        "--rho",
        type=float,
        required=True,
        metavar="RATE",
        help="compromise hazard rate (operator measurement, no default)",
    )
    p_cadence.add_argument(
        "--M",
        type=int,
        default=1,
        metavar="N",
        help="agents sharing one anchor (default: 1 -- structural 'no fleet "
        "sharing', not a guessed measurement)",
    )
    p_cadence.add_argument(
        "--delta",
        type=float,
        required=True,
        metavar="SECONDS",
        help="anchor finality latency",
    )
    p_cadence.add_argument(
        "--t-max",
        type=float,
        required=True,
        metavar="SECONDS",
        dest="t_max",
        help="operator's tolerated detection window",
    )

    p_preflight = sub.add_parser(
        "preflight",
        help="print which rung of the attacker-capability ladder this "
        "trail's configuration stops (read-only; a reading, not a verdict)",
    )
    p_preflight.add_argument("path")
    p_preflight.add_argument(
        "--pin",
        type=Path,
        default=None,
        metavar="STATEFILE",
        help=_PREFLIGHT_PIN_HELP,
    )

    p_segments = sub.add_parser(
        "segments",
        help="verify a directory of sealed trail segments and the rotation "
        "bindings that link them (read-only; appends nothing)",
    )
    p_segments.add_argument("dir", help="the per-project trail directory to walk")

    p_install = sub.add_parser(
        "install", help="write the audit hook shim files for an agent framework"
    )
    from waxseal.integrations._install import TARGETS

    p_install.add_argument("target", choices=TARGETS)
    p_install.add_argument(
        "--home",
        type=Path,
        default=None,
        help="host home directory (default: the host's own, e.g. ~/.hermes)",
    )
    p_install.add_argument("--force", action="store_true", help="overwrite shim files that differ")

    p_ledger_status = sub.add_parser(
        "ledger-status",
        help="read-only liveness/registry/bond ternaries for a trail's "
        "on-chain state (exit codes match reconcile-tickets: 0 clean, "
        "1 a positively-detected finding, 2 unmeasured, 3 no such trail)",
    )
    p_ledger_status.add_argument("path")
    p_ledger_status.add_argument(
        "--rpc", action="append", default=None, metavar="URL", help=_RPC_HELP
    )
    p_ledger_status.add_argument("--liveness", required=True, metavar="ADDR", help=_LIVENESS_HELP)
    p_ledger_status.add_argument(
        "--registry", default=None, metavar="ADDR", help=_LEDGER_REGISTRY_HELP
    )
    p_ledger_status.add_argument("--bond", default=None, metavar="ADDR", help=_BOND_HELP)
    p_ledger_status.add_argument(
        "--writer",
        default=None,
        metavar="ADDR",
        help="the writer address to check the bond of; required with --bond",
    )
    p_ledger_status.add_argument("--trail-id", default=None, metavar="NAME", help=_TRAIL_ID_HELP)
    p_ledger_status.add_argument("--json", action="store_true", help="emit JSON instead of text")

    p_registry = sub.add_parser(
        "registry", help="on-chain fingerprint registry writes (ledger layer)"
    )
    sub_registry = p_registry.add_subparsers(dest="registry_command", required=True)
    p_registry_publish = sub_registry.add_parser(
        "publish",
        help="publish a header-schema descriptor to the on-chain fingerprint "
        "registry (not a chain-entry append — same footing as `anchor`)",
    )
    p_registry_publish.add_argument(
        "--descriptor-of",
        required=True,
        metavar="FINGERPRINT",
        help="which fingerprint (as this build's own VersionRegistry knows "
        "it) to publish the descriptor of; the contract computes "
        "sha256(descriptor) itself, so there is no separate fingerprint "
        "argument that could disagree with the bytes sent",
    )
    p_registry_publish.add_argument(
        "--registry", required=True, metavar="ADDR", help="FingerprintRegistry contract address"
    )
    p_registry_publish.add_argument(
        "--rpc", action="append", default=None, metavar="URL", help=_RPC_HELP
    )
    p_registry_publish.add_argument(
        "--write-rpc",
        default=None,
        metavar="URL",
        help="which --rpc endpoint actually receives the transaction (default: the first)",
    )

    p_bond = sub.add_parser("bond", help="bonded-equivocation contract writes (ledger layer)")
    sub_bond = p_bond.add_subparsers(dest="bond_command", required=True)
    p_bond_deposit = sub_bond.add_parser("deposit", help="post or top up the signer's own stake")
    p_bond_deposit.add_argument("--bond", required=True, metavar="ADDR", help=_BOND_HELP)
    p_bond_deposit.add_argument(
        "--rpc", action="append", default=None, metavar="URL", help=_RPC_HELP
    )
    p_bond_deposit.add_argument(
        "--write-rpc",
        default=None,
        metavar="URL",
        help="which --rpc endpoint actually receives the transaction (default: the first)",
    )
    p_bond_deposit.add_argument(
        "--amount-wei", type=int, required=True, metavar="WEI", help="amount to deposit, in wei"
    )
    p_bond_prove = sub_bond.add_parser(
        "prove",
        help="submit a fraud proof (equivocation or non-extension) against a writer's bond",
    )
    p_bond_prove.add_argument(
        "proof",
        help="path to a JSON fraud-proof file; "
        '{"kind": "equivocation", "chain_id": ..., "checkpoint_a": '
        '{"seq": ..., "entry_hash": ..., "root": ...}, "signature_a": "0x..", '
        '"checkpoint_b": {...}, "signature_b": "0x.."} or '
        '{"kind": "non_extension", "chain_id": ..., "older": {...}, '
        '"older_signature": "0x..", "newer": {...}, "newer_signature": "0x..", '
        '"in_older": {"index": ..., "entry_hash": ..., "proof": ["0x..", ...]}, '
        '"in_newer": {...}}',
    )
    p_bond_prove.add_argument("--bond", required=True, metavar="ADDR", help=_BOND_HELP)
    p_bond_prove.add_argument("--rpc", action="append", default=None, metavar="URL", help=_RPC_HELP)
    p_bond_prove.add_argument(
        "--write-rpc",
        default=None,
        metavar="URL",
        help="which --rpc endpoint actually receives the transaction (default: the first)",
    )

    return parser
