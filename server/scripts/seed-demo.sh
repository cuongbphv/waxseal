#!/usr/bin/env bash
# Write demo chains so the portal has something real to show.
#
#   ./scripts/seed-demo.sh --data ./.local-data
#
# The data is DEMO data and is named as such. It carries no organisation name, no
# person's name, no address and no credential: these trails end up in
# screenshots and in shared dev environments, and a screenshot is the easiest
# way for a real name to leave a building.
#
# Written with the waxseal LIBRARY, not by hand — the same path a real client
# takes, so the demo cannot be a shape no actual client produces.

# shellcheck source=_lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"

DATA_DIR="$SERVER_DIR/.local-data"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --data) DATA_DIR="${2:?--data needs a value}"; shift ;;
    -h|--help) sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown flag $1" ;;
  esac
  shift
done

py="$(server_python)"
step "Seeding demo chains into $DATA_DIR/chains"
cd "$SERVER_DIR" || exit 1
DATA_DIR="$DATA_DIR" $py - <<'PYEOF'
import os
from pathlib import Path

from waxseal import AuditLog

chains = Path(os.environ["DATA_DIR"]) / "chains"

# Generic, inspectable, and deliberately anonymous. Placeholder identities only:
# `agent-a`, `reviewer-1`. No organisation, no real person, no email, no token.
DEMO = {
    "orders": [
        {"action": "order.approve", "amount": 1250, "currency": "USD",
         "agent": "agent-a", "oversight": "human_approved", "reviewer": "reviewer-1"},
        {"action": "order.approve", "amount": 90, "currency": "USD",
         "agent": "agent-a", "oversight": "automated"},
        {"action": "order.reject", "amount": 40000, "currency": "USD",
         "agent": "agent-b", "oversight": "human_approved", "reviewer": "reviewer-2"},
    ],
    "support": [
        {"action": "ticket.close", "ticket": "T-1001", "agent": "agent-c",
         "oversight": "automated"},
        {"action": "ticket.escalate", "ticket": "T-1002", "agent": "agent-c",
         "oversight": "unrecorded"},
    ],
    "audit-archive": [
        {"action": "policy.update", "policy": "retention", "agent": "agent-a",
         "oversight": "human_approved", "reviewer": "reviewer-1"},
    ],
}

for chain_id, payloads in DEMO.items():
    trail = chains / chain_id / "trail.jsonl"
    if trail.exists():
        print(f"  {chain_id}: already present, left alone")
        continue
    trail.parent.mkdir(parents=True, exist_ok=True)
    log = AuditLog.open(trail)
    for payload in payloads:
        log.append(payload=payload, payload_type="application/vnd.waxseal-demo.decision+json")
    print(f"  {chain_id}: {len(payloads)} entries")
PYEOF
step "Done"
