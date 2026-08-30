"""End-to-end demo: waxseal-audit hook running under the REAL hermes-agent
HookRegistry, then four attack/failure scenarios against the produced trail.

Requires an environment with BOTH hermes-agent and waxseal installed.
Run:  HERMES_HOME=<tmp> python e2e_demo.py

Scenarios:
  1. An agent session is audited through real hook dispatch -> verify exit 0
  2. Attacker rewrites a past action (hide an exfil command) -> verify exit 1
  3. Attacker deletes an entry                                -> verify exit 1 (seq_gap)
  4. Schema skew (the beads-v1.2.2 class): rows written by a NEWER schema are
     read by this binary -> exit 2 "unverifiable", NOT a false tampering alarm
  5. Secret in tool args (issue #487's concern) is redacted before disk
  6. The mirror of 4: ordinary rows read by an OUT-OF-DATE verifier, which
     must report them unverifiable rather than tampered
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

PASS = "PASS"
FAIL = "FAIL"
results: list[tuple[str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    results.append((PASS if ok else FAIL, name))
    print(f"  [{PASS if ok else FAIL}] {name}" + (f" — {detail}" if detail else ""))


def run_verify(trail: Path) -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, "-m", "waxseal.cli", "verify", str(trail)],
        capture_output=True,
        text=True,
    )
    return proc.returncode, proc.stdout.strip()


def main() -> int:
    home = Path(tempfile.mkdtemp(prefix="hermes-home-"))
    os.environ["HERMES_HOME"] = str(home)
    trail = home / "audit" / "trail.jsonl"

    # --- install the hook exactly the way a user would -----------------------
    hook_src = Path(__file__).parent
    hook_dst = home / "hooks" / "waxseal-audit"
    hook_dst.mkdir(parents=True)
    for name in ("HOOK.yaml", "handler.py"):
        shutil.copy(hook_src / name, hook_dst / name)

    # --- drive the REAL hermes-agent hook registry ---------------------------
    import gateway.hooks as gh

    gh.HOOKS_DIR = home / "hooks"  # module-level constant resolved at import
    registry = gh.HookRegistry()
    registry.discover_and_load()
    assert any(h["name"] == "waxseal-audit" for h in registry.loaded_hooks), (
        "hook was not discovered by hermes-agent"
    )

    async def session() -> None:
        ctx = {"platform": "telegram", "user_id": "u1", "chat_id": "c1", "session_id": "s1"}
        await registry.emit("session:start", ctx)
        await registry.emit("agent:start", {**ctx, "message": "deploy the service"})
        await registry.emit(
            "agent:step",
            {**ctx, "message": "tool=bash cmd='export TOKEN=sk-secret1234567890abcdef && deploy'"},
        )
        await registry.emit("agent:step", {**ctx, "message": "tool=bash cmd='kubectl apply -f'"})
        await registry.emit("agent:end", {**ctx, "response": "deployed"})

    asyncio.run(session())

    print("\nScenario 1 — audited session verifies clean")
    code, out = run_verify(trail)
    check("hook wrote a verifiable chain (exit 0)", code == 0, out)

    print("\nScenario 5 — secrets never reach disk (issue #487 concern)")
    import base64

    # Payloads are stored base64 — decode them, otherwise the absence check
    # passes vacuously against encoded bytes.
    decoded = b"\n".join(
        base64.b64decode(json.loads(line)["payload_b64"])
        for line in trail.read_text().splitlines()
    )
    check("cleartext secret absent from decoded payloads",
          b"sk-secret1234567890abcdef" not in decoded)
    check("redaction marker present in decoded payloads", b"***REDACTED***" in decoded)

    print("\nScenario 2 — attacker rewrites a past action")
    tampered = home / "audit" / "tampered.jsonl"
    lines = trail.read_text().splitlines()
    obj = json.loads(lines[3])  # the kubectl step
    payload = json.loads(base64.b64decode(obj["payload_b64"]))
    payload["message"] = "tool=bash cmd='ls'"  # hide what really ran
    obj["payload_b64"] = base64.b64encode(json.dumps(payload).encode()).decode()
    lines[3] = json.dumps(obj)
    tampered.write_text("\n".join(lines) + "\n")
    code, out = run_verify(tampered)
    check("edit detected (exit 1)", code == 1, out)
    check("break located at seq=3", "seq=3" in out)

    print("\nScenario 3 — attacker deletes an entry")
    deleted = home / "audit" / "deleted.jsonl"
    deleted.write_text("\n".join(lines[:2] + lines[3:]) + "\n")
    code, out = run_verify(deleted)
    check("deletion detected (exit 1)", code == 1, out)
    check("reason is seq_gap", "seq_gap" in out)

    print("\nScenario 4 — schema skew (beads-v1.2.2 class): newer writer, older verifier")
    from waxseal.domain.fingerprint import HEADER_FIELDS, fingerprint_for
    from waxseal.domain.hashing import compute_entry_hash, compute_payload_hash
    from waxseal.domain.header import EntryHeader

    future = home / "audit" / "future.jsonl"
    lines_f = trail.read_text().splitlines()
    last = json.loads(lines_f[-1])
    new_payload = b'{"event":"agent:start","written_by":"waxseal vNEXT"}'
    header = EntryHeader(
        seq=last["header"]["seq"] + 1,
        ts="2026-08-21T07:00:00+00:00",
        # A widened schema this binary has never seen:
        hash_version=fingerprint_for((*HEADER_FIELDS, "agent_id")),
        payload_type="application/vnd.hermes.hook-event+json",
        payload_hash=compute_payload_hash(new_payload),
        prev_hash=last["entry_hash"],
    )
    lines_f.append(
        json.dumps(
            {
                "header": header.__dict__ if hasattr(header, "__dict__") else {
                    "seq": header.seq, "ts": header.ts, "hash_version": header.hash_version,
                    "payload_type": header.payload_type, "payload_hash": header.payload_hash,
                    "prev_hash": header.prev_hash,
                },
                "entry_hash": compute_entry_hash(header),
                "payload_b64": base64.b64encode(new_payload).decode(),
            }
        )
    )
    future.write_text("\n".join(lines_f) + "\n")
    code, out = run_verify(future)
    check("unknown schema -> exit 2, not broken", code == 2, out)
    check("reported unverifiable, NOT tampering", "NOT evidence of tampering" in out)

    print("\nScenario 6 — a verifier that does not recognise the schema")
    from waxseal.adapters.jsonl import JSONLBackend
    from waxseal.domain.fingerprint import fingerprint
    from waxseal.domain.registry import VersionRegistry
    from waxseal.domain.verify import verify_chain

    # Scenario 4 forges a row from a FUTURE schema. This is the mirror image,
    # and the commoner case in practice: the rows are ordinary and it is the
    # VERIFIER that is out of date -- a rolled-back binary reading a trail
    # written by a build it predates. It must say so, not cry tampering.
    written = list(JSONLBackend(trail).entries())
    check(
        "the hook stamped every row with the derived schema fingerprint",
        bool(written) and all(e.header.hash_version == fingerprint() for e in written),
        f"hash_version={fingerprint()[:12]}...",
    )

    class OutdatedVerifier(VersionRegistry):
        """A build predating this schema: it recognises no fingerprint at all.

        Overriding encoder_for is enough -- recomputable() is defined in terms
        of it, so the two can never disagree about what this build can verify.
        """

        def encoder_for(self, fingerprint_: str):
            return None

    rolled_back = verify_chain(written, OutdatedVerifier())
    check(
        "it reports them unverifiable, NOT tampered",
        rolled_back.ok
        and rolled_back.broken_seq is None
        and len(rolled_back.unverifiable) == len(written),
        f"unverifiable={list(rolled_back.unverifiable)} broken_seq={rolled_back.broken_seq}",
    )

    print()
    failed = [name for status, name in results if status == FAIL]
    print(f"{len(results) - len(failed)}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
