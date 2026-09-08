"""End-to-end demo: WaxsealRunHooks exercised with REAL OpenAI Agents SDK
objects — a real Agent, a real @function_tool FunctionTool, and a real
ToolContext (the exact context object Runner passes to hooks for function
tools) — then four attack/failure scenarios against the produced trail.

Requires openai-agents and waxseal installed. Run:  python e2e_demo.py

Honest scope: a full Runner.run needs a model provider and API key, so this
demo awaits the hook coroutines directly with the same (context, agent,
tool, result) objects Runner would pass. The isinstance gate that Runner
type-checks hooks against is asserted explicitly.

Scenarios:
  1. Agent start -> tool dispatch/result -> handoff -> agent end -> exit 0
  2. Attacker rewrites a past action (hide an exfil command) -> verify exit 1
  3. Attacker deletes an entry                                -> exit 1 (seq_gap)
  4. Schema skew (the beads-v1.2.2 class): rows written by a NEWER schema are
     read by this binary -> exit 2 "unverifiable", NOT a false tampering alarm
  5. Secret in tool arguments is redacted before disk
  6. The mirror of 4: ordinary rows read by an OUT-OF-DATE verifier, which
     must report them unverifiable rather than tampered
"""

from __future__ import annotations

import asyncio
import base64
import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from agents import Agent, function_tool  # noqa: E402
from agents.lifecycle import RunHooksBase  # noqa: E402
from agents.tool_context import ToolContext  # noqa: E402
from hooks import WaxsealRunHooks  # noqa: E402

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


@function_tool
def run_shell(command: str) -> str:
    """Pretend to run a shell command."""
    return f"ran: {command}"


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="openai-agents-e2e-"))
    trail = tmp / "trail.jsonl"
    audit = WaxsealRunHooks(trail)
    # agents.RunHooks is a subscripted alias of RunHooksBase; the base class
    # is what instance checks (and Runner's typing) resolve against.
    check("hooks are a real RunHooksBase instance", isinstance(audit, RunHooksBase))

    agent = Agent(name="devops", instructions="deploy things", tools=[run_shell])
    specialist = Agent(name="specialist", instructions="fix things")

    def tool_ctx(call_id: str, arguments: str) -> ToolContext:
        # The exact context object Runner builds for function-tool hooks.
        return ToolContext(
            context=None,
            tool_name=run_shell.name,
            tool_call_id=call_id,
            tool_arguments=arguments,
        )

    async def session() -> None:
        secret_args = '{"command": "export GITHUB_TOKEN=ghp_16C7e42F292c6912E7710c838347Ae178B4a"}'
        deploy_args = '{"command": "kubectl apply -f deploy.yaml"}'
        await audit.on_agent_start(tool_ctx("c0", "{}"), agent)
        await audit.on_tool_start(tool_ctx("c1", secret_args), agent, run_shell)
        await audit.on_tool_end(tool_ctx("c1", secret_args), agent, run_shell, "ran: export …")
        await audit.on_tool_start(tool_ctx("c2", deploy_args), agent, run_shell)
        await audit.on_tool_end(tool_ctx("c2", deploy_args), agent, run_shell, "ran: kubectl …")
        await audit.on_handoff(tool_ctx("c3", "{}"), agent, specialist)
        await audit.on_agent_end(tool_ctx("c4", "{}"), specialist, "deployed")

    asyncio.run(session())

    print("\nScenario 1 — audited run verifies clean")
    code, out = run_verify(trail)
    check("hooks wrote a verifiable chain (exit 0)", code == 0, out)
    decoded_lines = [
        json.loads(base64.b64decode(json.loads(line)["payload_b64"]))
        for line in trail.read_text().splitlines()
    ]
    phases = [p["phase"] for p in decoded_lines]
    check(
        "full lifecycle recorded (start/dispatch/result/handoff/end)",
        phases
        == ["agent_start", "dispatch", "result", "dispatch", "result", "handoff", "agent_end"],
        str(phases),
    )

    print("\nScenario 5 — secret in tool arguments never reaches disk")
    decoded = json.dumps(decoded_lines).encode()
    check(
        "GitHub token absent from decoded payloads",
        b"ghp_16C7e42F292c6912E7710c838347Ae178B4a" not in decoded,
    )
    check("redaction marker present in decoded payloads", b"***REDACTED***" in decoded)

    print("\nScenario 2 — attacker rewrites a past action")
    lines = trail.read_text().splitlines()
    obj = json.loads(lines[3])  # the kubectl dispatch
    payload = json.loads(base64.b64decode(obj["payload_b64"]))
    payload["tool_arguments"] = '{"command": "ls"}'  # hide what really ran
    obj["payload_b64"] = base64.b64encode(json.dumps(payload).encode()).decode()
    tampered = tmp / "tampered.jsonl"
    tampered.write_text("\n".join(lines[:3] + [json.dumps(obj)] + lines[4:]) + "\n")
    code, out = run_verify(tampered)
    check("edit detected (exit 1)", code == 1, out)
    check("break located at seq=3", "seq=3" in out)

    print("\nScenario 3 — attacker deletes an entry")
    deleted = tmp / "deleted.jsonl"
    deleted.write_text("\n".join(lines[:3] + lines[4:]) + "\n")
    code, out = run_verify(deleted)
    check("deletion detected (exit 1)", code == 1, out)
    check("reason is seq_gap", "seq_gap" in out)

    print("\nScenario 4 — schema skew (beads-v1.2.2 class): newer writer, older verifier")
    from waxseal.domain.fingerprint import HEADER_FIELDS, fingerprint_for
    from waxseal.domain.hashing import compute_entry_hash, compute_payload_hash
    from waxseal.domain.header import EntryHeader

    last = json.loads(lines[-1])
    new_payload = b'{"phase":"dispatch","written_by":"waxseal vNEXT"}'
    header = EntryHeader(
        seq=last["header"]["seq"] + 1,
        ts="2026-08-21T07:00:00+00:00",
        hash_version=fingerprint_for((*HEADER_FIELDS, "agent_id")),
        payload_type="application/vnd.openai-agents.run-event+json",
        payload_hash=compute_payload_hash(new_payload),
        prev_hash=last["entry_hash"],
    )
    future = tmp / "future.jsonl"
    future.write_text(
        "\n".join(
            lines
            + [
                json.dumps(
                    {
                        "header": {
                            "seq": header.seq,
                            "ts": header.ts,
                            "hash_version": header.hash_version,
                            "payload_type": header.payload_type,
                            "payload_hash": header.payload_hash,
                            "prev_hash": header.prev_hash,
                        },
                        "entry_hash": compute_entry_hash(header),
                        "payload_b64": base64.b64encode(new_payload).decode(),
                    }
                )
            ]
        )
        + "\n"
    )
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
