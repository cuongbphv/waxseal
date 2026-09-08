"""waxseal-audit sink for Microsoft AGT (agent-governance-toolkit).

Attach a `WaxsealAuditSink` to AGT's own governance `AuditLog` to chain every
governance decision (policy evaluation, approval, advisory check) onto a
tamper-evident hash chain:

    from agentmesh.governance import AuditLog as AGTAuditLog
    from waxseal.integrations.agt import WaxsealAuditSink

    audit = AGTAuditLog(sink=WaxsealAuditSink(trail_path))
    audit.log(event_type="policy_evaluation", agent_did="did:web:agent-1",
              action="read_file", outcome="allow", policy_decision="allow")

The trail argument is optional: with none given, `WAXSEAL_TRAIL` is honoured,
and `DEFAULT_TRAIL` is the last resort. An argument passed here always wins
over the environment.

Contract verified against ``agent-governance-toolkit`` 4.1.0 and
``agent-governance-toolkit-core`` 4.1.0 (real PyPI wheels, downloaded with
``pip download`` and read directly, 2026-09-01 — not the README, per
CLAUDE.md Condition R; the finding below was re-checked against
``agent-governance-toolkit-core`` 5.0.0, the newest core release, and holds
there too):

- The package installed by ``pip install agent-governance-toolkit`` is a
  thin meta-installer: its only importable module is ``agent_compliance``
  (supply-chain/prompt-defense/lint/CLI tooling). The actual governance
  RUNTIME is the separate ``agent-governance-toolkit-core`` wheel, importing
  as ``agentmesh`` and ``agent_os`` — ``agent-governance-toolkit``'s
  ``[core]`` extra pins ``agent-governance-toolkit-core<5.0,>=4.0.0``, so
  4.1.0 is what an actual install resolves.
- The README's ``govern()`` is real:
  ``agentmesh.governance.govern.govern(fn, *, policy, agent_id="*",
  audit=True, on_deny=None, approval_handler=None, advisory=None,
  conflict_strategy="deny_overrides", ring=None, session_id="")`` wraps any
  callable in a ``GovernedCallable``, evaluates policy via ``PolicyEngine``,
  and (`GovernedCallable.__call__`) logs the decision to an internal
  ``AuditLog`` BEFORE calling the wrapped function — the log call sits
  ahead of ``return self._fn(*args, **kwargs)`` in every path, allow or
  deny. That confirms the plan's "write before execution, when the
  extension point allows it": AGT's own audit call already runs
  pre-execution, and any sink attached to that ``AuditLog`` inherits the
  same ordering.
- BUT ``GovernanceConfig``/``GovernedCallable`` construct that internal log
  as ``self._audit = AuditLog() if config.audit else None`` — no field on
  ``GovernanceConfig`` threads a custom sink through ``govern()`` itself, in
  EITHER 4.1.0 or 5.0.0 core (``GovernanceConfig.audit_file`` is accepted
  but never read by ``GovernedCallable.__init__`` in either version read —
  a dead field). **Deviation from the plan's framing ("govern() accepts an
  audit-backend callback"): it does not, directly.** This is an upstream
  API gap, not a waxseal choice — recorded here rather than routed around
  silently (CLAUDE.md rule 6).
- The real, exported, documented extension point sits one level down:
  ``agentmesh.governance.audit_backends.AuditSink``, a
  ``@runtime_checkable Protocol`` — ``write(entry: AuditEntry) -> None``,
  ``write_batch(entries: list[AuditEntry]) -> None``,
  ``verify_integrity() -> tuple[bool, str | None]``, ``close() -> None``.
  ``agentmesh.governance.audit.AuditLog.__init__(self, *, sink: AuditSink |
  None = None)`` calls ``self._sink.write(entry)`` synchronously inside
  ``AuditLog.log()``, for every entry, with NO try/except around that call
  — a genuinely constructor-injected, structurally-typed pluggable backend
  (its own docstring: "An optional external AuditSink can be provided to
  persist entries to an external store with cryptographic integrity"),
  exactly the shape this codebase's own ``ports/`` pattern already uses.
  ``AuditSink`` and ``AuditLog`` are both re-exported at the
  ``agentmesh.governance`` package level.
- ``AuditEntry`` (a pydantic model, ``agentmesh.governance.audit.AuditEntry``)
  carries: ``event_type``, ``agent_did`` (agent identity), ``action`` /
  ``resource`` / ``data`` (the requested action), ``outcome`` (one of
  success/failure/denied/error) plus ``policy_decision`` / ``matched_rule``
  / ``policy_version`` (policy in effect and its verdict). AGT has no
  dedicated top-level "reason" field on ``AuditEntry`` itself —
  ``GovernedCallable`` puts the human-readable reason inside
  ``data["reason"]``, so this sink reads it from there.
  ``AuditEntry`` carries no model identity at all (no ``model``/
  ``model_name``/``model_version`` field anywhere in the schema) — see
  ``_decision_payload`` below for how that gap is handled, not hidden.
- Because ``govern()`` cannot be handed a sink directly, the wiring this
  module targets is ``AuditLog(sink=...)`` used DIRECTLY: standalone at an
  operator's own governance checkpoints, or (undocumented, no public
  setter) by reaching into ``governed._audit`` post-construction. Recorded
  here as an owner-decision item, not smoothed over.
- Never-veto is held exactly as strictly as the other 8 integrations, with
  one addition: unlike every host the other 8 attach to, AGT's own
  ``AuditLog.log()`` does **not** swallow a sink exception — a raise here
  would abort whatever governed call triggered the audit. Every failure
  path below (open failure, malformed entry, a failed append) degrades to
  a labelled, counted dropped write instead, same discipline, held one
  layer more defensively because upstream offers no safety net of its own.

Ships in the wheel: ``pip install waxseal agent-governance-toolkit[core]``,
then import from waxseal.integrations.agt, with no file copying. AGT is
"Public Preview — may have breaking changes before GA" (its own README);
this module pins the version verified above and imports NOTHING from
``agent_governance_toolkit``/``agentmesh``/``agent_os`` at all — ``AuditSink``
is a structural Protocol, so satisfying it needs no import, and CI does not
depend on AGT being installed (waxseal-fg4 Workstream H).
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from waxseal import AuditLog
from waxseal.adapters.redactors import RegexRedactor
from waxseal.domain.decision import (
    DECISION_PAYLOAD_TYPE,
    DecisionRecord,
    HumanOversight,
    ModelRef,
)
from waxseal.domain.decision import to_payload as _decision_to_payload
from waxseal.integrations import _sanitize as _sanitize_impl
from waxseal.integrations._trail import home_default, resolve_trail

MAX_FIELD_CHARS = _sanitize_impl.MAX_FIELD_CHARS
_sanitize = _sanitize_impl.sanitize

PAYLOAD_TYPE = "application/vnd.waxseal.agt-event+json"

#: Where this integration writes when the caller names no path and
#: `WAXSEAL_TRAIL` is unset.
DEFAULT_TRAIL = "~/.waxseal/agt-trail.jsonl"


def _commitment(payload: dict[str, Any]) -> str:
    """SHA-256 hex digest of the already-redacted action payload.

    ``DecisionRecord.input_commitment`` must commit to redacted data, never
    raw input (domain/decision.py: "so the trail carries no customer
    data") — ``payload`` here has already been through `_sanitize`, so this
    hashes text with no cleartext secret in it.
    """
    canonical = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _oversight_for(entry: Any) -> HumanOversight | None:
    """AGT's only human-review signal on ``AuditEntry`` is ``approver_did``,
    set exclusively on ``approval_decision`` events. Every other event type
    (deterministic policy evaluation) carries none — and CLAUDE.md's own
    ``domain/report.py`` draws the line this function must not blur:
    ``human_oversight=None`` means "AGT did not say", counted as
    unrecorded; it is never rendered as ``HumanOversight(mode="unrecorded")``,
    because an institution may legitimately use that literal string as one
    of ITS OWN oversight modes, and "nobody wrote it down" must not read as
    "a human reviewed it and recorded the word 'unrecorded'".
    """
    approver = getattr(entry, "approver_did", None)
    if not approver:
        return None
    return HumanOversight(mode="agt_approval", reviewer_ref=str(approver))


class WaxsealAuditSink:
    """Structural implementation of
    ``agentmesh.governance.audit_backends.AuditSink``.

    No import of ``agent_governance_toolkit``/``agentmesh`` is performed or
    required: ``AuditSink`` is a ``@runtime_checkable Protocol`` (duck
    typed), so this class satisfies it purely by shape — ``write``,
    ``write_batch``, ``verify_integrity``, ``close``. ``entry`` arrives as
    AGT's ``AuditEntry`` (a pydantic model) but is read here only via
    ``getattr``, never ``isinstance``-checked against an AGT type, which is
    the other half of why no import is needed.
    """

    def __init__(
        self,
        trail: Path | str | None = None,
        *,
        model: ModelRef | None = None,
        system_id: str = "agt",
    ) -> None:
        """``trail`` wins over `WAXSEAL_TRAIL`, which wins over
        `DEFAULT_TRAIL` — same precedence as every other library-style
        integration in this package.

        ``model`` is this sink's answer to the model-identity gap: AGT's
        ``AuditEntry`` carries no model name/version/digest anywhere in its
        schema (verified above), but ``DecisionRecord.model`` is a required
        ``ModelRef`. A caller wiring this sink into an agent framework
        usually DOES know which model is running, even though AGT's own
        audit event does not say — so `model` is accepted here, at the
        sink, rather than invented per-entry. Left ``None`` (the default),
        every entry stays a plain agt-event: that is "the shape does not
        match" (CLAUDE.md/plan wording), not a silent downgrade.
        """
        self._trail = resolve_trail(trail, default=lambda: home_default(DEFAULT_TRAIL))
        self._log: AuditLog | None = None
        self._model = model
        self._system_id = system_id

    # -- AuditSink protocol ------------------------------------------------

    def write(self, entry: Any) -> None:
        self._write_one(entry)

    def write_batch(self, entries: list[Any]) -> None:
        for entry in entries:
            self._write_one(entry)

    def verify_integrity(self) -> tuple[bool, str | None]:
        """Delegate to waxseal's own verifier (CLAUDE.md rule 4: verify
        reports, never repairs — this sink does not re-implement chain
        verification, it opens the trail read-only and relays the verdict).
        """
        try:
            result = AuditLog.open(self._trail).verify(measure_drops=False)
        except Exception as e:  # broken/absent trail: not (False, exception)
            return False, f"cannot open trail for verification: {e}"
        return result.ok, result.reason

    def close(self) -> None:
        """No resource to release: like every other library-style
        integration (crewai, langchain, openai_agents), this sink re-opens
        the backend per write rather than holding a handle across calls."""
        return None

    # -- internals -----------------------------------------------------

    def _payload_for(self, entry: Any) -> dict[str, Any]:
        data = getattr(entry, "data", None)
        data = data if isinstance(data, dict) else {}
        return {
            "event_type": getattr(entry, "event_type", None),
            "agent_did": getattr(entry, "agent_did", None),
            "action": getattr(entry, "action", None),
            "resource": getattr(entry, "resource", None),
            "outcome": getattr(entry, "outcome", None),
            "policy_decision": getattr(entry, "policy_decision", None),
            "matched_rule": getattr(entry, "matched_rule", None),
            "policy_version": getattr(entry, "policy_version", None),
            "reason": _sanitize(data.get("reason")),
            "data": _sanitize(data),
            "entry_id": getattr(entry, "entry_id", None),
            "trace_id": getattr(entry, "trace_id", None),
            "session_id": getattr(entry, "session_id", None),
        }

    def _decision_payload(self, entry: Any, payload: dict[str, Any]) -> dict[str, Any] | None:
        """Best-effort ``DecisionRecord`` mapping. Returns ``None`` — "the
        shape does not match" — whenever the record would fail to commit to
        real evidence: no configured ``model`` (CLAUDE.md/plan: "matched
        khi hình dạng khớp"), or a missing identifier/action/outcome that
        ``DecisionRecord.__post_init__`` would reject anyway. A record that
        commits to nothing is worse than no record (domain/decision.py).
        """
        if self._model is None:
            return None
        entry_id = payload.get("entry_id")
        action = payload.get("action")
        outcome = payload.get("outcome")
        if not entry_id or not action or not outcome:
            return None
        try:
            record = DecisionRecord(
                decision_id=str(entry_id),
                decision_type=str(payload.get("event_type") or "agt-governance"),
                system_id=self._system_id,
                model=self._model,
                input_commitment=_commitment(payload),
                outcome=str(outcome),
                rationale=payload.get("reason"),
                policy_version=payload.get("policy_version"),
                human_oversight=_oversight_for(entry),
                trace_id=payload.get("trace_id"),
            )
        except ValueError:
            # A malformed field (e.g. an empty-string outcome) is "does not
            # match", not a crash: fall back to the plain agt-event below.
            return None
        return _decision_to_payload(record)

    def _open_log(self) -> AuditLog | None:
        if self._log is not None:
            return self._log
        try:
            self._log = AuditLog.open(self._trail, redactor=RegexRedactor(), record_drops=True)
        except Exception as e:  # broken environment: never abort the governed call
            print(f"[waxseal-audit] cannot open trail (entry dropped): {e}", file=sys.stderr)
            # No AuditLog to route this through, so record it directly,
            # best-effort (FileDropRecorder.record() never raises).
            from waxseal.adapters.drops import FileDropRecorder

            FileDropRecorder(self._trail).record(
                reason=type(e).__name__, payload_type=PAYLOAD_TYPE
            )
            return None
        return self._log

    def _write_one(self, entry: Any) -> None:
        try:
            payload = self._payload_for(entry)
        except Exception as e:
            # Unlike the other 8 integrations' hosts, AGT's AuditLog.log()
            # does not swallow this call — a raise here aborts the governed
            # action, so an unexpected entry shape must be caught HERE.
            print(
                f"[waxseal-audit] cannot read AGT audit entry (entry dropped): {e}",
                file=sys.stderr,
            )
            from waxseal.adapters.drops import FileDropRecorder

            FileDropRecorder(self._trail).record(
                reason=type(e).__name__, payload_type=PAYLOAD_TYPE
            )
            return
        log = self._open_log()
        if log is None:
            return
        decision_payload = self._decision_payload(entry, payload)
        record_payload = decision_payload if decision_payload is not None else payload
        record_type = DECISION_PAYLOAD_TYPE if decision_payload is not None else PAYLOAD_TYPE
        if not log.try_append(payload=record_payload, payload_type=record_type):
            # Labelled fail-open (chain integrity ≠ trail completeness).
            print(
                f"[waxseal-audit] dropped write for {payload.get('event_type')!r} "
                f"(total dropped: {log.dropped_writes})",
                file=sys.stderr,
            )
