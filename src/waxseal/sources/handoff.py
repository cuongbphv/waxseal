"""Cross-trail handoff binding: record it, when there are two real trails.

A general-purpose recorder, not tied to any one integration: ANY
integration/source that hands work between two agents keeping SEPARATE trails
can call ``record_handoff`` on the delegate's own log. It is deliberately not
threaded through ``integrations/openai_agents.py``'s ``WaxsealRunHooks`` --
that hook is built around ONE ``AuditLog`` shared by every agent in a run
(one ``self._trail`` per ``WaxsealRunHooks`` instance, no per-agent trail
selection), so there is no second trail for a binding to point at today. See
that module's docstring / the waxseal-otj commit message for the measurement.
"""

from __future__ import annotations

from waxseal.domain.handoff import HANDOFF_PAYLOAD_TYPE, HandoffBinding, to_payload
from waxseal.domain.header import Entry
from waxseal.log import AuditLog


def record_handoff(
    log: AuditLog,
    *,
    chain_id: str,
    seq: int,
    head_hash: str,
) -> Entry:
    """Append a handoff-binding entry to ``log`` (the DELEGATE's own trail),
    pointing at ``(chain_id, seq, head_hash)`` -- typically the ORIGIN
    trail's identity, current tip seq, and current ``entry_hash`` at the
    moment of delegation (``origin_log.entry_hashes()[-1]``).

    Call this on the delegate's trail, never the origin's own: a
    self-referential binding would commit a trail to its own tip, which its
    ``prev_hash`` chain already proves for free.
    """
    binding = HandoffBinding(chain_id=chain_id, seq=seq, head_hash=head_hash)
    return log.append(payload=to_payload(binding), payload_type=HANDOFF_PAYLOAD_TYPE)
