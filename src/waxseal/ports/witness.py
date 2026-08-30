"""WitnessReader: the read side of an anchor sink.

``AnchorSink`` publishes a checkpoint and forgets it. That is enough to make a
rewrite detectable by whoever holds the receipt, but it never closes the loop
back to the client: a split-view server can serve one history to this client
and another elsewhere, and the client publishing its own head learns nothing
about that.

Reading back does close it. If the auditor and the operator publish to the same
witness, each sees checkpoints the other's view has to be consistent with, and
the server has to fork the witness too, which is a different administrative
domain, and the point of the exercise. A witness read back from the same
authority that serves the chain proves nothing at all.

Unreachability is the caller's to interpret, so implementations RAISE rather
than returning an empty observation: an empty answer means "I have seen
nothing", a raise means "I could not ask", and a verifier must never render
the second as the first.
"""

from __future__ import annotations

from typing import Protocol

from waxseal.domain.witnessing import WitnessObservation


class WitnessReader(Protocol):
    name: str

    def fetch(self) -> WitnessObservation:
        """What this witness has seen, oldest checkpoint first.

        Raise on unreachability or an unusable response. Returning an empty
        observation for a witness that could not be contacted would report a
        failed check as zero coverage, which a caller cannot tell apart from
        a witness that genuinely holds nothing.
        """
        ...
