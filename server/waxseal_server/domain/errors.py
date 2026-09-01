"""The vocabulary of failure, in one place.

Each of these names a distinct thing that can be wrong, and the API layer maps
each to exactly one status code. They live together because the distinctions
between them are the point: "no log" and "unreadable log" reach different
screens, and a shared base class would invite a single `except` that erased the
difference.

Nothing here imports FastAPI. The layer that knows about HTTP does the mapping;
the layer that knows about trails does the deciding.
"""

from __future__ import annotations


class InvalidIdentifier(ValueError):
    """An id that is not a safe single path segment (HTTP 400).

    Checked on the value, never on the resolved path: there is then nothing to
    normalize around and no `..` to reason about.
    """


class MalformedEnvelope(ValueError):
    """A body that is not the shape SPEC.md section 7 defines (HTTP 400)."""


class PreconditionFailed(Exception):
    """The CAS on `(header.seq, header.prev_hash)` did not hold (HTTP 409).

    Not an error about the entry: it is the answer to "is this still the tail?",
    and the client's correct response is to re-read `/head` and rebuild against
    the fresh one.
    """


class DamagedReceiptLog(Exception):
    """A receipt log line this build cannot parse at all (HTTP 422).

    Distinct from "no log" on purpose: "there is nothing to read" and "I could
    not read it" send an operator to different places, and collapsing them is
    the failure this whole codebase is organised against.
    """


class UnsupportedTrailFormat(ValueError):
    """An upload waxseal has no backend for (HTTP 400)."""


class OperatorExists(Exception):
    """An operator with that username is already registered (HTTP 409).

    Never a silent update: two callers seeding the same name is a deployment
    mistake worth surfacing, not a last-write-wins race over who is an admin.
    """


class NoSuchOperator(Exception):
    """A key was requested for an operator that does not exist (HTTP 404).

    Creating the operator instead would mint a credential with no role, which
    is worse than no credential.
    """


class NoSuchSetting(Exception):
    """A setting key that is not in the registry (HTTP 404).

    Covers two different refusals and says which in the message: a key nobody
    defined, and a key deliberately kept out of the store because it is a
    credential or a bootstrap value. Both are refusals rather than 400s — the
    request is well formed, the setting simply is not one this server has.

    Accepting an unknown key would be worse than refusing it: a typo that saves
    cleanly is indistinguishable from a change that took effect.
    """
