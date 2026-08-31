"""Never-raise fuzzing sweep across EVERY verifier entry point (waxseal-lmv).

CLAUDE.md's own normative rule -- stated piecemeal across module docstrings
("Never raises", "Fails closed and never raises", "fails closed") and the
Locked Design section's "Unknown fingerprint -> ... NEVER a crash" -- is that
a function checking hostile input (an attacker-writable trail, sidecar,
anchor record, RFC 3161 token, OTS receipt, or proof bundle) must never let
an unanticipated exception escape. Before this file, that promise was
checked only in scattered per-function tests (grep hits:
tests/test_anchored_log.py, tests/test_auditlog.py,
tests/test_sources_openclaw.py, tests/domain/test_pinning.py,
tests/domain/test_witnessing.py, tests/domain/test_rfc3161.py,
tests/domain/test_anchored_aggregate.py) -- nothing enumerated the whole set.

Discovery, not a hand-typed list
---------------------------------
A hardcoded list of "verifier entry points" rots the moment a new module or
function is added -- exactly the failure this bead exists to prevent. This
file instead DEFINES the class systematically and DISCOVERS it via
``inspect``/``pkgutil`` module walking (see ``discover_entry_points`` below):

    A "verifier entry point" is any public (no leading underscore) top-level
    function, actually defined (not merely re-exported) in a module under
    ``waxseal.domain`` or in ``waxseal.adapters.anchors``, whose name matches
    ``^(verify|check|parse|decode|read)_`` or ends in ``_from_json``, OR
    whose docstring contains "never raise", "fails closed", or
    "fail-closed" (case-insensitive).

The name prefixes catch the checkers (``verify_*``, ``check_*``) and the
boundary parsers that read hostile bytes/JSON/DER (``parse_*``, ``decode_*``,
``read_*``, ``bundle_from_json``); the docstring phrases catch the few
(``anchor_staleness``, ``anchor_policy_downgrade``) that name the same
contract without a matching prefix. ``adapters.anchors`` is included by name
(not swept module-by-module across all of ``adapters/``) because it is the
one adapter this bead's own text calls out: "an unknown 'v' is unverifiable,
not a crash" -- the rest of ``adapters/`` is I/O plumbing, not hostile-input
parsing, and sweeping it would just re-discover ``read_drop_count`` (a plain
sidecar line count, not a verifier) and invite completeness failures
unrelated to this bead.

Self-updating completeness check
----------------------------------
``FUZZED_ENTRY_POINTS`` names, by qualified name, every function this file
has a dedicated fuzz test for. ``TestRegistryCompleteness`` asserts this set
is EXACTLY what ``discover_entry_points()`` finds right now -- in both
directions, so adding a new module/function matching the convention above
and forgetting to fuzz it fails loudly (a name discovery finds but the
registry lacks), and so does the registry drifting stale after a rename (a
name the registry claims but discovery no longer finds).

Known vs. unexpected exceptions
---------------------------------
Not every entry point's contract is "returns a verdict, raises nothing at
all" -- some (``bundle_from_json``, ``parse_pin_state``,
``parse_timestamp_resp``, ``read_anchor_records``) are documented to raise
ONE named, catchable exception type (or a small explicit set) on malformed
input, by design, so a CLI can turn it into a verdict. Both are "never raise
an UNEXPECTED exception": an ``AttributeError``/``IndexError`` from
malformed input reaching deep, un-hardened code is the bug either way. Each
fuzz test below only swallows the exception type(s) that function's own
docstring documents; anything else propagates and fails the test.
"""

from __future__ import annotations

import contextlib
import importlib
import inspect
import json
import pkgutil
import re
import tempfile
from datetime import datetime
from pathlib import Path

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

import waxseal.domain as _domain_pkg
from tests.domain.test_properties import _lone_surrogate_char, _text_with_lone_surrogate
from waxseal.adapters import anchors as _anchors_module
from waxseal.adapters.anchors import read_anchor_records
from waxseal.domain.anchoring import verify_consistency, verify_membership
from waxseal.domain.checkpoint import Checkpoint, verify_checkpoint
from waxseal.domain.export import (
    BUNDLE_VERSION,
    ProofBundle,
    bundle_from_json,
    verify_proof_bundle,
)
from waxseal.domain.fingerprint import fingerprint
from waxseal.domain.handoff import HandoffBinding, binding_holds
from waxseal.domain.header import GENESIS_PREV_HASH, Entry, EntryHeader
from waxseal.domain.ots import decode_receipt as ots_decode_receipt
from waxseal.domain.pinning import (
    PinState,
    PinStateError,
    anchor_policy_downgrade,
    anchor_staleness,
    check_pin,
    check_pin_target,
    parse_pin_state,
)
from waxseal.domain.registry import VersionRegistry
from waxseal.domain.rfc3161 import (
    DerError,
    check_timestamp_resp,
    parse_timestamp_resp,
    read_timestamp_resp,
)
from waxseal.domain.rfc3161 import decode_receipt as rfc3161_decode_receipt
from waxseal.domain.sealing import (
    FS_HMAC_AGG_SCHEME,
    FS_HMAC_SCHEME,
    Attestation,
    verify_aggregate,
    verify_anchored_aggregate,
    verify_seals,
)
from waxseal.domain.segments import (
    ROTATION_PAYLOAD_TYPE,
    SegmentRead,
    verify_segments,
)
from waxseal.domain.separation import SeparationTopology
from waxseal.domain.verify import VerifyResult, verify_chain
from waxseal.domain.witnessing import WitnessObservation, check_witnessed

# --------------------------------------------------------------------------
# Discovery: the definition of "verifier entry point" made executable.
# --------------------------------------------------------------------------

_NAME_PATTERN = re.compile(r"^(verify|check|parse|decode|read)_")
_DOC_PATTERN = re.compile(r"never raises?|fails? closed|fail-closed", re.IGNORECASE)

# The one adapters module this bead names explicitly (see module docstring).
_EXTRA_MODULES = (_anchors_module,)


def _is_entry_point(name: str, func: object) -> bool:
    if name.startswith("_") or not inspect.isfunction(func):
        return False
    doc = inspect.getdoc(func) or ""
    return bool(_NAME_PATTERN.match(name)) or name.endswith("_from_json") or bool(
        _DOC_PATTERN.search(doc)
    )


def discover_entry_points() -> dict[str, object]:
    """Every function currently matching the "verifier entry point"
    definition, across every ``waxseal.domain`` submodule and
    ``waxseal.adapters.anchors``. Keyed by ``"<module>.<name>"``.

    Uses ``pkgutil``/``inspect`` on the IMPORTED package, not a source-text
    scan: a function created dynamically or reached only via re-export is
    exactly the case a text grep would miss, and the whole point of this
    file is to not need updating when a new module lands.
    """
    modules = list(_EXTRA_MODULES)
    for info in pkgutil.iter_modules(_domain_pkg.__path__, prefix=f"{_domain_pkg.__name__}."):
        modules.append(importlib.import_module(info.name))

    found: dict[str, object] = {}
    for module in modules:
        for name, obj in inspect.getmembers(module, inspect.isfunction):
            if obj.__module__ != module.__name__:
                continue  # imported into this module, not defined here
            if _is_entry_point(name, obj):
                found[f"{module.__name__}.{name}"] = obj
    return found


# Every qualified name this file has a dedicated fuzz test for. Kept as an
# explicit set (not derived from discovery) so TestRegistryCompleteness can
# catch drift in EITHER direction -- see module docstring.
FUZZED_ENTRY_POINTS: frozenset[str] = frozenset(
    {
        "waxseal.domain.anchoring.verify_consistency",
        "waxseal.domain.anchoring.verify_membership",
        "waxseal.domain.checkpoint.verify_checkpoint",
        "waxseal.domain.export.bundle_from_json",
        "waxseal.domain.export.verify_proof_bundle",
        "waxseal.domain.handoff.binding_holds",
        "waxseal.domain.ots.decode_receipt",
        "waxseal.domain.pinning.anchor_policy_downgrade",
        "waxseal.domain.pinning.anchor_staleness",
        "waxseal.domain.pinning.check_pin",
        "waxseal.domain.pinning.check_pin_target",
        "waxseal.domain.pinning.parse_pin_state",
        "waxseal.domain.rfc3161.check_timestamp_resp",
        "waxseal.domain.rfc3161.decode_receipt",
        "waxseal.domain.rfc3161.parse_timestamp_resp",
        "waxseal.domain.rfc3161.read_timestamp_resp",
        "waxseal.domain.segments.verify_segments",
        "waxseal.domain.sealing.verify_aggregate",
        "waxseal.domain.sealing.verify_anchored_aggregate",
        "waxseal.domain.sealing.verify_seals",
        "waxseal.domain.verify.verify_chain",
        "waxseal.domain.witnessing.check_witnessed",
        "waxseal.adapters.anchors.read_anchor_records",
    }
)


class TestRegistryCompleteness:
    """The self-updating requirement itself: this must go red the moment a
    new never-raise-obligated function exists and this file has not been
    updated to fuzz it -- in EITHER direction (a new function appears, or a
    registered one no longer matches -- e.g. renamed)."""

    def test_every_discovered_entry_point_has_a_fuzz_test(self) -> None:
        discovered = set(discover_entry_points())
        missing = discovered - FUZZED_ENTRY_POINTS
        assert not missing, (
            f"discovered verifier entry point(s) with no fuzz test: {sorted(missing)} "
            "-- add a fuzz test above and register it in FUZZED_ENTRY_POINTS"
        )

    def test_registry_has_no_stale_entries(self) -> None:
        discovered = set(discover_entry_points())
        stale = FUZZED_ENTRY_POINTS - discovered
        assert not stale, (
            f"FUZZED_ENTRY_POINTS names function(s) discovery no longer finds "
            f"(renamed or removed?): {sorted(stale)}"
        )

    def test_discovery_finds_a_nonempty_known_set(self) -> None:
        # A guard against the discovery predicate itself silently matching
        # nothing (e.g. a typo'd regex) and this whole file passing vacuously.
        discovered = set(discover_entry_points())
        assert {
            "waxseal.domain.verify.verify_chain",
            "waxseal.adapters.anchors.read_anchor_records",
        } <= discovered


# --------------------------------------------------------------------------
# Shared hostile-value strategies.
# --------------------------------------------------------------------------

# Ordinary hostile unicode, PLUS lone UTF-16 surrogates (gap G4,
# tests/domain/test_properties.py) -- valid `str`, no UTF-8 form. Reused
# rather than redefined: this is the exact strategy that already caught the
# real bug this bead's fix addresses (verify_chain / verify_proof_bundle /
# verify_checkpoint crashing on one of these instead of returning a verdict).
_HOSTILE_TEXT = st.one_of(
    st.text(max_size=40),
    _lone_surrogate_char,
    _text_with_lone_surrogate,
)
_HEXLIKE = st.one_of(
    st.just(""),
    st.text(max_size=80),
    st.text(min_size=64, max_size=64, alphabet="0123456789abcdef"),
    _lone_surrogate_char,
)
_HOSTILE_INT = st.integers(min_value=-10_000, max_value=10_000)
_HOSTILE_BYTES = st.binary(max_size=400)

_FUZZ_SETTINGS = settings(
    max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow]
)


def _hostile_header() -> st.SearchStrategy[EntryHeader]:
    # hash_version is sometimes the REAL fingerprint (exercises the
    # "recomputable" path -- the one the LpEncodingError fix above lives in)
    # and sometimes garbage (exercises the "unverifiable" path).
    return st.builds(
        EntryHeader,
        seq=_HOSTILE_INT,
        ts=_HOSTILE_TEXT,
        hash_version=st.one_of(st.just(fingerprint()), _HEXLIKE),
        payload_type=_HOSTILE_TEXT,
        payload_hash=_HEXLIKE,
        prev_hash=st.one_of(st.just(GENESIS_PREV_HASH), _HEXLIKE),
    )


def _hostile_entry() -> st.SearchStrategy[Entry]:
    return st.builds(
        Entry,
        header=_hostile_header(),
        entry_hash=_HEXLIKE,
        payload=st.one_of(st.none(), _HOSTILE_BYTES),
    )


def _hostile_checkpoint() -> st.SearchStrategy[Checkpoint]:
    @st.composite
    def _build(draw: st.DrawFn) -> Checkpoint:
        seq = draw(_HOSTILE_INT)
        entry_hash = draw(_HEXLIKE)
        root = draw(_HEXLIKE)
        if draw(st.booleans()):
            # Checkpoint.__post_init__ requires agg_commit/agg_epoch both
            # present or both absent -- respect that so construction itself
            # never raises (that would test the dataclass guard, not the
            # verifier function this test targets).
            return Checkpoint(
                seq=seq,
                entry_hash=entry_hash,
                root=root,
                agg_commit=draw(_HEXLIKE),
                agg_epoch=draw(_HOSTILE_INT),
            )
        return Checkpoint(seq=seq, entry_hash=entry_hash, root=root)

    return _build()


def _hostile_pin_state() -> st.SearchStrategy[PinState]:
    return st.builds(
        PinState,
        target=_HOSTILE_TEXT,
        chain_id=st.one_of(st.none(), _HOSTILE_TEXT),
        checkpoint=_hostile_checkpoint(),
        pinned_ts=_HOSTILE_TEXT,
        declared_topology=st.one_of(
            st.none(),
            st.builds(
                SeparationTopology,
                seal_escrow=st.booleans(),
                anchor_sinks=_HOSTILE_INT,
                witness=st.booleans(),
                pin_separate=st.booleans(),
            ),
        ),
        max_anchor_age_s=st.one_of(st.none(), _HOSTILE_INT),
        expect_anchor_binding=st.booleans(),
    )


def _hostile_attestation() -> st.SearchStrategy[Attestation]:
    return st.builds(
        Attestation,
        seq=_HOSTILE_INT,
        entry_hash=_HEXLIKE,
        scheme=st.one_of(st.just(FS_HMAC_SCHEME), st.just(FS_HMAC_AGG_SCHEME), _HOSTILE_TEXT),
        value=_HEXLIKE,
        key_id=st.one_of(st.none(), _HOSTILE_TEXT),
    )


_JSON_LEAF = st.one_of(
    st.none(), st.booleans(), st.integers(-1000, 1000), st.text(max_size=20)
)
_JSON_HOSTILE_VALUE = st.recursive(
    _JSON_LEAF,
    lambda children: st.one_of(
        st.lists(children, max_size=3),
        st.dictionaries(st.text(max_size=10), children, max_size=3),
    ),
    max_leaves=6,
)


# --------------------------------------------------------------------------
# domain/verify.py
# --------------------------------------------------------------------------


class TestVerifyChainNeverRaises:
    @_FUZZ_SETTINGS
    @given(entries=st.lists(_hostile_entry(), max_size=6))
    def test_never_raises(self, entries: list[Entry]) -> None:
        verify_chain(entries, VersionRegistry())


# --------------------------------------------------------------------------
# domain/export.py
# --------------------------------------------------------------------------


class TestVerifyProofBundleNeverRaises:
    @_FUZZ_SETTINGS
    @given(
        header=_hostile_header(),
        entry_hash=_HEXLIKE,
        payload=st.one_of(st.none(), _HOSTILE_BYTES),
        batch_size=_HOSTILE_INT,
        proof=st.lists(_HEXLIKE, max_size=6),
        root=_HEXLIKE,
    )
    def test_never_raises(
        self,
        header: EntryHeader,
        entry_hash: str,
        payload: bytes | None,
        batch_size: int,
        proof: list[str],
        root: str,
    ) -> None:
        bundle = ProofBundle(
            header=header,
            entry_hash=entry_hash,
            payload=payload,
            batch_size=batch_size,
            proof=tuple(proof),
            root=root,
        )
        verify_proof_bundle(bundle, VersionRegistry())


class TestBundleFromJsonOnlyRaisesValueError:
    """Documented contract (export.py module docstring): "raises only
    ValueError". Fuzzed at two levels: arbitrary text (not even JSON), and
    JSON-shaped-but-hostile-fielded objects (wrong types, unknown bundle
    version, garbage proof entries)."""

    @_FUZZ_SETTINGS
    @given(text=st.one_of(st.text(max_size=200), _HOSTILE_TEXT))
    def test_arbitrary_text(self, text: str) -> None:
        with contextlib.suppress(ValueError):
            bundle_from_json(text)

    @staticmethod
    @st.composite
    def _hostile_bundle_json(draw: st.DrawFn) -> str:
        obj = {
            "bundle_version": draw(st.one_of(st.just(BUNDLE_VERSION), _JSON_HOSTILE_VALUE)),
            "header": draw(
                st.one_of(
                    _JSON_HOSTILE_VALUE,
                    st.just(
                        {
                            "seq": 0,
                            "ts": "x",
                            "hash_version": "y",
                            "payload_type": "z",
                            "payload_hash": "w",
                            "prev_hash": "v",
                        }
                    ),
                )
            ),
            "entry_hash": draw(st.one_of(_JSON_HOSTILE_VALUE, _HEXLIKE)),
            "batch_size": draw(_JSON_HOSTILE_VALUE),
            "proof": draw(st.one_of(_JSON_HOSTILE_VALUE, st.lists(_HEXLIKE, max_size=4))),
            "root": draw(st.one_of(_JSON_HOSTILE_VALUE, _HEXLIKE)),
            "payload_b64": draw(st.one_of(st.none(), _JSON_HOSTILE_VALUE, st.text(max_size=20))),
        }
        try:
            return json.dumps(obj)
        except (TypeError, ValueError):
            # A lone surrogate inside a str value: json.dumps itself can
            # refuse (unlike json.loads, which happily round-trips one via
            # \uXXXX escapes) -- not the function under test, fall back to
            # a value json.dumps always accepts.
            return json.dumps({"bundle_version": None})

    @_FUZZ_SETTINGS
    @given(text=_hostile_bundle_json())
    def test_hostile_json_shapes(self, text: str) -> None:
        with contextlib.suppress(ValueError):
            bundle_from_json(text)


# --------------------------------------------------------------------------
# domain/anchoring.py
# --------------------------------------------------------------------------


class TestAnchoringNeverRaises:
    @_FUZZ_SETTINGS
    @given(
        old_root=_HEXLIKE,
        old_size=_HOSTILE_INT,
        new_root=_HEXLIKE,
        new_size=_HOSTILE_INT,
        proof=st.lists(_HEXLIKE, max_size=6),
    )
    def test_verify_consistency_never_raises(
        self, old_root: str, old_size: int, new_root: str, new_size: int, proof: list[str]
    ) -> None:
        verify_consistency(old_root, old_size, new_root, new_size, proof)

    @_FUZZ_SETTINGS
    @given(
        entry_hash=_HEXLIKE,
        index=_HOSTILE_INT,
        batch_size=_HOSTILE_INT,
        proof=st.lists(_HEXLIKE, max_size=6),
        root=_HEXLIKE,
    )
    def test_verify_membership_never_raises(
        self, entry_hash: str, index: int, batch_size: int, proof: list[str], root: str
    ) -> None:
        verify_membership(entry_hash, index, batch_size, proof, root)


# --------------------------------------------------------------------------
# domain/checkpoint.py
# --------------------------------------------------------------------------


class TestVerifyCheckpointNeverRaises:
    @_FUZZ_SETTINGS
    @given(entry_hashes=st.lists(_HEXLIKE, max_size=6), checkpoint=_hostile_checkpoint())
    def test_never_raises(self, entry_hashes: list[str], checkpoint: Checkpoint) -> None:
        verify_checkpoint(entry_hashes, checkpoint)


# --------------------------------------------------------------------------
# domain/handoff.py
# --------------------------------------------------------------------------
#
# Landed by waxseal-otj (D3) after this file's own baseline was written --
# discovered by TestRegistryCompleteness itself, exactly the drift-in-either-
# direction case that test exists to catch (its docstring says "Never
# raises"). ``HandoffBinding`` validates strictly at construction (raises
# ValueError on a malformed triple, which is a caller-input contract, not
# this bead's hostile-READ-side concern) -- what ``binding_holds`` promises
# never to raise on is a hostile ORIGIN trail's hash list: too short, too
# long, non-hex, or containing a value with no UTF-8 form.


class TestBindingHoldsNeverRaises:
    @_FUZZ_SETTINGS
    @given(
        seq=st.integers(min_value=0, max_value=20),
        head_hash=st.text(min_size=64, max_size=64, alphabet="0123456789abcdef"),
        origin_entry_hashes=st.lists(_HEXLIKE, max_size=10),
    )
    def test_never_raises(
        self, seq: int, head_hash: str, origin_entry_hashes: list[str]
    ) -> None:
        binding = HandoffBinding(chain_id="fuzz-origin", seq=seq, head_hash=head_hash)
        binding_holds(binding, origin_entry_hashes)


# --------------------------------------------------------------------------
# domain/segments.py
# --------------------------------------------------------------------------
#
# Landed by waxseal-9uz (Workstream B). The hostile input is a DIRECTORY of
# segment files an attacker can write: a seq-0 payload that is any JSON value
# at all (or none), a chain_id naming anything, a predecessor whose hash list
# is the wrong length or not hex, and a `chain` that is None because the file
# would not parse. Every one of those is a verdict here, never an exception --
# `waxseal segments` has to print a per-segment state for whatever it finds.


def _hostile_genesis_payload() -> st.SearchStrategy[object]:
    return st.one_of(
        st.none(),
        _HOSTILE_TEXT,
        _HOSTILE_INT,
        st.lists(_HOSTILE_TEXT, max_size=3),
        st.fixed_dictionaries(
            {"chain_id": _HOSTILE_TEXT, "seq": _HOSTILE_INT, "head_hash": _HEXLIKE}
        ),
        st.dictionaries(_HOSTILE_TEXT, _HOSTILE_TEXT, max_size=3),
    )


def _hostile_segment_read() -> st.SearchStrategy[SegmentRead]:
    return st.builds(
        SegmentRead,
        identity=_HOSTILE_TEXT,
        chain=st.one_of(st.none(), st.builds(_verify_result_from, st.booleans())),
        entry_hashes=st.lists(_HEXLIKE, max_size=4).map(tuple),
        genesis_payload_type=st.one_of(
            st.none(), st.just(ROTATION_PAYLOAD_TYPE), _HOSTILE_TEXT
        ),
        genesis_payload=_hostile_genesis_payload(),
    )


def _verify_result_from(ok: bool) -> VerifyResult:
    return VerifyResult(
        ok=ok,
        checked=0,
        broken_seq=None if ok else 0,
        reason=None if ok else "entry_hash_mismatch",
        unverifiable=() if ok else (0,),
        dropped_writes=None,
    )


class TestVerifySegmentsNeverRaises:
    @_FUZZ_SETTINGS
    @given(segments=st.lists(_hostile_segment_read(), max_size=5))
    def test_never_raises(self, segments: list[SegmentRead]) -> None:
        verify_segments(segments)


# --------------------------------------------------------------------------
# domain/witnessing.py
# --------------------------------------------------------------------------


class TestCheckWitnessedNeverRaises:
    @_FUZZ_SETTINGS
    @given(
        entry_hashes=st.lists(_HEXLIKE, max_size=6),
        checkpoints=st.lists(_hostile_checkpoint(), max_size=4),
        unreadable=st.integers(min_value=0, max_value=1000),
    )
    def test_never_raises(
        self, entry_hashes: list[str], checkpoints: list[Checkpoint], unreadable: int
    ) -> None:
        observation = WitnessObservation(checkpoints=tuple(checkpoints), unreadable=unreadable)
        check_witnessed(entry_hashes, observation, name="w1")


# --------------------------------------------------------------------------
# domain/pinning.py
# --------------------------------------------------------------------------


class TestPinningNeverRaises:
    @_FUZZ_SETTINGS
    @given(entry_hashes=st.lists(_HEXLIKE, max_size=6), pin=_hostile_checkpoint())
    def test_check_pin_never_raises(self, entry_hashes: list[str], pin: Checkpoint) -> None:
        check_pin(entry_hashes, pin)

    @_FUZZ_SETTINGS
    @given(
        state=_hostile_pin_state(),
        target=_HOSTILE_TEXT,
        chain_id=st.one_of(st.none(), _HOSTILE_TEXT),
    )
    def test_check_pin_target_never_raises(
        self, state: PinState, target: str, chain_id: str | None
    ) -> None:
        check_pin_target(state, target=target, chain_id=chain_id)

    @_FUZZ_SETTINGS
    @given(
        max_age_s=_HOSTILE_INT,
        records=st.lists(st.tuples(_HOSTILE_INT, _HOSTILE_TEXT), max_size=6),
        now=st.datetimes(),
    )
    def test_anchor_staleness_never_raises(
        self, max_age_s: int, records: list[tuple[int, str]], now: datetime
    ) -> None:
        anchor_staleness(max_age_s, records, now=now)

    @_FUZZ_SETTINGS
    @given(
        pinned_seq=_HOSTILE_INT,
        records=st.lists(st.tuples(_HOSTILE_INT, st.one_of(st.none(), _HEXLIKE)), max_size=6),
        any_unreadable=st.booleans(),
    )
    def test_anchor_policy_downgrade_never_raises(
        self, pinned_seq: int, records: list[tuple[int, str | None]], any_unreadable: bool
    ) -> None:
        anchor_policy_downgrade(pinned_seq, records, any_unreadable=any_unreadable)


class TestParsePinStateOnlyRaisesPinStateError:
    """Documented contract (pinning.py): PinMalformed or PinVersionUnknown,
    both PinStateError, never anything else."""

    @_FUZZ_SETTINGS
    @given(text=st.one_of(st.text(max_size=200), _HOSTILE_TEXT))
    def test_arbitrary_text(self, text: str) -> None:
        with contextlib.suppress(PinStateError):
            parse_pin_state(text)

    @staticmethod
    @st.composite
    def _hostile_pin_json(draw: st.DrawFn) -> str:
        obj = {
            "v": draw(st.one_of(st.integers(-5, 5), _JSON_HOSTILE_VALUE)),
            "target": draw(st.one_of(_JSON_HOSTILE_VALUE, st.text(max_size=20))),
            "chain_id": draw(st.one_of(st.none(), _JSON_HOSTILE_VALUE)),
            "seq": draw(_JSON_HOSTILE_VALUE),
            "entry_hash": draw(_JSON_HOSTILE_VALUE),
            "root": draw(_JSON_HOSTILE_VALUE),
            "pinned_ts": draw(_JSON_HOSTILE_VALUE),
            "declared_topology": draw(st.one_of(st.none(), _JSON_HOSTILE_VALUE)),
            "max_anchor_age_s": draw(st.one_of(st.none(), _JSON_HOSTILE_VALUE)),
            "expect_anchor_binding": draw(_JSON_HOSTILE_VALUE),
        }
        try:
            return json.dumps(obj)
        except (TypeError, ValueError):
            return json.dumps({"v": -1})

    @_FUZZ_SETTINGS
    @given(text=_hostile_pin_json())
    def test_hostile_json_shapes(self, text: str) -> None:
        with contextlib.suppress(PinStateError):
            parse_pin_state(text)


# --------------------------------------------------------------------------
# domain/rfc3161.py
# --------------------------------------------------------------------------


class TestParseTimestampRespOnlyRaisesDerError:
    @_FUZZ_SETTINGS
    @given(der=st.binary(max_size=600))
    def test_never_raises_anything_but_dererror(self, der: bytes) -> None:
        with contextlib.suppress(DerError):
            parse_timestamp_resp(der)


class TestRfc3161NeverRaises:
    @_FUZZ_SETTINGS
    @given(der=st.binary(max_size=600), message=st.binary(max_size=64))
    def test_read_timestamp_resp_never_raises(self, der: bytes, message: bytes) -> None:
        read_timestamp_resp(der, message)

    @_FUZZ_SETTINGS
    @given(der=st.binary(max_size=600), message=st.binary(max_size=64))
    def test_check_timestamp_resp_never_raises(self, der: bytes, message: bytes) -> None:
        check_timestamp_resp(der, message)

    @_FUZZ_SETTINGS
    @given(receipt=st.one_of(st.text(max_size=200), _HOSTILE_TEXT))
    def test_decode_receipt_never_raises(self, receipt: str) -> None:
        rfc3161_decode_receipt(receipt)


# --------------------------------------------------------------------------
# domain/ots.py
# --------------------------------------------------------------------------


class TestOtsDecodeReceiptNeverRaises:
    @_FUZZ_SETTINGS
    @given(receipt=st.one_of(st.text(max_size=200), _HOSTILE_TEXT))
    def test_never_raises(self, receipt: str) -> None:
        ots_decode_receipt(receipt)


# --------------------------------------------------------------------------
# domain/sealing.py
# --------------------------------------------------------------------------


class TestSealingNeverRaises:
    @_FUZZ_SETTINGS
    @given(
        attestations=st.lists(_hostile_attestation(), max_size=6),
        key=st.binary(min_size=32, max_size=32),
    )
    def test_verify_seals_never_raises(
        self, attestations: list[Attestation], key: bytes
    ) -> None:
        verify_seals(attestations, key)

    @_FUZZ_SETTINGS
    @given(
        attestations=st.lists(_hostile_attestation(), max_size=6),
        key=st.binary(min_size=32, max_size=32),
        agg_start=_HOSTILE_INT,
        epoch=_HOSTILE_INT,
        agg=_HEXLIKE,
    )
    def test_verify_aggregate_never_raises(
        self,
        attestations: list[Attestation],
        key: bytes,
        agg_start: int,
        epoch: int,
        agg: str,
    ) -> None:
        verify_aggregate(attestations, key, agg_start=agg_start, epoch=epoch, agg=agg)

    @_FUZZ_SETTINGS
    @given(
        attestations=st.lists(_hostile_attestation(), max_size=6),
        key=st.binary(min_size=32, max_size=32),
        agg_start=_HOSTILE_INT,
        anchored_epoch=_HOSTILE_INT,
        anchored_commit=_HEXLIKE,
    )
    def test_verify_anchored_aggregate_never_raises(
        self,
        attestations: list[Attestation],
        key: bytes,
        agg_start: int,
        anchored_epoch: int,
        anchored_commit: str,
    ) -> None:
        verify_anchored_aggregate(
            attestations,
            key,
            agg_start=agg_start,
            anchored_epoch=anchored_epoch,
            anchored_commit=anchored_commit,
        )


# --------------------------------------------------------------------------
# adapters/anchors.py
# --------------------------------------------------------------------------


class TestReadAnchorRecordsOnlyRaisesDocumentedTypes:
    """Documented contract (adapters/anchors.py): ValueError (including
    json.JSONDecodeError), KeyError, or TypeError on unparseable lines --
    exactly the set cli.py's own ``_anchor_check`` already catches. Fuzzed
    by writing hostile bytes/lines to a real ``<trail>.anchors`` sidecar
    file, since this is the one entry point in this sweep that touches I/O
    rather than pure in-memory structures."""

    @staticmethod
    @st.composite
    def _hostile_sidecar_line(draw: st.DrawFn) -> str:
        obj = {
            "v": draw(st.one_of(st.integers(0, 3), _JSON_HOSTILE_VALUE)),
            "seq": draw(_JSON_HOSTILE_VALUE),
            "entry_hash": draw(_JSON_HOSTILE_VALUE),
            "root": draw(_JSON_HOSTILE_VALUE),
            "agg_commit": draw(st.one_of(st.none(), _JSON_HOSTILE_VALUE)),
            "agg_epoch": draw(st.one_of(st.none(), _JSON_HOSTILE_VALUE)),
            "sink": draw(_JSON_HOSTILE_VALUE),
            "receipt": draw(st.one_of(st.none(), _JSON_HOSTILE_VALUE)),
            "ts": draw(_JSON_HOSTILE_VALUE),
            "nonce": draw(st.one_of(st.none(), _JSON_HOSTILE_VALUE)),
        }
        try:
            return json.dumps(obj)
        except (TypeError, ValueError):
            return '{"v": 999}'

    @_FUZZ_SETTINGS
    @given(
        lines=st.lists(
            st.one_of(_hostile_sidecar_line(), st.text(max_size=100)), max_size=5
        )
    )
    def test_hostile_sidecar_only_raises_documented_types(self, lines: list[str]) -> None:
        # A fresh temp dir per example (not a pytest fixture, which hypothesis
        # flags as function-scoped and shared across examples) -- this test
        # touches real I/O, the one entry point in this sweep that does.
        with tempfile.TemporaryDirectory() as tmp:
            trail = Path(tmp) / "trail.jsonl"
            sidecar = trail.with_name(trail.name + ".anchors")
            sidecar.write_text("\n".join(lines) + "\n", encoding="utf-8")
            with contextlib.suppress(ValueError, KeyError, TypeError):
                read_anchor_records(trail)
