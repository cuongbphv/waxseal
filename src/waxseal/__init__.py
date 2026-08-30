"""waxseal: a tamper-evident, schema-evolution-safe audit hash chain.

Public API (frozen by tests/architecture/test_invariants.py, TestPublicApiFrozen):
"""

from waxseal.domain.anchoring import (
    batch_root,
    consistency_proof,
    membership_proof,
    verify_consistency,
    verify_membership,
)
from waxseal.domain.checkpoint import Checkpoint, checkpoint_for, checkpoint_frame
from waxseal.domain.decision import DecisionRecord, HumanOversight, ModelRef
from waxseal.domain.export import (
    BundleResult,
    ProofBundle,
    build_proof_bundle,
    verify_proof_bundle,
)
from waxseal.domain.fingerprint import fingerprint, fingerprint_for
from waxseal.domain.header import GENESIS_PREV_HASH, Entry, EntryHeader
from waxseal.domain.registry import VersionRegistry
from waxseal.domain.separation import SeparationTopology, separation_degree
from waxseal.domain.verdict import Verdict
from waxseal.domain.verify import VerifyResult, verify_chain
from waxseal.log import AuditLog

__all__ = [
    "GENESIS_PREV_HASH",
    "AuditLog",
    "BundleResult",
    "Checkpoint",
    "DecisionRecord",
    "Entry",
    "EntryHeader",
    "HumanOversight",
    "ModelRef",
    "ProofBundle",
    "SeparationTopology",
    "Verdict",
    "VerifyResult",
    "VersionRegistry",
    "batch_root",
    "build_proof_bundle",
    "checkpoint_for",
    "checkpoint_frame",
    "consistency_proof",
    "fingerprint",
    "fingerprint_for",
    "membership_proof",
    "separation_degree",
    "verify_chain",
    "verify_consistency",
    "verify_membership",
    "verify_proof_bundle",
]

__version__ = "0.1.4"
