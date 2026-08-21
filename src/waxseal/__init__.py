"""waxseal — tamper-evident, schema-evolution-safe audit hash chain.

Public API (frozen by tests/architecture/test_public_api.py):
"""

from waxseal.domain.anchoring import (
    batch_root,
    membership_proof,
    verify_membership,
)
from waxseal.domain.fingerprint import fingerprint_for, fingerprint_v1
from waxseal.domain.header import GENESIS_PREV_HASH, Entry, EntryHeader
from waxseal.domain.registry import VersionRegistry
from waxseal.domain.verify import VerifyResult, verify_chain
from waxseal.log import AuditLog

__all__ = [
    "GENESIS_PREV_HASH",
    "AuditLog",
    "Entry",
    "EntryHeader",
    "VerifyResult",
    "VersionRegistry",
    "batch_root",
    "fingerprint_for",
    "fingerprint_v1",
    "membership_proof",
    "verify_chain",
    "verify_membership",
]

__version__ = "0.1.1"
