"""Compatibility re-exports for the log package split (b7a)."""

from __future__ import annotations


def test_auditlog_and_attestation_failure_import_from_waxseal_log() -> None:
    from waxseal.log import AttestationFailure, AuditLog

    assert AuditLog is not None
    assert issubclass(AttestationFailure, RuntimeError)
