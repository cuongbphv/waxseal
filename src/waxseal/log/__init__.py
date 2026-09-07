"""Public facade for the audit log.

`from waxseal.log import AuditLog, AttestationFailure` stays the import path
after the package split. The class body lives in facade.py.
"""

from __future__ import annotations

from waxseal.log.facade import AttestationFailure, AuditLog

__all__ = ("AttestationFailure", "AuditLog")
