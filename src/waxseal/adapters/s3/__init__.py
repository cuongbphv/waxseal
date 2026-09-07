"""S3 adapter package. Public names stay on `waxseal.adapters.s3`.

Submodules never import this package barrel. `_WORM_LABEL` and
`_STORAGE_REFUSAL_PROMISE` are re-exported for tests, not added to
`waxseal.__all__`.
"""

from __future__ import annotations

from waxseal.adapters.s3.backend import S3Backend
from waxseal.adapters.s3.upload import SegmentUpload, upload_sealed_segment
from waxseal.adapters.s3.worm import (
    _STORAGE_REFUSAL_PROMISE,
    _WORM_LABEL,
    RETENTION_MODE_STRENGTH,
    RETENTION_MODES,
    WormReport,
    WormRetention,
    WormState,
    WormStrength,
    WormSubject,
    bucket_worm_state,
    object_worm_state,
    render_worm_state,
)

__all__ = (
    "RETENTION_MODE_STRENGTH",
    "RETENTION_MODES",
    "S3Backend",
    "SegmentUpload",
    "WormReport",
    "WormRetention",
    "WormState",
    "WormStrength",
    "WormSubject",
    "_STORAGE_REFUSAL_PROMISE",
    "_WORM_LABEL",
    "bucket_worm_state",
    "object_worm_state",
    "render_worm_state",
    "upload_sealed_segment",
)
