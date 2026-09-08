"""Shared S3 error-code extraction. Does not import backend or worm."""

from __future__ import annotations


def _is_precondition_failed(exc: Exception) -> bool:
    code = _error_code(exc)
    return code in {"PreconditionFailed", "412"}


def _is_not_found(exc: Exception) -> bool:
    code = _error_code(exc)
    return code in {"NoSuchKey", "404", "NotFound"}


def _error_code(exc: Exception) -> str:
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        return str(response.get("Error", {}).get("Code", ""))
    return ""


def _describe(exc: Exception) -> str:
    code = _error_code(exc)
    return f"{type(exc).__name__} code={code!r}: {exc}"
