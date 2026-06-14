"""Unified exception handling for AegisGraph Sentinel."""

from .base_exceptions import (
    AegisException,
    AuthenticationError,
    AuthorizationError,
    ProcessingException,
    SecurityException,
    ServiceUnavailableException,
    ValidationException,
)
from .error_codes import ErrorCode
from .error_responses import build_error_from_aegis_exception, build_error_payload, utc_timestamp
from .handlers import register_exception_handlers, register_observability_middleware

__all__ = [
    "AegisException",
    "AuthenticationError",
    "AuthorizationError",
    "ErrorCode",
    "ProcessingException",
    "SecurityException",
    "ServiceUnavailableException",
    "ValidationException",
    "build_error_from_aegis_exception",
    "build_error_payload",
    "register_exception_handlers",
    "register_observability_middleware",
    "utc_timestamp",
]
