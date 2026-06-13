"""Base exception hierarchy for AegisGraph Sentinel."""

from typing import Any, Dict, Optional

from .error_codes import ErrorCode


class AegisException(Exception):
    """Base application exception with HTTP mapping and structured error metadata."""

    default_code = ErrorCode.INTERNAL_ERROR
    default_status_code = 500

    def __init__(
        self,
        message: str,
        *,
        code: Optional[ErrorCode] = None,
        status_code: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code or self.default_code
        self.status_code = status_code if status_code is not None else self.default_status_code
        self.details = details or {}

    @property
    def type_name(self) -> str:
        return self.__class__.__name__


class ValidationException(AegisException):
    default_code = ErrorCode.VALIDATION_ERROR
    default_status_code = 422


class ProcessingException(AegisException):
    default_code = ErrorCode.PROCESSING_ERROR
    default_status_code = 500


class SecurityException(AegisException):
    default_code = ErrorCode.SECURITY_ERROR
    default_status_code = 403


class ServiceUnavailableException(AegisException):
    default_code = ErrorCode.SERVICE_UNAVAILABLE
    default_status_code = 503


class AuthenticationError(AegisException):
    default_code = ErrorCode.SECURITY_ERROR
    default_status_code = 401


class AuthorizationError(AegisException):
    default_code = ErrorCode.SECURITY_ERROR
    default_status_code = 403
