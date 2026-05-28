"""Structured API error response builders with comprehensive validation error support."""

from datetime import datetime, timezone
from typing import Any, Dict, Optional, Union, List

from .base_exceptions import AegisException
from .error_codes import ErrorCode


def utc_timestamp() -> str:
    """Return an ISO-8601 UTC timestamp with Z suffix."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_error_payload(
    *,
    code: Union[ErrorCode, str],
    type_name: str,
    message: str,
    request_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    timestamp: Optional[str] = None,
    field_errors: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Build the standardized nested error response body with optional field-level errors."""
    code_value = code.value if isinstance(code, ErrorCode) else str(code)
    payload: Dict[str, Any] = {
        "error": {
            "code": code_value,
            "type": type_name,
            "message": message,
            "request_id": request_id,
            "timestamp": timestamp or utc_timestamp(),
            "details": details or {},
        }
    }
    
    # Add field-level errors if provided
    if field_errors:
        payload["error"]["field_errors"] = field_errors
    
    return payload


def build_validation_error_payload(
    *,
    field: str,
    value: Any,
    constraint: str,
    suggestion: str,
    request_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Build detailed validation error response for a single field."""
    return build_error_payload(
        code="VALIDATION_ERROR",
        type_name="ValidationError",
        message=f"Validation failed for field '{field}'",
        request_id=request_id,
        details={
            "field": field,
            "value": str(value) if value is not None else None,
            "constraint": constraint,
            "suggestion": suggestion,
        },
    )


def build_multi_field_validation_error_payload(
    *,
    errors: List[Dict[str, Any]],
    request_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Build validation error response with multiple field errors."""
    return build_error_payload(
        code="VALIDATION_ERROR",
        type_name="MultiFieldValidationError",
        message="Validation failed for one or more fields",
        request_id=request_id,
        field_errors=errors,
        details={"error_count": len(errors)},
    )


def build_rate_limit_error_payload(
    *,
    retry_after: int,
    limit_type: str = "account",
    request_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Build rate limit error response."""
    return build_error_payload(
        code="RATE_LIMIT_EXCEEDED",
        type_name="RateLimitError",
        message=f"Rate limit exceeded for {limit_type}",
        request_id=request_id,
        details={
            "limit_type": limit_type,
            "retry_after_seconds": retry_after,
            "message": f"Please retry after {retry_after} seconds",
        },
    )


def build_error_from_aegis_exception(
    exc: AegisException,
    request_id: Optional[str] = None,
) -> Dict[str, Any]:
    return build_error_payload(
        code=exc.code,
        type_name=exc.type_name,
        message=exc.message,
        request_id=request_id,
        details=exc.details,
    )


def build_pydantic_validation_errors(
    *,
    pydantic_errors: List[Dict[str, Any]],
    request_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Convert Pydantic validation errors to our error format."""
    field_errors = []
    
    for error in pydantic_errors:
        field_path = ".".join(str(loc) for loc in error.get("loc", []))
        field_errors.append({
            "field": field_path,
            "message": error.get("msg", "Validation failed"),
            "type": error.get("type", "unknown"),
            "constraint": error.get("ctx", {}).get("error", "unknown"),
        })
    
    return build_multi_field_validation_error_payload(
        errors=field_errors,
        request_id=request_id,
    )
