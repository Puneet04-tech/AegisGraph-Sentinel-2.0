"""Centralized FastAPI exception handlers and request tracing middleware."""

from __future__ import annotations

import traceback
from typing import Any, Dict, Optional, Union

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse

from ..observability.audit_logger import get_audit_logger
from ..observability.structured_logger import (
    clear_request_context,
    generate_request_id,
    get_logger,
    get_request_id,
    set_request_context,
)
from .base_exceptions import AegisException, ServiceUnavailableException
from .error_codes import ErrorCode
from .error_responses import build_error_from_aegis_exception, build_error_payload


def _resolve_request_id(request: Request) -> str:
    incoming = (
        request.headers.get("X-Request-ID")
        or request.headers.get("X-Request-Id")
        or request.headers.get("X-Correlation-ID")
        or request.headers.get("X-Correlation-Id")
    )
    return incoming.strip() if incoming else generate_request_id()


def _resolve_correlation_id(request: Request, request_id: str) -> str:
    correlation = (
        request.headers.get("X-Correlation-ID")
        or request.headers.get("X-Correlation-Id")
    )
    return correlation.strip() if correlation else request_id


def _http_exception_message(detail: Any) -> str:
    if isinstance(detail, str):
        return detail
    if isinstance(detail, dict):
        if "message" in detail:
            return str(detail["message"])
        if "error" in detail:
            return str(detail["error"])
        return "Request failed"
    return str(detail)


def _http_exception_details(detail: Any) -> Dict[str, Any]:
    if isinstance(detail, dict):
        return dict(detail)
    if detail is not None and not isinstance(detail, str):
        return {"detail": detail}
    return {}


def _status_to_error_code(status_code: int) -> ErrorCode:
    if status_code == 422:
        return ErrorCode.VALIDATION_ERROR
    if status_code == 403:
        return ErrorCode.SECURITY_ERROR
    if status_code == 503:
        return ErrorCode.SERVICE_UNAVAILABLE
    if status_code >= 500:
        return ErrorCode.INTERNAL_ERROR
    return ErrorCode.PROCESSING_ERROR


def _request_id_for_error(request: Request) -> str:
    return (
        get_request_id()
        or getattr(request.state, "request_id", None)
        or _resolve_request_id(request)
    )


async def aegis_exception_handler(request: Request, exc: AegisException) -> JSONResponse:
    request_id = _request_id_for_error(request)
    audit = get_audit_logger()
    audit.log_exception_trace(
        exc_type=exc.type_name,
        message=exc.message,
        status_code=exc.status_code,
        metadata={"code": str(exc.code), "path": request.url.path},
    )
    return JSONResponse(
        status_code=exc.status_code,
        content=build_error_from_aegis_exception(exc, request_id=request_id),
        headers={"X-Request-ID": request_id},
    )


async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    request_id = _request_id_for_error(request)
    code = _status_to_error_code(exc.status_code)
    if exc.status_code == 503:
        type_name = ServiceUnavailableException.__name__
    else:
        type_name = "HTTPException"

    audit = get_audit_logger()
    audit.log_exception_trace(
        exc_type=type_name,
        message=_http_exception_message(exc.detail),
        status_code=exc.status_code,
        metadata={"code": str(code), "path": request.url.path},
    )

    content = build_error_payload(
        code=code,
        type_name=type_name,
        message=_http_exception_message(exc.detail),
        request_id=request_id,
        details=_http_exception_details(exc.detail),
    )
    return JSONResponse(
        status_code=exc.status_code,
        content=content,
        headers={"X-Request-ID": request_id},
    )


async def validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    request_id = _request_id_for_error(request)
    
    # --- UPGRADE: Unpack nested Pydantic errors into a scannable message string ---
    error_details = []
    for error in exc.errors():
        loc = " -> ".join(str(loc_item) for loc_item in error.get("loc", []))
        msg = error.get("msg", "Invalid value")
        error_details.append(f"[{loc}]: {msg}")
    readable_message = "Request validation failed: " + " | ".join(error_details)
    # ------------------------------------------------------------------------------

    audit = get_audit_logger()
    audit.log_exception_trace(
        exc_type="ValidationException",
        message=readable_message,
        status_code=422,
        metadata={"errors": jsonable_encoder(exc.errors()), "path": request.url.path},
    )
    content = build_error_payload(
        code=ErrorCode.VALIDATION_ERROR,
        type_name="ValidationException",
        message=readable_message,
        request_id=request_id,
        details={"validation_errors": jsonable_encoder(exc.errors())},
    )
    return JSONResponse(
        status_code=422,
        content=content,
        headers={"X-Request-ID": request_id},
    )


async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    request_id = _request_id_for_error(request)
    
    # --- UPGRADE: Extract full Python execution traceback for server analytics ---
    error_trace = traceback.format_exc()
    # ------------------------------------------------------------------------------

    audit = get_audit_logger()
    audit.log_exception_trace(
        exc_type=type(exc).__name__,
        message="Unhandled internal error",
        status_code=500,
        metadata={
            "path": request.url.path, 
            "error": str(exc),
            "traceback": error_trace  # Full file and line number matrix preserved safely inside internal logs
        },
    )
    content = build_error_payload(
        code=ErrorCode.INTERNAL_ERROR,
        type_name="InternalError",
        message="Internal server error",
        request_id=request_id,
        details={},
    )
    return JSONResponse(
        status_code=500,
        content=content,
        headers={"X-Request-ID": request_id},
    )


def register_exception_handlers(app: FastAPI) -> None:
    """Register centralized exception handlers on the FastAPI application."""
    app.add_exception_handler(AegisException, aegis_exception_handler)
    app.add_exception_handler(HTTPException, http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(Exception, unhandled_exception_handler)


def register_observability_middleware(app: FastAPI) -> None:
    """Add request tracing and structured request logging middleware."""
    request_logger = get_logger("api")

    @app.middleware("http")
    async def request_logging_middleware(request: Request, call_next):
        request_id = getattr(request.state, "request_id", get_request_id())
        request_logger.info(
            "Request started",
            event_type="http_request_start",
            metadata={
                "method": request.method,
                "path": request.url.path,
                "request_id": request_id,
            },
        )
        response = await call_next(request)
        request_logger.info(
            "Request completed",
            event_type="http_request_complete",
            metadata={
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "request_id": request_id,
            },
        )
        return response

    @app.middleware("http")
    async def request_tracing_middleware(request: Request, call_next):
        request_id = _resolve_request_id(request)
        correlation_id = _resolve_correlation_id(request, request_id)
        set_request_context(request_id=request_id, correlation_id=correlation_id)
        request.state.request_id = request_id
        request.state.correlation_id = correlation_id
        try:
            response = await call_next(request)
        finally:
            clear_request_context()
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Correlation-ID"] = correlation_id
        return response