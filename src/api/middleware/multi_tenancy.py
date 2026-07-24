"""Request-scoped tenant context and FastAPI middleware."""

from __future__ import annotations

import hashlib
import logging
import os
import re
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Optional

import jwt
from fastapi import HTTPException, Request, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response

logger = logging.getLogger(__name__)

_TENANT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_TENANT_CONTEXT: ContextVar[Optional[str]] = ContextVar("tenant_id", default=None)


class TenantIsolationError(HTTPException):
    """HTTP error raised when tenant resolution fails."""

    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(status_code=status_code, detail=detail)


@dataclass(frozen=True)
class TenantResolutionResult:
    tenant_id: str
    source: str


def get_current_tenant() -> Optional[str]:
    return _TENANT_CONTEXT.get()


def set_current_tenant(tenant_id: str) -> None:
    if not tenant_id or not _TENANT_ID_RE.match(tenant_id):
        raise ValueError("Invalid tenant identifier")
    _TENANT_CONTEXT.set(tenant_id)


def clear_current_tenant() -> None:
    _TENANT_CONTEXT.set(None)


def _validate_tenant_id(tenant_id: str) -> str:
    tenant = tenant_id.strip()
    if not tenant or not _TENANT_ID_RE.match(tenant):
        raise TenantIsolationError(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Malformed tenant identifier",
        )
    return tenant


def _decode_jwt_tenant(request: Request) -> Optional[TenantResolutionResult]:
    authorization = request.headers.get("Authorization", "")
    if not authorization.lower().startswith("bearer "):
        return None

    token = authorization.split(" ", 1)[1].strip()
    if token.count(".") != 2:
        return None

    secret = os.getenv("AEGIS_JWT_SECRET")
    if not secret:
        raise TenantIsolationError(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="JWT tenant resolution is not configured",
        )

    try:
        payload = jwt.decode(token, secret, algorithms=["HS256"])
    except jwt.ExpiredSignatureError as exc:
        raise TenantIsolationError(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="JWT token has expired",
        ) from exc
    except jwt.InvalidTokenError as exc:
        raise TenantIsolationError(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid JWT token",
        ) from exc

    tenant_id = payload.get("tenant_id") or payload.get("org")
    if tenant_id is None:
        raise TenantIsolationError(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Tenant information is missing from JWT",
        )

    return TenantResolutionResult(tenant_id=_validate_tenant_id(str(tenant_id)), source="jwt")


def _has_jwt_like_authorization(request: Request) -> bool:
    authorization = request.headers.get("Authorization", "")
    if not authorization.lower().startswith("bearer "):
        return False
    token = authorization.split(" ", 1)[1].strip()
    return token.count(".") == 2


def _load_api_key_tenant_map() -> dict[str, str]:
    raw = os.getenv("AEGIS_API_KEY_TENANT_MAP", "").strip()
    if not raw:
        return {}

    tenant_map: dict[str, str] = {}
    for entry in raw.split(","):
        chunk = entry.strip()
        if not chunk or "=" not in chunk:
            continue
        key_hash, tenant_id = chunk.split("=", 1)
        tenant_map[key_hash.strip().lower()] = _validate_tenant_id(tenant_id)
    return tenant_map


def _resolve_from_api_key(request: Request) -> Optional[TenantResolutionResult]:
    api_key = request.headers.get("X-API-Key", "").strip()
    if not api_key:
        return None

    key_hash = hashlib.sha256(api_key.encode("utf-8")).hexdigest()
    tenant_map = _load_api_key_tenant_map()
    if key_hash in tenant_map:
        return TenantResolutionResult(tenant_id=tenant_map[key_hash], source="api_key")

    default_tenant = os.getenv("AEGIS_DEFAULT_TENANT_ID", "").strip()
    if default_tenant:
        return TenantResolutionResult(tenant_id=_validate_tenant_id(default_tenant), source="default")

    derived_tenant = f"api_{key_hash[:24]}"
    return TenantResolutionResult(tenant_id=_validate_tenant_id(derived_tenant), source="api_key_derived")


def _resolve_from_tenant_header(request: Request) -> Optional[TenantResolutionResult]:
    header_tenant = request.headers.get("X-Tenant-ID", "").strip()
    if not header_tenant:
        return None

    if not (request.headers.get("X-API-Key") or _has_jwt_like_authorization(request)):
        raise TenantIsolationError(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication for tenant resolution",
        )

    return TenantResolutionResult(tenant_id=_validate_tenant_id(header_tenant), source="x-tenant-id")


def resolve_tenant_from_request(request: Request) -> Optional[TenantResolutionResult]:
    has_auth = bool(request.headers.get("X-API-Key") or _has_jwt_like_authorization(request))
    jwt_result = _decode_jwt_tenant(request)
    header_result = _resolve_from_tenant_header(request)
    if jwt_result is not None:
        if header_result is not None and header_result.tenant_id != jwt_result.tenant_id:
            raise TenantIsolationError(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Unauthorized tenant access",
            )
        return jwt_result

    api_key_result = _resolve_from_api_key(request)

    if api_key_result and header_result and api_key_result.tenant_id != header_result.tenant_id:
        raise TenantIsolationError(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Unauthorized tenant access",
        )

    if api_key_result is not None:
        return api_key_result
    if header_result is not None:
        return header_result
    if has_auth:
        raise TenantIsolationError(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing tenant information",
        )
    return None


class TenantIsolationMiddleware(BaseHTTPMiddleware):
    """Resolve and bind tenant context for each request."""

    async def dispatch(self, request: Request, call_next) -> Response:
        token = None
        try:
            resolution = resolve_tenant_from_request(request)
            if resolution is not None:
                token = _TENANT_CONTEXT.set(resolution.tenant_id)
                request.state.tenant_id = resolution.tenant_id
                request.state.tenant_source = resolution.source
            else:
                request.state.tenant_id = None
                request.state.tenant_source = None
            response = await call_next(request)
            return response
        except HTTPException as exc:
            return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
        except Exception as exc:
            logger.exception("Tenant context initialization failure")
            raise TenantIsolationError(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Context initialization failure",
            ) from exc
        finally:
            if token is not None:
                _TENANT_CONTEXT.reset(token)
            else:
                clear_current_tenant()
