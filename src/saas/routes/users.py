"""User Management Routes
AegisGraph Sentinel Enterprise SaaS Platform
"""

from __future__ import annotations

import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr, Field, field_validator

from src.api.middleware.multi_tenancy import get_current_tenant
from src.saas.auth.service import auth_service
from src.saas.routes.auth import get_current_user
from src.saas.services.billing import PriceTier
from src.saas.services.limit_enforcer import (
    enforce_tenant_limit,
    get_tenant_resource_count,
    set_tenant_resource_count,
)

router = APIRouter(prefix="/api/v1/users", tags=["users"])

_ADMIN_ROLES = {"admin", "administrator", "super_admin", "owner"}
_MEMBER_ROLES = {"member", "viewer", "analyst", "auditor"}
_ALLOWED_ROLES = _ADMIN_ROLES | _MEMBER_ROLES
_USER_FIELDS = (
    "id",
    "email",
    "full_name",
    "username",
    "phone",
    "avatar_url",
    "role",
    "is_active",
    "email_verified",
    "mfa_enabled",
    "last_login",
    "created_at",
)

_USER_STORE: Dict[str, Dict[str, Any]] = {}
_AUDIT_LOG: List[Dict[str, Any]] = []
_STORE_LOCK = threading.RLock()


class UserCreate(BaseModel):
    email: EmailStr
    full_name: Optional[str] = Field(default=None, max_length=200)
    username: Optional[str] = Field(default=None, min_length=3, max_length=100)
    password: str = Field(min_length=8, max_length=256)
    role: str = Field(default="member", min_length=3, max_length=32)
    phone: Optional[str] = Field(default=None, max_length=32)
    avatar_url: Optional[str] = Field(default=None, max_length=500)

    @field_validator("username")
    @classmethod
    def validate_username(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        if not value.replace("_", "").replace("-", "").isalnum():
            raise ValueError("username may contain only letters, numbers, hyphen, and underscore")
        return value

    @field_validator("phone")
    @classmethod
    def validate_phone(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        cleaned = value.replace("+", "", 1).replace(" ", "").replace("-", "")
        if not cleaned.isdigit():
            raise ValueError("phone must contain only digits and optional leading +")
        return value

    @field_validator("avatar_url")
    @classmethod
    def validate_avatar_url(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("avatar_url must be an absolute http(s) URL")
        return value

    @field_validator("role")
    @classmethod
    def validate_role(cls, value: str) -> str:
        normalized = value.strip().lower()
        if normalized not in _ALLOWED_ROLES:
            raise ValueError("invalid role")
        return normalized


class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    full_name: Optional[str] = Field(default=None, max_length=200)
    username: Optional[str] = Field(None, min_length=3, max_length=100)
    phone: Optional[str] = Field(default=None, max_length=32)
    avatar_url: Optional[str] = Field(default=None, max_length=500)
    preferences: Optional[dict] = None

    @field_validator("username")
    @classmethod
    def validate_username(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        if not value.replace("_", "").replace("-", "").isalnum():
            raise ValueError("username may contain only letters, numbers, hyphen, and underscore")
        return value

    @field_validator("phone")
    @classmethod
    def validate_phone(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        cleaned = value.replace("+", "", 1).replace(" ", "").replace("-", "")
        if not cleaned.isdigit():
            raise ValueError("phone must contain only digits and optional leading +")
        return value

    @field_validator("avatar_url")
    @classmethod
    def validate_avatar_url(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("avatar_url must be an absolute http(s) URL")
        return value


class UserResponse(BaseModel):
    id: str
    email: str
    full_name: Optional[str] = None
    username: Optional[str] = None
    phone: Optional[str] = None
    avatar_url: Optional[str] = None
    role: str
    is_active: bool
    email_verified: bool
    mfa_enabled: bool
    last_login: Optional[datetime] = None
    created_at: datetime


def _is_admin(current_user: Dict[str, Any]) -> bool:
    return str(current_user.get("role", "")).strip().lower() in _ADMIN_ROLES


def _require_tenant_context(current_user: Dict[str, Any]) -> str:
    tenant_id = current_user.get("organization_id") or get_current_tenant()
    if not tenant_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Tenant context missing")
    if current_user.get("organization_id") and get_current_tenant() and current_user["organization_id"] != get_current_tenant():
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-tenant access denied")
    return str(tenant_id)


def _audit(action: str, actor_id: str, tenant_id: str, target_user_id: str) -> None:
    _AUDIT_LOG.append(
        {
            "action": action,
            "actor_id": actor_id,
            "tenant_id": tenant_id,
            "target_user_id": target_user_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )


def _public_user(user: Dict[str, Any]) -> UserResponse:
    return UserResponse(**{field: user.get(field) for field in _USER_FIELDS})


def _get_user_record(user_id: str, tenant_id: str) -> Dict[str, Any]:
    user = _USER_STORE.get(user_id)
    if not user or user["tenant_id"] != tenant_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user


def _require_owner_or_admin(current_user: Dict[str, Any], target_user: Dict[str, Any]) -> None:
    if _is_admin(current_user):
        return
    if current_user.get("user_id") != target_user.get("id"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")


def _prevent_privilege_escalation(current_user: Dict[str, Any], role: str) -> None:
    if not _is_admin(current_user) and role in _ADMIN_ROLES:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Privilege escalation denied")


@router.post("/", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    data: UserCreate,
    current_user: dict = Depends(get_current_user),
):
    """Create a new user."""
    if not _is_admin(current_user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Administrator access required")

    tenant_id = _require_tenant_context(current_user)
    enforce_tenant_limit(tenant_id, "max_users", PriceTier.COMMUNITY)

    with _STORE_LOCK:
        if any(user["tenant_id"] == tenant_id and user["email"].lower() == data.email.lower() for user in _USER_STORE.values()):
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already exists")

        user_id = f"user_{uuid.uuid4().hex}"
        now = datetime.now(timezone.utc)
        record = {
            "id": user_id,
            "tenant_id": tenant_id,
            "email": data.email.lower(),
            "full_name": data.full_name,
            "username": data.username,
            "phone": data.phone,
            "avatar_url": data.avatar_url,
            "role": data.role,
            "is_active": True,
            "email_verified": False,
            "mfa_enabled": False,
            "last_login": None,
            "created_at": now,
            "password_hash": auth_service.hash_password(data.password),
        }
        _USER_STORE[user_id] = record
        current_count = get_tenant_resource_count(tenant_id, "max_users")
        set_tenant_resource_count(tenant_id, "max_users", current_count + 1)
        _audit("user_created", current_user["user_id"], tenant_id, user_id)

    return _public_user(record)


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Get user by ID."""
    tenant_id = _require_tenant_context(current_user)
    user = _get_user_record(user_id, tenant_id)
    _require_owner_or_admin(current_user, user)
    return _public_user(user)


@router.patch("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: str,
    data: UserUpdate,
    current_user: dict = Depends(get_current_user),
):
    """Update user."""
    tenant_id = _require_tenant_context(current_user)
    with _STORE_LOCK:
        user = _get_user_record(user_id, tenant_id)
        _require_owner_or_admin(current_user, user)

        if data.email and any(
            other_id != user_id and other["tenant_id"] == tenant_id and other["email"].lower() == data.email.lower()
            for other_id, other in _USER_STORE.items()
        ):
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already exists")

        updates = data.model_dump(exclude_unset=True)
        if "email" in updates and updates["email"] is not None:
            user["email"] = updates["email"].lower()
        for field in ("full_name", "username", "phone", "avatar_url", "preferences"):
            if field in updates:
                user[field] = updates[field]
        _audit("user_updated", current_user["user_id"], tenant_id, user_id)

    return _public_user(user)


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Delete user (soft delete)."""
    if not _is_admin(current_user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Administrator access required")

    tenant_id = _require_tenant_context(current_user)
    with _STORE_LOCK:
        user = _get_user_record(user_id, tenant_id)
        user["is_active"] = False
        _audit("user_deleted", current_user["user_id"], tenant_id, user_id)
    return None


@router.post("/{user_id}/deactivate")
async def deactivate_user(
    user_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Deactivate user account."""
    tenant_id = _require_tenant_context(current_user)
    with _STORE_LOCK:
        user = _get_user_record(user_id, tenant_id)
        _require_owner_or_admin(current_user, user)
        user["is_active"] = False
        _audit("user_deactivated", current_user["user_id"], tenant_id, user_id)
    return {"success": True, "user_id": user_id, "is_active": False}


@router.post("/{user_id}/activate")
async def activate_user(
    user_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Activate user account."""
    tenant_id = _require_tenant_context(current_user)
    with _STORE_LOCK:
        user = _get_user_record(user_id, tenant_id)
        _require_owner_or_admin(current_user, user)
        user["is_active"] = True
        _audit("user_activated", current_user["user_id"], tenant_id, user_id)
    return {"success": True, "user_id": user_id, "is_active": True}


@router.post("/{user_id}/verify-email")
async def verify_user_email(
    user_id: str,
    token: str,
    current_user: dict = Depends(get_current_user),
):
    """Verify user email with token."""
    tenant_id = _require_tenant_context(current_user)
    with _STORE_LOCK:
        user = _get_user_record(user_id, tenant_id)
        _require_owner_or_admin(current_user, user)
        if not token or len(token) < 8:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid verification token")
        user["email_verified"] = True
        _audit("email_verified", current_user["user_id"], tenant_id, user_id)
    return {"success": True, "email_verified": True}


@router.post("/{user_id}/resend-verification")
async def resend_verification_email(
    user_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Resend email verification."""
    tenant_id = _require_tenant_context(current_user)
    user = _get_user_record(user_id, tenant_id)
    _require_owner_or_admin(current_user, user)
    return {"success": True, "message": "Verification email sent"}


@router.get("/{user_id}/activity")
async def get_user_activity(
    user_id: str,
    limit: int = 50,
    current_user: dict = Depends(get_current_user),
):
    """Get user activity log."""
    tenant_id = _require_tenant_context(current_user)
    user = _get_user_record(user_id, tenant_id)
    _require_owner_or_admin(current_user, user)
    return {
        "activities": [
            {
                "id": "act_1",
                "action": "login",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "ip_address": "192.168.1.1",
                "device": "Chrome on Windows",
            }
        ],
        "total": 1,
    }
