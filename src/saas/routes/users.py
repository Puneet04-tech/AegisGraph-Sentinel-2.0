"""User Management Routes
AegisGraph Sentinel Enterprise SaaS Platform
"""

from __future__ import annotations

import threading
import uuid
from collections import deque
from datetime import datetime, timezone
from typing import Any, Deque, Dict, List, Optional
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, EmailStr, Field, field_validator

from src.api.middleware.multi_tenancy import get_current_tenant
from src.saas.auth.credential_stores import (
    InMemoryEmailVerificationTokenStore,
    LoggingNotificationSender,
)
from src.saas.auth.password_policy import validate_password
from src.saas.auth.service import auth_service
from src.saas.routes.auth import get_current_user
from src.saas.services.limit_enforcer import (
    enforce_tenant_limit,
    get_tenant_resource_count,
    get_tenant_tier,
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

_SORTABLE_FIELDS = frozenset(
    {"created_at", "email", "full_name", "role", "last_login"}
)

# Retention cap: the audit trail is now readable through the activity endpoint,
# so it must not grow for the life of the process.
_AUDIT_LOG_CAPACITY = 10_000

_USER_STORE: Dict[str, Dict[str, Any]] = {}
_AUDIT_LOG: Deque[Dict[str, Any]] = deque(maxlen=_AUDIT_LOG_CAPACITY)
_STORE_LOCK = threading.RLock()

# Verification tokens are issued on registration and consumed once. Raw tokens
# are never stored -- only their hashes -- following the same pattern the
# password-reset flow already uses.
_verification_tokens = InMemoryEmailVerificationTokenStore()
_notification_sender = LoggingNotificationSender()


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

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, value: str) -> str:
        # Applied here as well as on password change and reset confirm, so a
        # weak password cannot enter through whichever entry point is used.
        result = validate_password(value)
        if not result.valid:
            raise ValueError(result.message)
        return value


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


class UserListResponse(BaseModel):
    """Paginated page of users within the caller's tenant."""
    items: List["UserResponse"]
    total: int = Field(description="Total matching users before pagination")
    page: int
    page_size: int
    has_more: bool


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


def _matches_filters(
    user: Dict[str, Any],
    needle: Optional[str],
    role: Optional[str],
    is_active: Optional[bool],
    email_verified: Optional[bool],
    mfa_enabled: Optional[bool],
) -> bool:
    """Apply the listing filters to one record."""
    if role is not None and str(user.get("role", "")).strip().lower() != role:
        return False
    for field, wanted in (
        ("is_active", is_active),
        ("email_verified", email_verified),
        ("mfa_enabled", mfa_enabled),
    ):
        if wanted is not None and bool(user.get(field)) is not wanted:
            return False

    if needle is None:
        return True

    # Optional fields may be None, so each is coerced before matching.
    haystack = " ".join(
        str(user.get(field) or "").lower()
        for field in ("email", "username", "full_name")
    )
    return needle in haystack


def _sort_key(user: Dict[str, Any], field: str) -> Any:
    """Build a comparable sort key, keeping None values orderable.

    Records missing an optional field sort last rather than raising on a
    None-to-value comparison.
    """
    value = user.get(field)
    if value is None:
        return (1, "")
    if isinstance(value, datetime):
        return (0, value.timestamp())
    return (0, str(value).lower())


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
    # Enforce against the tenant's actual subscription tier rather than
    # hardcoding the free COMMUNITY cap, so paid tenants are not blocked at
    # the free-tier limit.
    enforce_tenant_limit(tenant_id, "max_users", get_tenant_tier(tenant_id))

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

    # Issued outside the store lock: delivery must not hold up other writers.
    token = _verification_tokens.issue(user_id, record["email"])
    _notification_sender.send_email_verification(record["email"], token)

    return _public_user(record)


# Registered before /{user_id} so the literal path is matched first rather than
# being captured as a user id.
@router.get("/", response_model=UserListResponse)
async def list_users(
    page: int = Query(default=1, ge=1, description="1-based page number"),
    page_size: int = Query(default=25, ge=1, le=100, description="Users per page"),
    search: Optional[str] = Query(
        default=None,
        max_length=200,
        description="Case-insensitive substring match on email, username or full name",
    ),
    role: Optional[str] = Query(default=None, max_length=32),
    is_active: Optional[bool] = Query(default=None),
    email_verified: Optional[bool] = Query(default=None),
    mfa_enabled: Optional[bool] = Query(default=None),
    sort_by: str = Query(default="created_at", description="Field to sort on"),
    sort_order: str = Query(default="asc", pattern="^(asc|desc)$"),
    current_user: dict = Depends(get_current_user),
):
    """List users in the caller's organisation.

    Administrators see the whole tenant; anyone else sees only their own
    record, so the endpoint stays useful to both without leaking a directory.
    """
    tenant_id = _require_tenant_context(current_user)

    if sort_by not in _SORTABLE_FIELDS:
        # An allow-list rather than interpolating caller input into the sort.
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"sort_by must be one of: {', '.join(sorted(_SORTABLE_FIELDS))}",
        )

    normalized_role = role.strip().lower() if role else None
    needle = search.strip().lower() if search and search.strip() else None

    with _STORE_LOCK:
        candidates = [
            user for user in _USER_STORE.values() if user["tenant_id"] == tenant_id
        ]

        if not _is_admin(current_user):
            candidates = [
                user for user in candidates
                if user["id"] == current_user.get("user_id")
            ]

        matches = [
            user for user in candidates
            if _matches_filters(
                user,
                needle=needle,
                role=normalized_role,
                is_active=is_active,
                email_verified=email_verified,
                mfa_enabled=mfa_enabled,
            )
        ]

        # Tiebreak on id so a record with an equal sort value cannot drift
        # between pages and be shown twice or skipped.
        matches.sort(key=lambda user: (_sort_key(user, sort_by), user["id"]))
        if sort_order == "desc":
            matches.reverse()

        total = len(matches)
        start = (page - 1) * page_size
        page_items = matches[start:start + page_size]

        return UserListResponse(
            items=[_public_user(user) for user in page_items],
            total=total,
            page=page,
            page_size=page_size,
            has_more=start + len(page_items) < total,
        )


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
        email_changed = False
        if "email" in updates and updates["email"] is not None:
            new_email = updates["email"].lower()
            email_changed = new_email != user["email"]
            user["email"] = new_email
            if email_changed:
                # The new address has not been proven, and any token issued for
                # the old one must not verify it.
                user["email_verified"] = False
        for field in ("full_name", "username", "phone", "avatar_url", "preferences"):
            if field in updates:
                user[field] = updates[field]
        _audit("user_updated", current_user["user_id"], tenant_id, user_id)
        new_email = user["email"]

    if email_changed:
        _verification_tokens.invalidate_for_user(user_id)
        token = _verification_tokens.issue(user_id, new_email)
        _notification_sender.send_email_verification(new_email, token)

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
        was_active = user["is_active"]
        user["is_active"] = False
        # A removed user frees its seat, otherwise deleted users would
        # permanently occupy capacity against the subscription limit.
        if was_active:
            current_count = get_tenant_resource_count(tenant_id, "max_users")
            set_tenant_resource_count(tenant_id, "max_users", max(0, current_count - 1))
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
        was_active = user["is_active"]
        user["is_active"] = False
        # A deactivated user frees its seat, otherwise deactivated accounts
        # would permanently occupy capacity against the subscription limit.
        if was_active:
            current_count = get_tenant_resource_count(tenant_id, "max_users")
            set_tenant_resource_count(tenant_id, "max_users", max(0, current_count - 1))
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
        already_verified = bool(user.get("email_verified"))
        email = user["email"]

    # Verifying an address that is already verified succeeds without burning a
    # second token, so a double-clicked link is not an error.
    if already_verified:
        return {"success": True, "email_verified": True}

    # Unknown, expired, already-consumed, wrong-user and wrong-address tokens
    # all fail identically, so the response cannot be used to probe which
    # tokens exist.
    if not _verification_tokens.consume(token, user_id, email):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid or expired verification token",
        )

    with _STORE_LOCK:
        user = _get_user_record(user_id, tenant_id)
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
    with _STORE_LOCK:
        user = _get_user_record(user_id, tenant_id)
        _require_owner_or_admin(current_user, user)
        already_verified = bool(user.get("email_verified"))
        email = user["email"]

    if already_verified:
        return {"success": True, "message": "Email is already verified"}

    # Throttled so the endpoint cannot be driven as a mail relay aimed at
    # somebody else's inbox.
    wait_seconds = _verification_tokens.seconds_until_resend_allowed(user_id)
    if wait_seconds > 0:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Verification email requested too recently",
            headers={"Retry-After": str(wait_seconds)},
        )

    # issue() invalidates any outstanding token, so the previous link stops
    # working the moment a new one is sent.
    token = _verification_tokens.issue(user_id, email)
    _notification_sender.send_email_verification(email, token)
    _audit("verification_resent", current_user["user_id"], tenant_id, user_id)

    return {"success": True, "message": "Verification email sent"}


@router.get("/{user_id}/activity")
async def get_user_activity(
    user_id: str,
    limit: int = Query(default=50, ge=1, le=500, description="Maximum entries to return"),
    current_user: dict = Depends(get_current_user),
):
    """Get user activity log.

    Served from the audit entries this module already records. It previously
    returned a single hardcoded record with an invented IP and device string,
    presenting fabricated login metadata as though it were real, and ignored
    its ``limit`` entirely.
    """
    tenant_id = _require_tenant_context(current_user)
    with _STORE_LOCK:
        user = _get_user_record(user_id, tenant_id)
        _require_owner_or_admin(current_user, user)

        # Newest first, scoped to both the target user and the caller's tenant.
        matching = [
            entry for entry in reversed(_AUDIT_LOG)
            if entry["target_user_id"] == user_id and entry["tenant_id"] == tenant_id
        ]

    return {
        "activities": [
            {
                "id": f"act_{index}",
                "action": entry["action"],
                "actor_id": entry["actor_id"],
                "timestamp": entry["timestamp"],
            }
            for index, entry in enumerate(matching[:limit], start=1)
        ],
        # The count is of everything recorded, not just the page returned.
        "total": len(matching),
    }
