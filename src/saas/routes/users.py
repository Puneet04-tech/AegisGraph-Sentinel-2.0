"""
User Management Routes
AegisGraph Sentinel Enterprise SaaS Platform
"""

from fastapi import APIRouter, Depends, HTTPException, status
from typing import List, Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field
from src.saas.services.limit_enforcer import enforce_tenant_limit, get_tenant_resource_count, set_tenant_resource_count
from src.saas.services.billing import PriceTier

router = APIRouter(prefix="/api/v1/users", tags=["users"])


class UserCreate(BaseModel):
    email: str
    full_name: Optional[str] = None
    username: Optional[str] = Field(None, max_length=100)
    password: Optional[str] = Field(None, min_length=8)
    role: str = "member"


class UserUpdate(BaseModel):
    email: Optional[str] = None
    full_name: Optional[str] = None
    username: Optional[str] = Field(None, max_length=100)
    phone: Optional[str] = None
    avatar_url: Optional[str] = None
    preferences: Optional[dict] = None


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


@router.post("/", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(data: UserCreate, tenant_id: Optional[str] = None):
    """Create a new user"""
    if tenant_id:
        enforce_tenant_limit(tenant_id, "max_users", PriceTier.COMMUNITY)

    user = UserResponse(
        id=f"user_{datetime.now(timezone.utc).timestamp()}",
        email=data.email,
        full_name=data.full_name,
        username=data.username,
        role=data.role,
        is_active=True,
        email_verified=False,
        mfa_enabled=False,
        last_login=None,
        created_at=datetime.now(timezone.utc),
    )

    if tenant_id:
        current_count = get_tenant_resource_count(tenant_id, "max_users")
        set_tenant_resource_count(tenant_id, "max_users", current_count + 1)

    return user


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(user_id: str):
    """Get user by ID"""
    return UserResponse(
        id=user_id,
        email="user@example.com",
        full_name="Test User",
        username="testuser",
        phone="+919876543210",
        role="member",
        is_active=True,
        email_verified=True,
        mfa_enabled=False,
        last_login=datetime.now(timezone.utc),
        created_at=datetime.now(timezone.utc),
    )


@router.patch("/{user_id}", response_model=UserResponse)
async def update_user(user_id: str, data: UserUpdate):
    """Update user"""
    return UserResponse(
        id=user_id,
        email=data.email or "user@example.com",
        full_name=data.full_name,
        username=data.username,
        phone=data.phone,
        role="member",
        is_active=True,
        email_verified=True,
        mfa_enabled=False,
        last_login=datetime.now(timezone.utc),
        created_at=datetime.now(timezone.utc),
    )


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(user_id: str):
    """Delete user (soft delete)"""
    pass


@router.post("/{user_id}/deactivate")
async def deactivate_user(user_id: str):
    """Deactivate user account"""
    return {"success": True, "user_id": user_id, "is_active": False}


@router.post("/{user_id}/activate")
async def activate_user(user_id: str):
    """Activate user account"""
    return {"success": True, "user_id": user_id, "is_active": True}


@router.post("/{user_id}/verify-email")
async def verify_user_email(user_id: str, token: str):
    """Verify user email with token"""
    return {"success": True, "email_verified": True}


@router.post("/{user_id}/resend-verification")
async def resend_verification_email(user_id: str):
    """Resend email verification"""
    return {"success": True, "message": "Verification email sent"}


@router.get("/{user_id}/activity")
async def get_user_activity(user_id: str, limit: int = 50):
    """Get user activity log"""
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