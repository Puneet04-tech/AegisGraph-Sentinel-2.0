"""
Workspace Management Routes
AegisGraph Sentinel Enterprise SaaS Platform
"""

import threading
import uuid

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field

from src.saas.routes.auth import get_current_user
from src.saas.routes.organizations import _require_org_access

router = APIRouter(prefix="/api/v1/workspaces", tags=["workspaces"])

# Kept in step with the role sets in src/saas/routes/users.py, so a caller who
# is an administrator for user management is an administrator here too.
_ADMIN_ROLES = {"admin", "administrator", "super_admin", "owner"}
_MEMBER_ROLES = {"member", "viewer", "analyst", "auditor"}
_ALLOWED_MEMBER_ROLES = _ADMIN_ROLES | _MEMBER_ROLES

_DEFAULT_MAX_MEMBERS = 20
_DEFAULT_MAX_CASES = 1000

_WORKSPACE_STORE: Dict[str, Dict[str, Any]] = {}
_STORE_LOCK = threading.RLock()


def _is_admin(current_user: Dict[str, Any]) -> bool:
    return str(current_user.get("role", "")).strip().lower() in _ADMIN_ROLES


def _require_tenant(current_user: Dict[str, Any]) -> str:
    """Resolve the caller's organization, refusing a request without one."""
    organization_id = current_user.get("organization_id")
    if not organization_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Tenant context missing",
        )
    return str(organization_id)


def _require_admin(current_user: Dict[str, Any]) -> None:
    if not _is_admin(current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator access required",
        )


def _get_workspace(workspace_id: str, organization_id: str) -> Dict[str, Any]:
    """Fetch a workspace scoped to the caller's tenant.

    A workspace belonging to another organization is reported as missing rather
    than forbidden, so the endpoint cannot be used to probe which workspace ids
    exist in other tenants.
    """
    workspace = _WORKSPACE_STORE.get(workspace_id)
    if not workspace or workspace["organization_id"] != organization_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Workspace not found",
        )
    return workspace


def _public_workspace(workspace: Dict[str, Any]) -> "WorkspaceResponse":
    return WorkspaceResponse(
        id=workspace["id"],
        name=workspace["name"],
        slug=workspace["slug"],
        description=workspace["description"],
        organization_id=workspace["organization_id"],
        is_active=workspace["is_active"],
        is_default=workspace["is_default"],
        max_members=workspace["max_members"],
        max_cases=workspace["max_cases"],
        created_at=workspace["created_at"],
    )


def reset_workspace_store() -> None:
    """Clear all workspace state (used by tests)."""
    with _STORE_LOCK:
        _WORKSPACE_STORE.clear()


class WorkspaceCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    slug: str = Field(..., min_length=2, max_length=100)
    description: Optional[str] = None


class WorkspaceUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    settings: Optional[dict] = None


class WorkspaceResponse(BaseModel):
    id: str
    name: str
    slug: str
    description: Optional[str]
    organization_id: str
    is_active: bool
    is_default: bool
    max_members: int
    max_cases: int
    created_at: datetime


class WorkspaceMember(BaseModel):
    user_id: str
    email: str
    full_name: Optional[str]
    role: str
    permissions: List[str]
    joined_at: datetime


class SuccessResponse(BaseModel):
    """Standard success response for workspace mutation endpoints."""
    success: bool = Field(default=True, description="Always True on success")
    message: Optional[str] = Field(default=None, description="Optional human-readable message")


class MemberActionResponse(BaseModel):
    """Response returned after a workspace member action."""
    success: bool = Field(default=True)
    user_id: str
    workspace_id: str
    role: Optional[str] = None
    permissions: Optional[List[str]] = None


class WorkspaceSettingsResponse(BaseModel):
    """Response model for workspace settings."""
    default_case_priority: str = Field(
        ...,
        description="Priority assigned to new cases by default",
    )
    auto_assignment: bool = Field(
        ...,
        description="Whether new cases are auto-assigned to team members",
    )
    notification_preferences: dict = Field(
        default_factory=dict,
        description="Notification channel preferences",
    )


class WorkspaceSettingsUpdate(BaseModel):
    """Request model for updating workspace settings."""
    default_case_priority: Optional[str] = Field(
        None,
        pattern="^(low|medium|high|critical)$",
        description="Priority for new cases",
    )
    auto_assignment: Optional[bool] = Field(
        None,
        description="Enable or disable auto-assignment",
    )
    notification_preferences: Optional[dict] = Field(
        None,
        description="Notification channel preferences",
    )


@router.post("/", response_model=WorkspaceResponse, status_code=status.HTTP_201_CREATED)
async def create_workspace(
    data: WorkspaceCreate,
    organization_id: Optional[str] = Query(
        default=None,
        description="Optional organization identifier; must match the caller's tenant",
    ),
    current_user: dict = Depends(get_current_user),
):
    """Create a new workspace"""
    _require_admin(current_user)
    tenant_id = _require_tenant(current_user)
    if organization_id is not None:
        # The tenant is derived from the authenticated identity; a supplied
        # value may only confirm it, never redirect the write elsewhere.
        _require_org_access(organization_id, current_user)

    with _STORE_LOCK:
        slug = data.slug.strip().lower()
        if any(
            workspace["organization_id"] == tenant_id and workspace["slug"] == slug
            for workspace in _WORKSPACE_STORE.values()
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Workspace slug already exists in this organization",
            )

        workspace_id = f"ws_{uuid.uuid4().hex}"
        workspace = {
            "id": workspace_id,
            "name": data.name,
            "slug": slug,
            "description": data.description,
            "organization_id": tenant_id,
            "is_active": True,
            # The first workspace in an organization becomes its default.
            "is_default": not any(
                w["organization_id"] == tenant_id for w in _WORKSPACE_STORE.values()
            ),
            "max_members": _DEFAULT_MAX_MEMBERS,
            "max_cases": _DEFAULT_MAX_CASES,
            "created_at": datetime.now(timezone.utc),
            "members": {},
            "settings": {
                "default_case_priority": "medium",
                "auto_assignment": True,
                "notification_preferences": {},
            },
        }
        _WORKSPACE_STORE[workspace_id] = workspace

    return _public_workspace(workspace)


@router.get(
    "/{workspace_id}",
    response_model=WorkspaceResponse,
)
async def get_workspace(
    workspace_id: str = Path(
        ...,
        min_length=3,
        max_length=64,
        pattern=r"^[a-zA-Z0-9_-]+$",
        description="Workspace identifier",
    ),
    current_user: dict = Depends(get_current_user),
):
    """Get workspace by ID"""
    tenant_id = _require_tenant(current_user)
    with _STORE_LOCK:
        workspace = _get_workspace(workspace_id, tenant_id)
        return _public_workspace(workspace)


@router.get("/", response_model=List[WorkspaceResponse])
async def list_workspaces(
    current_user: dict = Depends(get_current_user),
):
    """List every workspace in the caller's organization"""
    tenant_id = _require_tenant(current_user)
    with _STORE_LOCK:
        return [
            _public_workspace(workspace)
            for workspace in _WORKSPACE_STORE.values()
            if workspace["organization_id"] == tenant_id
        ]


@router.patch("/{workspace_id}", response_model=WorkspaceResponse)
async def update_workspace(
    data: WorkspaceUpdate,
    workspace_id: str = Path(
        ...,
        min_length=3,
        max_length=64,
        pattern=r"^[a-zA-Z0-9_-]+$",
        description="Workspace identifier",
    ),
    current_user: dict = Depends(get_current_user),
):
    """Update workspace"""
    _require_admin(current_user)
    tenant_id = _require_tenant(current_user)

    with _STORE_LOCK:
        workspace = _get_workspace(workspace_id, tenant_id)
        updates = data.model_dump(exclude_unset=True)
        for field in ("name", "description"):
            if field in updates and updates[field] is not None:
                workspace[field] = updates[field]
        if "settings" in updates and updates["settings"] is not None:
            workspace["settings"].update(updates["settings"])

        return _public_workspace(workspace)


@router.delete("/{workspace_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_workspace(
    workspace_id: str = Path(
        ...,
        min_length=3,
        max_length=64,
        pattern=r"^[a-zA-Z0-9_-]+$",
        description="Workspace identifier",
    ),
    current_user: dict = Depends(get_current_user),
):
    """Delete workspace"""
    _require_admin(current_user)
    tenant_id = _require_tenant(current_user)

    with _STORE_LOCK:
        workspace = _get_workspace(workspace_id, tenant_id)
        if workspace["is_default"]:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="The default workspace cannot be deleted",
            )
        del _WORKSPACE_STORE[workspace_id]
    return None


@router.get(
    "/{workspace_id}/members",
    response_model=List[WorkspaceMember],
)
async def list_workspace_members(
    workspace_id: str = Path(
        ...,
        min_length=3,
        max_length=64,
        pattern=r"^[a-zA-Z0-9_-]+$",
        description="Workspace identifier",
    ),
    current_user: dict = Depends(get_current_user),
):
    """List workspace members"""
    tenant_id = _require_tenant(current_user)
    with _STORE_LOCK:
        workspace = _get_workspace(workspace_id, tenant_id)
        return [
            WorkspaceMember(**member)
            for member in workspace["members"].values()
        ]


@router.post("/{workspace_id}/members", response_model=MemberActionResponse)
async def add_workspace_member(
    workspace_id: str = Path(
        ...,
        min_length=3,
        max_length=64,
        pattern=r"^[a-zA-Z0-9_-]+$",
        description="Workspace identifier",
    ),
    user_id: str = Query(
        ...,
        min_length=3,
        max_length=128,
        description="User identifier",
    ),
    role: str = Query(
        default="member",
        pattern=r"^(member|admin|viewer)$",
        description="Role to assign to the user",
    ),
    permissions: Optional[List[str]] = None,
    current_user: dict = Depends(get_current_user),
):
    """Add member to workspace"""
    _require_admin(current_user)
    tenant_id = _require_tenant(current_user)
    resolved_permissions = permissions if permissions is not None else []

    with _STORE_LOCK:
        workspace = _get_workspace(workspace_id, tenant_id)
        if user_id in workspace["members"]:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="User is already a member of this workspace",
            )
        # The advertised max_members limit is now actually enforced.
        if len(workspace["members"]) >= workspace["max_members"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Workspace member limit reached",
            )

        workspace["members"][user_id] = {
            "user_id": user_id,
            "email": f"{user_id}@unknown.invalid",
            "full_name": None,
            "role": role,
            "permissions": resolved_permissions,
            "joined_at": datetime.now(timezone.utc),
        }

    return MemberActionResponse(
        success=True,
        user_id=user_id,
        workspace_id=workspace_id,
        role=role,
        permissions=resolved_permissions,
    )


@router.patch("/{workspace_id}/members/{user_id}", response_model=MemberActionResponse)
async def update_workspace_member(
    workspace_id: str = Path(
        ...,
        min_length=3,
        max_length=64,
        pattern=r"^[a-zA-Z0-9_-]+$",
        description="Workspace identifier",
    ),
    user_id: str = Path(
        ...,
        min_length=3,
        max_length=128,
        description="User identifier",
    ),
    role: Optional[str] = None,
    permissions: Optional[List[str]] = None,
    current_user: dict = Depends(get_current_user),
):
    """Update workspace member"""
    _require_admin(current_user)
    tenant_id = _require_tenant(current_user)

    if role is not None and role.strip().lower() not in _ALLOWED_MEMBER_ROLES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid role",
        )

    with _STORE_LOCK:
        workspace = _get_workspace(workspace_id, tenant_id)
        member = workspace["members"].get(user_id)
        if member is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Member not found in this workspace",
            )

        if role is not None:
            member["role"] = role.strip().lower()
        if permissions is not None:
            member["permissions"] = permissions

        return MemberActionResponse(
            success=True,
            user_id=user_id,
            workspace_id=workspace_id,
            role=member["role"],
            permissions=member["permissions"],
        )


@router.delete("/{workspace_id}/members/{user_id}", response_model=SuccessResponse)
async def remove_workspace_member(
    workspace_id: str = Path(
        ...,
        min_length=3,
        max_length=64,
        pattern=r"^[a-zA-Z0-9_-]+$",
        description="Workspace identifier",
    ),
    user_id: str = Path(
        ...,
        min_length=3,
        max_length=128,
        description="User identifier",
    ),
    current_user: dict = Depends(get_current_user),
):
    """Remove member from workspace"""
    _require_admin(current_user)
    tenant_id = _require_tenant(current_user)

    with _STORE_LOCK:
        workspace = _get_workspace(workspace_id, tenant_id)
        if user_id not in workspace["members"]:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Member not found in this workspace",
            )
        del workspace["members"][user_id]

    return SuccessResponse(success=True, message=f"User {user_id} removed from workspace {workspace_id}")


@router.get("/{workspace_id}/cases")
async def list_workspace_cases(
    workspace_id: str = Path(
        ...,
        min_length=3,
        max_length=64,
        pattern=r"^[a-zA-Z0-9_-]+$",
        description="Workspace identifier",
    ),
    limit: int = Query(default=50, ge=1, le=1000, description="Maximum number of cases to return"),
    current_user: dict = Depends(get_current_user),
):
    """List cases in workspace"""
    tenant_id = _require_tenant(current_user)
    with _STORE_LOCK:
        _get_workspace(workspace_id, tenant_id)

    return {
        "cases": [],
        "total": 0,
        "limit": limit,
    }


@router.get("/{workspace_id}/settings", response_model=WorkspaceSettingsResponse)
async def get_workspace_settings(
    workspace_id: str = Path(
        ...,
        min_length=3,
        max_length=64,
        pattern=r"^[a-zA-Z0-9_-]+$",
        description="Workspace identifier",
    ),
    current_user: dict = Depends(get_current_user),
):
    """Get workspace settings"""
    tenant_id = _require_tenant(current_user)
    with _STORE_LOCK:
        workspace = _get_workspace(workspace_id, tenant_id)
        settings = workspace["settings"]
        return WorkspaceSettingsResponse(
            default_case_priority=settings["default_case_priority"],
            auto_assignment=settings["auto_assignment"],
            notification_preferences=dict(settings["notification_preferences"]),
        )


@router.patch("/{workspace_id}/settings", response_model=WorkspaceSettingsResponse)
async def update_workspace_settings(
    workspace_id: str = Path(
        ...,
        min_length=3,
        max_length=64,
        pattern=r"^[a-zA-Z0-9_-]+$",
        description="Workspace identifier",
    ),
    data: WorkspaceSettingsUpdate = ...,
    current_user: dict = Depends(get_current_user),
):
    """Update workspace settings"""
    _require_admin(current_user)
    tenant_id = _require_tenant(current_user)

    with _STORE_LOCK:
        workspace = _get_workspace(workspace_id, tenant_id)
        settings = workspace["settings"]
        # Only fields the caller actually sent are applied, so a partial update
        # cannot silently reset the others to their defaults.
        updates = data.model_dump(exclude_unset=True)
        for field in ("default_case_priority", "auto_assignment", "notification_preferences"):
            if field in updates and updates[field] is not None:
                settings[field] = updates[field]

        return WorkspaceSettingsResponse(
            default_case_priority=settings["default_case_priority"],
            auto_assignment=settings["auto_assignment"],
            notification_preferences=dict(settings["notification_preferences"]),
        )
