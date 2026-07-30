"""
Workspace Management Routes
AegisGraph Sentinel Enterprise SaaS Platform
"""

from fastapi import APIRouter, HTTPException, Path, Query, status
from typing import List, Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/v1/workspaces", tags=["workspaces"])


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
    organization_id: str,
):
    """Create a new workspace"""
    return WorkspaceResponse(
        id=f"ws_{datetime.now(timezone.utc).timestamp()}",
        name=data.name,
        slug=data.slug,
        description=data.description,
        organization_id=organization_id,
        is_active=True,
        is_default=False,
        max_members=20,
        max_cases=1000,
        created_at=datetime.now(timezone.utc),
    )


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
):
    """Get workspace by ID"""
    return WorkspaceResponse(
        id=workspace_id,
        name="Default Workspace",
        slug="default",
        description="Default workspace for team",
        organization_id="org_123",
        is_active=True,
        is_default=True,
        max_members=20,
        max_cases=1000,
        created_at=datetime.now(timezone.utc),
    )


@router.patch("/{workspace_id}", response_model=WorkspaceResponse)
async def update_workspace(
    workspace_id: str,
    data: WorkspaceUpdate,
):
    """Update workspace"""
    return WorkspaceResponse(
        id=workspace_id,
        name=data.name or "Updated Workspace",
        slug="updated",
        description=data.description,
        organization_id="org_123",
        is_active=True,
        is_default=False,
        max_members=20,
        max_cases=1000,
        created_at=datetime.now(timezone.utc),
    )


@router.delete("/{workspace_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_workspace(
    workspace_id: str = Path(
        ...,
        min_length=3,
        max_length=64,
        pattern=r"^[a-zA-Z0-9_-]+$",
        description="Workspace identifier",
    ),
):
    """Delete workspace"""
    pass


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
):
    """List workspace members"""
    return [
        WorkspaceMember(
            user_id="user_1",
            email="admin@example.com",
            full_name="Admin User",
            role="admin",
            permissions=["read", "write", "delete"],
            joined_at=datetime.now(timezone.utc),
        )
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
):
    """Add member to workspace"""
    resolved_permissions = permissions if permissions is not None else []
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
):
    """Update workspace member"""
    return MemberActionResponse(
        success=True,
        user_id=user_id,
        workspace_id=workspace_id,
        role=role,
        permissions=permissions,
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
):
    """Remove member from workspace"""
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
):
    """List cases in workspace"""
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
):
    """Get workspace settings"""
    return WorkspaceSettingsResponse(
        default_case_priority="medium",
        auto_assignment=True,
        notification_preferences={},
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
):
    """Update workspace settings"""
    return WorkspaceSettingsResponse(
        default_case_priority=data.default_case_priority or "medium",
        auto_assignment=data.auto_assignment if data.auto_assignment is not None else True,
        notification_preferences=data.notification_preferences or {},
    )
