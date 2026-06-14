"""
Enterprise Security Collaboration Platform - Data Models
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
import uuid


class WorkspaceType(str, Enum):
    """Workspace types."""
    INVESTIGATION = "INVESTIGATION"
    THREAT_INTEL = "THREAT_INTEL"
    FRAUD = "FRAUD"
    COMPLIANCE = "COMPLIANCE"
    GENERAL = "GENERAL"


class SessionStatus(str, Enum):
    """Session status."""
    ACTIVE = "ACTIVE"
    ARCHIVED = "ARCHIVED"


class Workspace(BaseModel):
    """Collaboration workspace."""
    workspace_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str
    workspace_type: WorkspaceType
    owner: str = ""
    members: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Team(BaseModel):
    """Security team."""
    team_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str
    team_lead: str = ""
    members: List[str] = Field(default_factory=list)
    specialties: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class CollaborationSession(BaseModel):
    """Collaboration session."""
    session_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    workspace_id: str
    title: str
    status: SessionStatus = SessionStatus.ACTIVE
    participants: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    ended_at: Optional[datetime] = None


class Message(BaseModel):
    """Collaboration message."""
    message_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    workspace_id: str
    sender: str
    content: str
    attachments: List[Dict[str, Any]] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class SharedInvestigation(BaseModel):
    """Shared investigation."""
    investigation_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    workspace_id: str
    title: str
    owner: str
    shared_with: List[str] = Field(default_factory=list)
    permissions: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class CollaborationMetrics(BaseModel):
    """Collaboration metrics."""
    total_workspaces: int = 0
    total_teams: int = 0
    total_messages: int = 0
    active_sessions: int = 0
    shared_investigations: int = 0
