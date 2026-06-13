"""
Enterprise Security Collaboration Platform Service
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .models import (
    Workspace,
    Team,
    CollaborationSession,
    Message,
    SharedInvestigation,
    CollaborationMetrics,
    WorkspaceType,
    SessionStatus,
)
from .store import get_collaboration_store, CollaborationStore, reset_collaboration_store


class CollaborationService:
    """Core collaboration service."""

    def __init__(self, store: Optional[CollaborationStore] = None):
        self._store = store or get_collaboration_store()

    def create_workspace(
        self,
        name: str,
        description: str,
        workspace_type: WorkspaceType,
        owner: str = "",
    ) -> Workspace:
        """Create a workspace."""
        workspace = Workspace(
            name=name,
            description=description,
            workspace_type=workspace_type,
            owner=owner,
        )
        self._store.store_workspace(workspace)
        return workspace

    def get_workspace(self, workspace_id: str) -> Optional[Workspace]:
        """Get workspace by ID."""
        return self._store.get_workspace(workspace_id)

    def get_workspaces(
        self, workspace_type: Optional[WorkspaceType] = None
    ) -> List[Workspace]:
        """Get workspaces."""
        if workspace_type:
            return self._store.get_workspaces_by_type(workspace_type)
        return self._store.get_all_workspaces()

    def add_member(
        self, workspace_id: str, member: str
    ) -> Optional[Workspace]:
        """Add a member to workspace."""
        workspace = self._store.get_workspace(workspace_id)
        if workspace and member not in workspace.members:
            workspace.members.append(member)
            self._store.store_workspace(workspace)
        return workspace

    def create_team(
        self,
        name: str,
        description: str,
        team_lead: str = "",
        specialties: List[str] = None,
    ) -> Team:
        """Create a team."""
        team = Team(
            name=name,
            description=description,
            team_lead=team_lead,
            specialties=specialties or [],
        )
        self._store.store_team(team)
        return team

    def get_team(self, team_id: str) -> Optional[Team]:
        """Get team by ID."""
        return self._store.get_team(team_id)

    def get_all_teams(self) -> List[Team]:
        """Get all teams."""
        return self._store.get_all_teams()

    def start_session(
        self,
        workspace_id: str,
        title: str,
        participants: List[str],
    ) -> Optional[CollaborationSession]:
        """Start a collaboration session."""
        session = CollaborationSession(
            workspace_id=workspace_id,
            title=title,
            participants=participants,
        )
        self._store.store_session(session)
        return session

    def get_session(self, session_id: str) -> Optional[CollaborationSession]:
        """Get session by ID."""
        return self._store.get_session(session_id)

    def end_session(self, session_id: str) -> Optional[CollaborationSession]:
        """End a collaboration session."""
        session = self._store.get_session(session_id)
        if session:
            session.status = SessionStatus.ARCHIVED
            session.ended_at = datetime.now(timezone.utc)
            self._store.store_session(session)
        return session

    def send_message(
        self,
        workspace_id: str,
        sender: str,
        content: str,
        attachments: List[Dict[str, Any]] = None,
    ) -> Message:
        """Send a message."""
        message = Message(
            workspace_id=workspace_id,
            sender=sender,
            content=content,
            attachments=attachments or [],
        )
        self._store.store_message(message)
        return message

    def get_messages(self, workspace_id: str) -> List[Message]:
        """Get messages for workspace."""
        return self._store.get_messages_by_workspace(workspace_id)

    def share_investigation(
        self,
        workspace_id: str,
        title: str,
        owner: str,
        shared_with: List[str],
        permissions: Dict[str, Any] = None,
    ) -> SharedInvestigation:
        """Share an investigation."""
        investigation = SharedInvestigation(
            workspace_id=workspace_id,
            title=title,
            owner=owner,
            shared_with=shared_with,
            permissions=permissions or {},
        )
        self._store.store_investigation(investigation)
        return investigation

    def get_investigation(
        self, investigation_id: str
    ) -> Optional[SharedInvestigation]:
        """Get investigation by ID."""
        return self._store.get_investigation(investigation_id)

    def get_investigations(self, workspace_id: str) -> List[SharedInvestigation]:
        """Get investigations for workspace."""
        return self._store.get_investigations_by_workspace(workspace_id)

    def get_metrics(self) -> CollaborationMetrics:
        """Get collaboration metrics."""
        metrics_dict = self._store.get_metrics()
        return CollaborationMetrics(**metrics_dict)

    def clear(self) -> None:
        """Clear all data."""
        reset_collaboration_store()


_collaboration_service: Optional[CollaborationService] = None


def get_collaboration_service() -> CollaborationService:
    global _collaboration_service
    if _collaboration_service is None:
        _collaboration_service = CollaborationService()
    return _collaboration_service


def reset_collaboration_service() -> None:
    global _collaboration_service
    _collaboration_service = None
    reset_collaboration_store()
