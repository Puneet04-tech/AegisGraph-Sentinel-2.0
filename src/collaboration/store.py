"""
Enterprise Security Collaboration Platform Store - Thread-safe storage
"""

from __future__ import annotations

from threading import Lock
from typing import Any, Dict, List, Optional

from .models import (
    Workspace,
    Team,
    CollaborationSession,
    Message,
    SharedInvestigation,
    WorkspaceType,
    SessionStatus,
)


class CollaborationStore:
    """Thread-safe storage for collaboration data."""

    def __init__(self):
        self._lock = Lock()
        self._workspaces: Dict[str, Workspace] = {}
        self._teams: Dict[str, Team] = {}
        self._sessions: Dict[str, CollaborationSession] = {}
        self._messages: Dict[str, Message] = {}
        self._investigations: Dict[str, SharedInvestigation] = {}

    def store_workspace(self, workspace: Workspace) -> Workspace:
        with self._lock:
            self._workspaces[workspace.workspace_id] = workspace
        return workspace

    def get_workspace(self, workspace_id: str) -> Optional[Workspace]:
        return self._workspaces.get(workspace_id)

    def get_workspaces_by_type(
        self, workspace_type: WorkspaceType
    ) -> List[Workspace]:
        return [w for w in self._workspaces.values() if w.workspace_type == workspace_type]

    def get_all_workspaces(self) -> List[Workspace]:
        return list(self._workspaces.values())

    def store_team(self, team: Team) -> Team:
        with self._lock:
            self._teams[team.team_id] = team
        return team

    def get_team(self, team_id: str) -> Optional[Team]:
        return self._teams.get(team_id)

    def get_all_teams(self) -> List[Team]:
        return list(self._teams.values())

    def store_session(self, session: CollaborationSession) -> CollaborationSession:
        with self._lock:
            self._sessions[session.session_id] = session
        return session

    def get_session(self, session_id: str) -> Optional[CollaborationSession]:
        return self._sessions.get(session_id)

    def get_sessions_by_workspace(
        self, workspace_id: str
    ) -> List[CollaborationSession]:
        return [s for s in self._sessions.values() if s.workspace_id == workspace_id]

    def get_active_sessions(self) -> List[CollaborationSession]:
        return [s for s in self._sessions.values() if s.status == SessionStatus.ACTIVE]

    def store_message(self, message: Message) -> Message:
        with self._lock:
            self._messages[message.message_id] = message
        return message

    def get_message(self, message_id: str) -> Optional[Message]:
        return self._messages.get(message_id)

    def get_messages_by_workspace(
        self, workspace_id: str
    ) -> List[Message]:
        return [m for m in self._messages.values() if m.workspace_id == workspace_id]

    def store_investigation(
        self, investigation: SharedInvestigation
    ) -> SharedInvestigation:
        with self._lock:
            self._investigations[investigation.investigation_id] = investigation
        return investigation

    def get_investigation(
        self, investigation_id: str
    ) -> Optional[SharedInvestigation]:
        return self._investigations.get(investigation_id)

    def get_investigations_by_workspace(
        self, workspace_id: str
    ) -> List[SharedInvestigation]:
        return [
            i for i in self._investigations.values()
            if i.workspace_id == workspace_id
        ]

    def get_metrics(self) -> Dict[str, Any]:
        return {
            "total_workspaces": len(self._workspaces),
            "total_teams": len(self._teams),
            "total_messages": len(self._messages),
            "active_sessions": len(self.get_active_sessions()),
            "shared_investigations": len(self._investigations),
        }


_collaboration_store: Optional[CollaborationStore] = None
_store_lock = Lock()


def get_collaboration_store() -> CollaborationStore:
    global _collaboration_store
    with _store_lock:
        if _collaboration_store is None:
            _collaboration_store = CollaborationStore()
        return _collaboration_store


def reset_collaboration_store() -> None:
    global _collaboration_store
    with _store_lock:
        _collaboration_store = CollaborationStore()
