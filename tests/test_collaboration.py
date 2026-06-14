"""
Tests for Enterprise Security Collaboration Platform
"""

import pytest

from src.collaboration.models import (
    Workspace,
    Team,
    CollaborationSession,
    Message,
    WorkspaceType,
    SessionStatus,
)
from src.collaboration.store import get_collaboration_store, reset_collaboration_store
from src.collaboration.service import CollaborationService


class TestCollaborationModels:
    """Tests for collaboration models."""

    def test_create_workspace(self):
        """Test creating a workspace."""
        workspace = Workspace(
            name="Fraud Investigation",
            description="Collaborative fraud investigation",
            workspace_type=WorkspaceType.FRAUD,
        )
        assert workspace.name == "Fraud Investigation"
        assert workspace.workspace_type == WorkspaceType.FRAUD

    def test_create_team(self):
        """Test creating a team."""
        team = Team(
            name="SOC Team",
            description="Security operations team",
            team_lead="analyst@example.com",
        )
        assert team.team_lead == "analyst@example.com"

    def test_create_session(self):
        """Test creating a session."""
        session = CollaborationSession(
            workspace_id="ws-001",
            title="Daily Standup",
            participants=["user1", "user2"],
        )
        assert session.status == SessionStatus.ACTIVE

    def test_create_message(self):
        """Test creating a message."""
        message = Message(
            workspace_id="ws-001",
            sender="analyst@example.com",
            content="New threat detected",
        )
        assert message.content == "New threat detected"


class TestCollaborationStore:
    """Tests for collaboration store."""

    def setup_method(self):
        """Set up test store."""
        reset_collaboration_store()
        self.store = get_collaboration_store()

    def test_store_workspace(self):
        """Test storing a workspace."""
        workspace = Workspace(
            name="Test",
            description="Test",
            workspace_type=WorkspaceType.GENERAL,
        )
        self.store.store_workspace(workspace)
        retrieved = self.store.get_workspace(workspace.workspace_id)
        assert retrieved is not None

    def test_store_team(self):
        """Test storing a team."""
        team = Team(name="Test", description="Test")
        self.store.store_team(team)
        retrieved = self.store.get_team(team.team_id)
        assert retrieved is not None

    def test_store_session(self):
        """Test storing a session."""
        session = CollaborationSession(
            workspace_id="ws-001",
            title="Test",
        )
        self.store.store_session(session)
        retrieved = self.store.get_session(session.session_id)
        assert retrieved is not None

    def test_get_active_sessions(self):
        """Test getting active sessions."""
        self.store.store_session(CollaborationSession(
            workspace_id="ws-001",
            title="Test",
        ))
        active = self.store.get_active_sessions()
        assert len(active) >= 1


class TestCollaborationService:
    """Tests for collaboration service."""

    def setup_method(self):
        """Set up test service."""
        reset_collaboration_store()
        self.service = CollaborationService()

    def test_create_workspace(self):
        """Test creating a workspace."""
        workspace = self.service.create_workspace(
            name="Test Workspace",
            description="Test",
            workspace_type=WorkspaceType.INVESTIGATION,
        )
        assert workspace.workspace_id is not None

    def test_add_member(self):
        """Test adding a member."""
        workspace = self.service.create_workspace(
            name="Test",
            description="Test",
            workspace_type=WorkspaceType.GENERAL,
        )
        updated = self.service.add_member(workspace.workspace_id, "new_member")
        assert "new_member" in updated.members

    def test_create_team(self):
        """Test creating a team."""
        team = self.service.create_team(
            name="Threat Intel Team",
            description="Threat intelligence specialists",
            specialties=["APT", "Malware"],
        )
        assert team.team_id is not None
        assert len(team.specialties) == 2

    def test_start_session(self):
        """Test starting a session."""
        workspace = self.service.create_workspace(
            name="Test",
            description="Test",
            workspace_type=WorkspaceType.GENERAL,
        )
        session = self.service.start_session(
            workspace_id=workspace.workspace_id,
            title="Investigation Session",
            participants=["analyst1", "analyst2"],
        )
        assert session is not None
        assert session.status == SessionStatus.ACTIVE

    def test_end_session(self):
        """Test ending a session."""
        workspace = self.service.create_workspace(
            name="Test",
            description="Test",
            workspace_type=WorkspaceType.GENERAL,
        )
        session = self.service.start_session(
            workspace_id=workspace.workspace_id,
            title="Test",
            participants=[],
        )
        ended = self.service.end_session(session.session_id)
        assert ended is not None
        assert ended.status == SessionStatus.ARCHIVED

    def test_send_message(self):
        """Test sending a message."""
        workspace = self.service.create_workspace(
            name="Test",
            description="Test",
            workspace_type=WorkspaceType.GENERAL,
        )
        message = self.service.send_message(
            workspace_id=workspace.workspace_id,
            sender="analyst@example.com",
            content="New finding",
        )
        assert message.message_id is not None

    def test_share_investigation(self):
        """Test sharing an investigation."""
        workspace = self.service.create_workspace(
            name="Test",
            description="Test",
            workspace_type=WorkspaceType.INVESTIGATION,
        )
        investigation = self.service.share_investigation(
            workspace_id=workspace.workspace_id,
            title="Fraud Case 2024-001",
            owner="analyst@example.com",
            shared_with=["manager@example.com"],
        )
        assert investigation.investigation_id is not None

    def test_get_metrics(self):
        """Test getting metrics."""
        self.service.create_workspace(
            name="Test",
            description="Test",
            workspace_type=WorkspaceType.GENERAL,
        )
        metrics = self.service.get_metrics()
        assert metrics.total_workspaces >= 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
