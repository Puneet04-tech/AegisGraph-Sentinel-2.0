"""
Unit tests for collaboration data models in src/collaboration/models.py
"""

import pytest
from datetime import datetime, timezone

from src.collaboration.models import (
    Workspace,
    WorkspaceType,
    Team,
    CollaborationSession,
    SessionStatus,
)


class TestWorkspace:
    """Tests for Workspace Pydantic model."""

    def test_create_with_required_fields(self):
        """Workspace can be created with just required fields."""
        ws = Workspace(
            name="Test Workspace",
            description="A test workspace",
            workspace_type=WorkspaceType.INVESTIGATION,
        )
        assert ws.name == "Test Workspace"
        assert ws.workspace_type == WorkspaceType.INVESTIGATION
        assert isinstance(ws.workspace_id, str)
        assert ws.members == []
        assert ws.tags == []

    def test_model_dump_returns_dict(self):
        """model_dump returns a serializable dict."""
        ws = Workspace(
            name="Test",
            description="Desc",
            workspace_type=WorkspaceType.COMPLIANCE,
            owner="admin",
            members=["user-1", "user-2"],
        )
        data = ws.model_dump()
        assert isinstance(data, dict)
        assert data["name"] == "Test"
        assert data["workspace_type"] == "COMPLIANCE"
        assert data["members"] == ["user-1", "user-2"]

    def test_workspace_type_enum_values(self):
        """All expected WorkspaceType values are present."""
        values = {e.value for e in WorkspaceType}
        assert "INVESTIGATION" in values
        assert "THREAT_INTEL" in values
        assert "FRAUD" in values
        assert "COMPLIANCE" in values
        assert "GENERAL" in values


class TestTeam:
    """Tests for Team Pydantic model."""

    def test_create_with_required_fields(self):
        """Team can be created with just required fields."""
        team = Team(
            name="Red Team",
            description="Red team operations",
        )
        assert team.name == "Red Team"
        assert isinstance(team.team_id, str)
        assert team.members == []
        assert team.specialties == []

    def test_model_dump(self):
        """Team model_dump returns expected structure."""
        team = Team(
            name="Blue Team",
            description="Blue team ops",
            team_lead="lead-1",
            members=["member-1", "member-2"],
            specialties=["SIEM", "Threat Intel"],
        )
        data = team.model_dump()
        assert data["name"] == "Blue Team"
        assert data["team_lead"] == "lead-1"
        assert data["specialties"] == ["SIEM", "Threat Intel"]


class TestCollaborationSession:
    """Tests for CollaborationSession Pydantic model."""

    def test_create_with_required_fields(self):
        """CollaborationSession can be created with required fields."""
        session = CollaborationSession(
            workspace_id="ws-123",
            title="Q3 Threat Review",
        )
        assert session.workspace_id == "ws-123"
        assert session.title == "Q3 Threat Review"
        assert session.status == SessionStatus.ACTIVE
        assert session.participants == []
        assert session.ended_at is None

    def test_model_dump(self):
        """CollaborationSession serializes correctly."""
        session = CollaborationSession(
            workspace_id="ws-456",
            title="Incident Review",
            status=SessionStatus.ARCHIVED,
            participants=["analyst-1", "analyst-2"],
        )
        data = session.model_dump()
        assert data["workspace_id"] == "ws-456"
        assert data["status"] == "ARCHIVED"
        assert data["participants"] == ["analyst-1", "analyst-2"]

    def test_session_status_enum_values(self):
        """SessionStatus has ACTIVE and ARCHIVED values."""
        values = {e.value for e in SessionStatus}
        assert "ACTIVE" in values
        assert "ARCHIVED" in values
