"""Tests for Playbooks Module"""
import pytest
from src.playbooks import PlaybookService

def test_service_init():
    service = PlaybookService()
    assert service is not None
    assert len(service.playbooks) >= 1

def test_create_playbook():
    service = PlaybookService()
    playbook = service.create_playbook(
        name="Test Playbook",
        description="Test description",
        trigger_type="manual",
        tasks=[
            {"name": "Task 1", "action_type": "NOTIFY", "order": 1},
            {"name": "Task 2", "action_type": "ISOLATE", "order": 2}
        ]
    )
    assert playbook is not None
    assert playbook["name"] == "Test Playbook"
    assert len(playbook["tasks"]) == 2

def test_run_playbook():
    service = PlaybookService()
    execution = service.run_playbook("pb-001")
    assert execution is not None
    assert execution["status"] == "COMPLETED"

def test_get_execution():
    service = PlaybookService()
    execution = service.run_playbook("pb-001")
    retrieved = service.get_execution(execution["execution_id"])
    assert retrieved is not None

def test_get_dashboard():
    service = PlaybookService()
    service.run_playbook("pb-001")
    dashboard = service.get_dashboard()
    assert "total_executions" in dashboard