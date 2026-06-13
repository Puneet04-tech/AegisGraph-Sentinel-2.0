"""Tests for Advanced Forensics & Investigation"""
import pytest
from src.forensics.models import Investigation, Evidence
from src.forensics.store import get_forensics_store
from src.forensics.service import ForensicsService


class TestForensicsModels:
    def test_create_investigation(self):
        inv = Investigation(title="Test Case", description="Test description")
        assert inv.title == "Test Case"

    def test_create_evidence(self):
        ev = Evidence(investigation_id="test-id", evidence_type="file", content={"path": "/tmp/test"})
        assert ev.evidence_type == "file"


class TestForensicsStore:
    def setup_method(self):
        self.store = get_forensics_store()

    def test_store_investigation(self):
        inv = Investigation(title="Test", description="Test")
        self.store.store_investigation(inv)
        assert self.store.get_investigation(inv.investigation_id) is not None


class TestForensicsService:
    def setup_method(self):
        self.service = ForensicsService()

    def test_create_investigation(self):
        inv = self.service.create_investigation("Case 1", "Description")
        assert inv.investigation_id is not None

    def test_add_evidence(self):
        inv = self.service.create_investigation("Case 1", "Description")
        ev = self.service.add_evidence(inv.investigation_id, "log", {"data": "test"})
        assert ev.evidence_id is not None

    def test_get_metrics(self):
        self.service.create_investigation("Case 1", "Description")
        m = self.service.get_metrics()
        assert m.total_investigations >= 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
