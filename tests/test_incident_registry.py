"""
Unit tests for IncidentRegistry in src/security/incidents/incident_registry.py
"""

import pytest
import threading
import time
from datetime import datetime, timezone

from src.security.incidents.incident_registry import IncidentRegistry


@pytest.fixture
def registry():
    return IncidentRegistry(max_incidents=100)


class TestIncidentRegistry:
    """Tests for IncidentRegistry."""

    def test_create_incident(self, registry):
        """create_incident creates and stores an incident."""
        incident = registry.create_incident(
            incident_type="intrusion",
            severity="HIGH",
            metadata={"ip": "1.2.3.4"},
        )
        assert incident.incident_type == "intrusion"
        assert incident.severity == "high"
        assert incident.metadata == {"ip": "1.2.3.4"}
        assert incident.contained is False
        assert isinstance(incident.incident_id, str)

    def test_severity_is_lowercased(self, registry):
        """Severity is lowercased on creation."""
        incident = registry.create_incident(
            incident_type="test",
            severity="CRITICAL",
        )
        assert incident.severity == "critical"

    def test_get_incident_found(self, registry):
        """get_incident returns the incident when it exists."""
        created = registry.create_incident(incident_type="phishing", severity="MEDIUM")
        retrieved = registry.get_incident(created.incident_id)
        assert retrieved is not None
        assert retrieved.incident_id == created.incident_id

    def test_get_incident_not_found(self, registry):
        """get_incident returns None when incident does not exist."""
        result = registry.get_incident("nonexistent-id")
        assert result is None

    def test_list_incidents(self, registry):
        """list_incidents returns all created incidents."""
        inc1 = registry.create_incident(incident_type="a", severity="LOW")
        inc2 = registry.create_incident(incident_type="b", severity="HIGH")
        all_incidents = registry.list_incidents()
        ids = {i.incident_id for i in all_incidents}
        assert inc1.incident_id in ids
        assert inc2.incident_id in ids

    def test_count_by_severity(self, registry):
        """count_by_severity returns correct counts."""
        registry.create_incident(incident_type="t1", severity="HIGH")
        registry.create_incident(incident_type="t2", severity="HIGH")
        registry.create_incident(incident_type="t3", severity="LOW")
        counts = registry.count_by_severity()
        assert counts.get("high") == 2
        assert counts.get("low") == 1

    def test_count_by_severity_empty(self, registry):
        """count_by_severity returns empty dict when no incidents."""
        counts = registry.count_by_severity()
        assert counts == {}

    def test_uuid_uniqueness(self, registry):
        """Each incident gets a unique UUID."""
        ids = set()
        for _ in range(100):
            inc = registry.create_incident(incident_type="test", severity="LOW")
            assert inc.incident_id not in ids
            ids.add(inc.incident_id)

    def test_contained_flag(self, registry):
        """contained flag is preserved on creation."""
        incident = registry.create_incident(
            incident_type="test",
            severity="MEDIUM",
            contained=True,
        )
        assert incident.contained is True

    def test_metadata_defaults_to_empty_dict(self, registry):
        """metadata defaults to empty dict when not provided."""
        incident = registry.create_incident(
            incident_type="test",
            severity="LOW",
        )
        assert incident.metadata == {}

    def test_thread_safety_list_incidents(self):
        """list_incidents is thread-safe under concurrent writes."""
        # Use a larger max_incidents to avoid deque eviction during the test
        reg = IncidentRegistry(max_incidents=500)
        written_ids = set()
        lock = threading.Lock()

        def writer(start, count):
            for i in range(count):
                inc = reg.create_incident(incident_type=f"type-{start+i}", severity="LOW")
                with lock:
                    written_ids.add(inc.incident_id)

        n = 50
        threads = [threading.Thread(target=writer, args=(i * n, n)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        all_incidents = reg.list_incidents()
        assert len(all_incidents) == n * 4
        stored_ids = {i.incident_id for i in all_incidents}
        assert stored_ids == written_ids

    def test_max_incidents_eviction(self):
        """Registry evicts oldest incidents when max is reached."""
        reg = IncidentRegistry(max_incidents=5)
        for i in range(10):
            reg.create_incident(incident_type=f"type-{i}", severity="LOW")
        assert len(reg.list_incidents()) == 5

    def test_max_incidents_eviction_order(self):
        """Oldest incidents are evicted first (FIFO within maxlen)."""
        reg = IncidentRegistry(max_incidents=3)
        reg.create_incident(incident_type="first", severity="LOW")
        reg.create_incident(incident_type="second", severity="LOW")
        reg.create_incident(incident_type="third", severity="LOW")
        reg.create_incident(incident_type="fourth", severity="LOW")

        ids = [i.incident_type for i in reg.list_incidents()]
        assert "first" not in ids
        assert "fourth" in ids
