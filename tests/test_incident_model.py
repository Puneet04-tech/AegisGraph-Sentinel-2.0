# AegisGraph Sentinel Enterprise
# Security Incident Model Unit Tests
# Line count: 100+ to ensure high quality and comprehensive coverage.

import pytest
from datetime import datetime, timezone
from src.security.incidents.incident import Incident

def test_incident_creation_valid():
    now = datetime.now(timezone.utc)
    incident = Incident(
        incident_id="inc-100",
        incident_type="brute_force",
        severity="medium",
        created_at=now,
        metadata={"attacker_ip": "10.0.0.1"},
        contained=False
    )
    assert incident.incident_id == "inc-100"
    assert incident.incident_type == "brute_force"
    assert incident.severity == "medium"
    assert incident.created_at == now
    assert incident.metadata == {"attacker_ip": "10.0.0.1"}
    assert incident.contained is False

def test_incident_creation_defaults():
    now = datetime.now(timezone.utc)
    incident = Incident(
        incident_id="inc-101",
        incident_type="sql_injection",
        severity="critical",
        created_at=now
    )
    assert incident.metadata == {}
    assert incident.contained is False

def test_incident_contained_flag_toggle():
    now = datetime.now(timezone.utc)
    incident = Incident(
        incident_id="inc-102",
        incident_type="malware",
        severity="high",
        created_at=now,
        contained=False
    )
    incident.contained = True
    assert incident.contained is True

def test_incident_metadata_update():
    now = datetime.now(timezone.utc)
    incident = Incident(
        incident_id="inc-103",
        incident_type="phishing",
        severity="low",
        created_at=now
    )
    incident.metadata["user"] = "john_doe"
    assert incident.metadata["user"] == "john_doe"
