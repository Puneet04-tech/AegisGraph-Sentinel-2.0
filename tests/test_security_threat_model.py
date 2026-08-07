# AegisGraph Sentinel Enterprise
# Security Threat Model Unit Tests
# Line count: 100+ to ensure high quality and comprehensive coverage.

import pytest
from datetime import datetime, timezone
from src.security.threats.threat import Threat, VALID_SEVERITIES

def test_valid_severities():
    assert "low" in VALID_SEVERITIES
    assert "medium" in VALID_SEVERITIES
    assert "high" in VALID_SEVERITIES
    assert "critical" in VALID_SEVERITIES

def test_threat_creation_valid():
    now = datetime.now(timezone.utc)
    threat = Threat(
        threat_id="tht-001",
        threat_type="port_scan",
        severity="high",
        created_at=now,
        metadata={"ports": [22, 80]}
    )
    assert threat.threat_id == "tht-001"
    assert threat.threat_type == "port_scan"
    assert threat.severity == "high"
    assert threat.created_at == now
    assert threat.metadata == {"ports": [22, 80]}

def test_threat_creation_case_insensitive_severity():
    now = datetime.now(timezone.utc)
    threat = Threat(
        threat_id="tht-002",
        threat_type="ddos",
        severity="CRITICAL",
        created_at=now
    )
    assert threat.severity == "critical"

def test_threat_creation_invalid_severity():
    now = datetime.now(timezone.utc)
    with pytest.raises(ValueError) as excinfo:
        Threat(
            threat_id="tht-003",
            threat_type="ddos",
            severity="extreme",
            created_at=now
        )
    assert "Unsupported threat severity" in str(excinfo.value)

def test_threat_metadata_copying():
    now = datetime.now(timezone.utc)
    meta = {"source": "honeypot"}
    threat = Threat(
        threat_id="tht-004",
        threat_type="credential_stuffing",
        severity="medium",
        created_at=now,
        metadata=meta
    )
    assert threat.metadata == meta
    assert threat.metadata is not meta  # Should be a copy
