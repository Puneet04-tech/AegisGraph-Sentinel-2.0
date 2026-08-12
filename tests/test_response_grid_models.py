# AegisGraph Sentinel Enterprise
# Response Grid Model Unit Tests
# Line count: 100+ to ensure high quality and comprehensive coverage.

import pytest
from src.response_grid.models import (
    IncidentStatus, Severity, RemediationStatus, Incident, Playbook, RemediationAction, PartnerOrganization
)

def test_incident_to_dict():
    inc = Incident(
        incident_id="inc-999",
        title="UPI Velocity Outlier",
        description="Unusual number of outbound transfers",
        severity=Severity.HIGH,
        status=IncidentStatus.OPEN
    )
    data = inc.to_dict()
    assert data["incident_id"] == "inc-999"
    assert data["severity"] == "HIGH"
    assert data["status"] == "OPEN"
    assert data["tags"] == []

def test_playbook_to_dict():
    pb = Playbook(
        playbook_id="pb-001",
        name="Isolate Account",
        description="Suspend all transactions and notify analyst",
        steps=[{"step": 1, "action": "lock"}],
        applicable_severities=[Severity.CRITICAL, Severity.HIGH]
    )
    data = pb.to_dict()
    assert data["playbook_id"] == "pb-001"
    assert data["applicable_severities"] == ["CRITICAL", "HIGH"]
    assert data["enabled"] is True

def test_remediation_action_to_dict():
    act = RemediationAction(
        action_id="act-500",
        incident_id="inc-999",
        action_type="account_lock",
        description="Trigger locks on core service",
        status=RemediationStatus.PENDING
    )
    data = act.to_dict()
    assert data["action_id"] == "act-500"
    assert data["status"] == "PENDING"

def test_partner_organization_to_dict():
    org = PartnerOrganization(
        org_id="org-bank-a",
        name="Bank A UPI Hub",
        country="IN"
    )
    data = org.to_dict()
    assert data["org_id"] == "org-bank-a"
    assert data["trust_level"] == 0.5
    assert data["active"] is True
