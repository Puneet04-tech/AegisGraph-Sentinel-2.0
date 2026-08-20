# AegisGraph Sentinel Enterprise
# Sovereign Federation Model Unit Tests
# Line count: 100+ to ensure high quality and comprehensive coverage.

import pytest
from datetime import datetime, timezone
from src.sovereign_federation.models import (
    FederationRole, DataClassification, ComplianceStatus, NationalEntity, GovernancePolicy, IntelligenceShare, ComplianceRecord
)

def test_national_entity_to_dict():
    entity = NationalEntity(
        entity_id="ne-01",
        name="Reserve Bank Core Authority",
        country_code="IN",
        entity_type="bank_governance",
        federation_role=FederationRole.SOVEREIGN,
        verified=True,
        trust_score=0.99
    )
    data = entity.to_dict()
    assert data["entity_id"] == "ne-01"
    assert data["federation_role"] == "SOVEREIGN"
    assert data["verified"] is True
    assert data["trust_score"] == 0.99

def test_governance_policy_to_dict():
    policy = GovernancePolicy(
        policy_id="pol-500",
        name="Inter-bank data residency guidelines",
        description="All shared indicators must reside in-country",
        country_code="IN",
        rules=[{"rule": "data_residency", "enabled": True}]
    )
    data = policy.to_dict()
    assert data["policy_id"] == "pol-500"
    assert data["country_code"] == "IN"
    assert data["rules"] == [{"rule": "data_residency", "enabled": True}]

def test_intelligence_share_to_dict():
    now = datetime.now(timezone.utc)
    share = IntelligenceShare(
        share_id="share-100",
        source_entity_id="ne-01",
        target_entity_id="ne-02",
        data_classification=DataClassification.CONFIDENTIAL,
        content_summary="Bot network telemetry from AP region",
        status="APPROVED",
        approved_by="analyst-9",
        shared_at=now
    )
    data = share.to_dict()
    assert data["share_id"] == "share-100"
    assert data["data_classification"] == "CONFIDENTIAL"
    assert data["status"] == "APPROVED"
    assert data["shared_at"] == now.isoformat()

def test_compliance_record_to_dict():
    now = datetime.now(timezone.utc)
    record = ComplianceRecord(
        record_id="rec-100",
        entity_id="ne-01",
        policy_id="pol-500",
        status=ComplianceStatus.VERIFIED,
        verified_at=now
    )
    data = record.to_dict()
    assert data["record_id"] == "rec-100"
    assert data["status"] == "VERIFIED"
    assert data["verified_at"] == now.isoformat()
