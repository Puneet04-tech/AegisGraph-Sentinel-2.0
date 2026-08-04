"""Unit tests for the security exchange federation layer.

Covers ``src.security_exchange``: ``FederationLayer`` and the
``ExchangePartner`` / ``SharedIntelligence`` / ``DataGovernanceRule`` models.
"""

from __future__ import annotations

import pytest

from src.security_exchange.federation import FederationLayer
from src.security_exchange.models import (
    DataClassification,
    DataGovernanceRule,
    ExchangePartner,
    OrganizationType,
    ShareStatus,
    SharedIntelligence,
)


@pytest.fixture
def federation() -> FederationLayer:
    return FederationLayer()


def _partner(
    partner_id="p1",
    name="Partner One",
    org_type=OrganizationType.SECURITY_PROVIDER,
    country="US",
    verified=True,
    trust_score=0.9,
) -> ExchangePartner:
    return ExchangePartner(
        partner_id=partner_id,
        name=name,
        organization_type=org_type,
        country=country,
        verified=verified,
        trust_score=trust_score,
    )


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class TestModels:
    def test_enum_values(self):
        assert OrganizationType.GOVERNMENT.value == "GOVERNMENT"
        assert DataClassification.RESTRICTED.value == "RESTRICTED"
        assert ShareStatus.APPROVED.value == "APPROVED"

    def test_partner_to_dict(self):
        partner = _partner(trust_score=0.95)
        data = partner.to_dict()
        assert data["organization_type"] == "SECURITY_PROVIDER"
        assert data["verified"] is True
        assert data["trust_score"] == 0.95
        assert data["data_classification"] == "INTERNAL"

    def test_shared_intelligence_to_dict(self):
        share = SharedIntelligence(
            share_id="s1", title="t", description="d", intelligence_type="THREAT",
            from_partner="p1", to_partners=["p2"],
            classification=DataClassification.CONFIDENTIAL,
            status=ShareStatus.APPROVED, threat_indicators=["i1"],
        )
        data = share.to_dict()
        assert data["classification"] == "CONFIDENTIAL"
        assert data["status"] == "APPROVED"
        assert data["expires_at"] is None

    def test_governance_rule_to_dict(self):
        rule = DataGovernanceRule(
            rule_id="r1", name="n", description="d",
            classification_required=DataClassification.RESTRICTED,
            partners_allowed=["p1"], retention_days=90,
        )
        data = rule.to_dict()
        assert data["classification_required"] == "RESTRICTED"
        assert data["retention_days"] == 90


# ---------------------------------------------------------------------------
# FederationLayer
# ---------------------------------------------------------------------------


class TestFederationLayer:
    def test_sample_partners_initialized(self, federation):
        assert len(federation.partners) == 3
        assert federation.get_partner("partner-fbi") is not None

    def test_add_and_get_partner(self, federation):
        partner = _partner()

        assert federation.add_partner(partner) == "p1"
        assert federation.get_partner("p1") is partner
        assert federation.get_partner("missing") is None

    def test_partners_by_type_and_country(self, federation):
        federation.add_partner(_partner(partner_id="p1", org_type=OrganizationType.ENTERPRISE, country="US"))
        federation.add_partner(_partner(partner_id="p2", org_type=OrganizationType.GOVERNMENT, country="UK"))

        assert len(federation.get_partners_by_type(OrganizationType.ENTERPRISE)) == 2  # sample ISAC is also ENTERPRISE
        assert len(federation.get_partners_by_country("UK")) == 1
        assert len(federation.get_partners_by_country("XX")) == 0

    def test_share_intelligence_valid(self, federation):
        federation.add_partner(_partner(partner_id="p1"))
        federation.add_partner(_partner(partner_id="p2"))

        share = federation.share_intelligence(
            "Ransomware campaign", "New ransomware wave", "THREAT",
            "p1", ["p2"], "CONFIDENTIAL", ["ip:1.2.3.4"], expires_in_days=30,
        )

        assert share is not None
        assert share.status == ShareStatus.APPROVED
        assert share.classification == DataClassification.CONFIDENTIAL
        assert share.from_partner == "p1"
        assert share.to_partners == ["p2"]
        assert federation.shares[share.share_id] is share

    def test_share_rejects_unknown_sender(self, federation):
        assert federation.share_intelligence(
            "t", "d", "THREAT", "unknown", ["p2"], "PUBLIC", []) is None

    def test_share_rejects_unknown_recipient(self, federation):
        federation.add_partner(_partner(partner_id="p1"))
        assert federation.share_intelligence(
            "t", "d", "THREAT", "p1", ["unknown"], "PUBLIC", []) is None

    def test_share_rejects_unverified_partner(self, federation):
        federation.add_partner(_partner(partner_id="p1"))
        federation.add_partner(_partner(partner_id="p2", verified=False))

        assert federation.share_intelligence(
            "t", "d", "THREAT", "p1", ["p2"], "PUBLIC", []) is None

    def test_check_governance_gating(self, federation):
        federation.add_partner(_partner(partner_id="p1"))
        federation.add_partner(_partner(partner_id="p2", verified=False))

        assert federation._check_governance("PUBLIC", "p1", ["p2"]) is False
        assert federation._check_governance("PUBLIC", "missing", ["p2"]) is False

    def test_search_intelligence_filters(self, federation):
        federation.add_partner(_partner(partner_id="p1"))
        federation.add_partner(_partner(partner_id="p2"))
        federation.add_partner(_partner(partner_id="p3"))

        federation.share_intelligence("Phishing alert", "Phishing campaign", "PHISHING", "p1", ["p2"], "CONFIDENTIAL", ["url:x"], expires_in_days=30)
        federation.share_intelligence("Malware alert", "Malware campaign", "MALWARE", "p1", ["p3"], "INTERNAL", ["hash:y"], expires_in_days=30)
        federation.share_intelligence("Phishing digest", "Daily phishing digest", "PHISHING", "p2", ["p1"], "CONFIDENTIAL", [], expires_in_days=30)

        assert len(federation.search_intelligence()) == 3
        assert len(federation.search_intelligence(query="phishing")) == 2
        assert len(federation.search_intelligence(intelligence_type="MALWARE")) == 1
        assert len(federation.search_intelligence(from_partner="p2")) == 1
        assert len(federation.search_intelligence(classification="INTERNAL")) == 1

    def test_search_excludes_expired(self, federation):
        federation.add_partner(_partner(partner_id="p1"))
        federation.add_partner(_partner(partner_id="p2"))
        expired = federation.share_intelligence("Old", "Old alert", "THREAT", "p1", ["p2"], "PUBLIC", [], expires_in_days=30)
        expired.status = ShareStatus.EXPIRED

        assert len(federation.search_intelligence()) == 0

    def test_federation_stats(self, federation):
        assert federation.get_federation_stats()["total_partners"] == 3
        stats = federation.get_federation_stats()
        assert stats["verified_partners"] == 3
        assert stats["by_country"]["US"] >= 2
        assert stats["by_organization_type"]["GOVERNMENT"] == 2
