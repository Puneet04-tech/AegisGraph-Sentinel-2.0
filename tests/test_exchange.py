"""Tests for Security Exchange Module"""
import pytest
from src.security_exchange import SecurityExchangeService

def test_service_init():
    """Test service initialization"""
    service = SecurityExchangeService()
    assert service is not None
    assert service.federation is not None

def test_add_partner():
    """Test adding a partner"""
    service = SecurityExchangeService()
    partner = service.add_partner(
        name="Test Bank",
        organization_type="FINANCIAL_INSTITUTION",
        country="US",
        trust_score=0.75
    )
    assert partner is not None
    assert partner["name"] == "Test Bank"
    assert partner["verified"] is False

def test_get_partner():
    """Test getting a partner"""
    service = SecurityExchangeService()
    partner = service.add_partner(
        name="Test Corp",
        organization_type="ENTERPRISE",
        country="UK"
    )
    
    retrieved = service.get_partner(partner["partner_id"])
    assert retrieved is not None
    assert retrieved["name"] == "Test Corp"

def test_get_all_partners():
    """Test getting all partners"""
    service = SecurityExchangeService()
    partners = service.get_all_partners()
    assert len(partners) > 0
    assert partners[0]["partner_id"] is not None

def test_share_intelligence():
    """Test sharing intelligence"""
    service = SecurityExchangeService()
    
    # Add a verified partner
    service.add_partner(
        name="Sharing Partner",
        organization_type="GOVERNMENT",
        country="US",
        trust_score=0.9
    )
    
    # Get existing verified partners
    partners = service.get_all_partners()
    verified_partners = [p for p in partners if p.get("verified", False)][:1]
    
    if verified_partners:
        share = service.share_intelligence(
            title="APT Threat Intelligence",
            description="New APT group targeting financial sector",
            intelligence_type="APT",
            from_partner=verified_partners[0]["partner_id"],
            to_partners=["partner-isac"],
            classification="CONFIDENTIAL",
            threat_indicators=["IOC1", "IOC2", "IOC3"]
        )
        assert share is not None
        assert share["title"] == "APT Threat Intelligence"

def test_search_intelligence():
    """Test searching intelligence"""
    service = SecurityExchangeService()
    results = service.search_intelligence(query="threat")
    assert isinstance(results, list)

def test_get_federation_stats():
    """Test federation statistics"""
    service = SecurityExchangeService()
    stats = service.get_federation_stats()
    assert stats is not None
    assert "total_partners" in stats
    assert "total_shares" in stats
    assert stats["total_partners"] >= 3

def test_exchange_dashboard():
    """Test exchange dashboard"""
    service = SecurityExchangeService()
    dashboard = service.get_exchange_dashboard()
    assert "federation_stats" in dashboard
    assert "recent_shares" in dashboard
    assert "total_intelligence_shared" in dashboard