"""Tests for Intelligence Marketplace Module"""
import pytest
from src.intelligence_marketplace import MarketplaceService

def test_service_init():
    """Test service initialization"""
    service = MarketplaceService()
    assert service is not None
    assert service.catalog is not None

def test_publish_asset():
    """Test publishing an asset"""
    service = MarketplaceService()
    asset = service.publish_asset(
        name="Fraud Detection Model v2",
        description="Advanced fraud detection ML model",
        asset_type="FRAUD_DETECTOR",
        publisher_id="aegisgraph",
        version="2.0.0",
        tags=["fraud", "ml", "detection"]
    )
    assert asset is not None
    assert asset["name"] == "Fraud Detection Model v2"
    assert asset["status"] == "PUBLISHED"
    assert asset["downloads"] == 0

def test_get_asset():
    """Test getting an asset"""
    service = MarketplaceService()
    published = service.publish_asset(
        name="Threat Feed Pro",
        description="Premium threat intelligence feed",
        asset_type="THREAT_FEED",
        publisher_id="aegisgraph",
        version="1.0.0",
        tags=["threat", "intelligence"]
    )
    
    retrieved = service.get_asset(published["asset_id"])
    assert retrieved is not None
    assert retrieved["name"] == "Threat Feed Pro"

def test_search_assets():
    """Test searching assets"""
    service = MarketplaceService()
    service.publish_asset(
        name="AI Model X",
        description="AI security model",
        asset_type="AI_MODEL",
        publisher_id="aegisgraph",
        version="1.0.0",
        tags=["ai", "security"]
    )
    
    results = service.search_assets(query="AI")
    assert len(results) > 0

def test_search_by_type():
    """Test searching by asset type"""
    service = MarketplaceService()
    service.publish_asset(
        name="Fraud Model",
        description="Fraud detection",
        asset_type="FRAUD_DETECTOR",
        publisher_id="aegisgraph",
        version="1.0.0",
        tags=["fraud"]
    )
    
    results = service.search_assets(asset_type="FRAUD_DETECTOR")
    assert all(r["asset_type"] == "FRAUD_DETECTOR" for r in results)

def test_subscribe():
    """Test subscribing to an asset"""
    service = MarketplaceService()
    asset = service.publish_asset(
        name="Compliance Policy Pack",
        description="Ready-to-use compliance policies",
        asset_type="COMPLIANCE_POLICY",
        publisher_id="aegisgraph",
        version="1.0.0",
        tags=["compliance"]
    )
    
    subscription = service.subscribe(
        asset_id=asset["asset_id"],
        subscriber_id="user123",
        duration_days=30
    )
    assert subscription is not None
    assert subscription["status"] == "ACTIVE"
    assert subscription["subscriber_id"] == "user123"

def test_get_user_subscriptions():
    """Test getting user subscriptions"""
    service = MarketplaceService()
    asset = service.publish_asset(
        name="Test Asset",
        description="Test",
        asset_type="AI_MODEL",
        publisher_id="aegisgraph",
        version="1.0.0",
        tags=["test"]
    )
    
    service.subscribe(asset["asset_id"], "user456", duration_days=30)
    subs = service.get_user_subscriptions("user456")
    assert len(subs) >= 1

def test_get_catalog_stats():
    """Test catalog statistics"""
    service = MarketplaceService()
    service.publish_asset(
        name="Asset 1",
        description="Test",
        asset_type="AI_MODEL",
        publisher_id="aegisgraph",
        version="1.0.0",
        tags=["test"]
    )
    service.publish_asset(
        name="Asset 2",
        description="Test",
        asset_type="THREAT_FEED",
        publisher_id="aegisgraph",
        version="1.0.0",
        tags=["test"]
    )
    
    stats = service.get_catalog_stats()
    assert stats["total_assets"] >= 2
    assert "by_type" in stats
    assert "total_publishers" in stats