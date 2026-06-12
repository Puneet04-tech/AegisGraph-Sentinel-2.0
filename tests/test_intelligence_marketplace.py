"""
Tests for Intelligence Marketplace Module
"""
import pytest
from datetime import datetime, timezone

from src.intelligence_marketplace import (
    MarketplaceEngine,
    get_marketplace_engine,
    ListingManager,
    SubscriptionManager,
    DatasetRegistry,
    ThreatFeedExchange,
    MarketplaceListing,
    ListingType,
    ListingStatus,
    SubscriptionTier,
)


class TestListingManager:
    """Tests for ListingManager."""
    
    def setup_method(self):
        self.manager = ListingManager()
    
    def test_initialization(self):
        """Test manager initialization."""
        assert len(self.manager.listings) > 0
    
    def test_create_listing(self):
        """Test creating a listing."""
        listing_id = self.manager.create_listing(
            name="Test Listing",
            description="Test description",
            listing_type=ListingType.DATASET,
            publisher_id="test-user",
            tags=["test"],
        )
        
        assert listing_id is not None
        assert self.manager.get_listing(listing_id) is not None
    
    def test_get_listing(self):
        """Test getting a listing."""
        listing = self.manager.get_listing("list-001")
        assert listing is not None
        assert listing.name == "Global Fraud Indicators"
    
    def test_update_listing(self):
        """Test updating a listing."""
        listing_id = self.manager.create_listing(
            name="Update Test",
            description="Test",
            listing_type=ListingType.THREAT_FEED,
            publisher_id="test",
        )
        
        success = self.manager.update_listing(listing_id, ListingStatus.PUBLISHED)
        assert success is True
        
        listing = self.manager.get_listing(listing_id)
        assert listing.status == ListingStatus.PUBLISHED
    
    def test_search_listings(self):
        """Test searching listings."""
        self.manager.create_listing(
            name="Fraud Detection Dataset",
            description="Fraud training data",
            listing_type=ListingType.DATASET,
            publisher_id="test",
            tags=["fraud"],
        )
        
        results = self.manager.search_listings("fraud", tags=["fraud"])
        assert len(results) >= 1


class TestSubscriptionManager:
    """Tests for SubscriptionManager."""
    
    def setup_method(self):
        self.manager = SubscriptionManager()
    
    def test_subscribe(self):
        """Test subscribing."""
        sub_id = self.manager.subscribe(
            listing_id="list-001",
            subscriber_id="user-001",
            tier=SubscriptionTier.STANDARD,
        )
        
        assert sub_id is not None
        assert self.manager.get_subscription(sub_id) is not None
    
    def test_get_subscription(self):
        """Test getting a subscription."""
        sub_id = self.manager.subscribe(
            listing_id="list-001",
            subscriber_id="user-002",
        )
        
        sub = self.manager.get_subscription(sub_id)
        assert sub is not None
        assert sub.subscriber_id == "user-002"
    
    def test_cancel_subscription(self):
        """Test cancelling a subscription."""
        sub_id = self.manager.subscribe(
            listing_id="list-001",
            subscriber_id="user-004",
        )
        
        success = self.manager.cancel_subscription(sub_id)
        assert success is True
        
        sub = self.manager.get_subscription(sub_id)
        assert sub.status == "CANCELLED"


class TestDatasetRegistry:
    """Tests for DatasetRegistry."""
    
    def setup_method(self):
        self.registry = DatasetRegistry()
    
    def test_initialization(self):
        """Test registry initialization."""
        assert len(self.registry.datasets) > 0
    
    def test_register_dataset(self):
        """Test registering a dataset."""
        ds_id = self.registry.register_dataset(
            listing_id="list-002",
            name="Test Dataset",
            size=10000,
            format="JSON",
            features=["f1", "f2"],
            labels=["l1", "l2"],
        )
        
        assert ds_id is not None
        assert self.registry.get_dataset(ds_id) is not None
    
    def test_get_dataset(self):
        """Test getting a dataset."""
        ds = self.registry.get_dataset("ds-001")
        assert ds is not None
        assert ds.name == "AML Training Data"


class TestThreatFeedExchange:
    """Tests for ThreatFeedExchange."""
    
    def setup_method(self):
        self.exchange = ThreatFeedExchange()
    
    def test_initialization(self):
        """Test exchange initialization."""
        assert len(self.exchange.feeds) > 0
    
    def test_publish_feed(self):
        """Test publishing a feed."""
        feed_id = self.exchange.publish_feed(
            listing_id="list-001",
            name="Test Feed",
            feed_type="INDICATORS",
            indicators=[{"type": "ip", "value": "1.2.3.4"}],
        )
        
        assert feed_id is not None
        assert self.exchange.get_feed(feed_id) is not None
    
    def test_get_feed_indicators(self):
        """Test getting feed indicators."""
        indicators = self.exchange.get_feed_indicators("feed-001")
        assert len(indicators) >= 1


class TestMarketplaceEngine:
    """Tests for MarketplaceEngine."""
    
    def setup_method(self):
        self.engine = MarketplaceEngine()
    
    def test_publish_listing(self):
        """Test publishing a listing."""
        listing_id = self.engine.publish_listing(
            name="Engine Test",
            description="Test",
            listing_type=ListingType.MODEL,
            publisher_id="test",
        )
        
        assert listing_id is not None
    
    def test_subscribe_to_listing(self):
        """Test subscribing to a listing."""
        listing_id = self.engine.listing_manager.create_listing(
            name="Subscribe Test",
            description="Test",
            listing_type=ListingType.THREAT_FEED,
            publisher_id="test",
        )
        
        sub_id = self.engine.subscribe_to_listing(
            listing_id=listing_id,
            subscriber_id="user-001",
        )
        
        assert sub_id is not None
    
    def test_get_dashboard(self):
        """Test getting dashboard."""
        dashboard = self.engine.get_dashboard()
        
        assert "total_listings" in dashboard
        assert "by_type" in dashboard


if __name__ == "__main__":
    pytest.main([__file__, "-v"])