"""
Tests for Threat Intelligence Marketplace
"""

import pytest

from src.threat_marketplace.models import (
    ThreatFeed,
    FeedSubscription,
    Dataset,
    FeedQuality,
    GovernancePolicy,
    FeedType,
    FeedStatus,
    SubscriptionTier,
    AccessLevel,
)
from src.threat_marketplace.store import get_marketplace_store, reset_marketplace_store
from src.threat_marketplace.service import MarketplaceService


class TestMarketplaceModels:
    """Tests for marketplace models."""

    def test_create_threat_feed(self):
        """Test creating a threat feed."""
        feed = ThreatFeed(
            name="Malware IOC Feed",
            description="Daily malware indicators",
            feed_type=FeedType.MALWARE,
            provider="Security Vendor",
            provider_id="vendor-001",
        )
        assert feed.name == "Malware IOC Feed"
        assert feed.status == FeedStatus.ACTIVE

    def test_create_subscription(self):
        """Test creating a subscription."""
        sub = FeedSubscription(
            feed_id="feed-001",
            subscriber_id="user-001",
            tier=SubscriptionTier.PREMIUM,
        )
        assert sub.tier == SubscriptionTier.PREMIUM
        assert sub.status == "ACTIVE"

    def test_create_dataset(self):
        """Test creating a dataset."""
        dataset = Dataset(
            name="APT Campaign Dataset",
            description="Historical APT data",
            provider="Research Team",
            provider_id="research-001",
        )
        assert dataset.name == "APT Campaign Dataset"
        assert dataset.access_level == AccessLevel.SUBSCRIBED

    def test_create_feed_quality(self):
        """Test creating feed quality metrics."""
        quality = FeedQuality(
            feed_id="feed-001",
            accuracy_score=0.9,
            freshness_score=0.8,
            coverage_score=0.85,
            reliability_score=0.9,
        )
        assert quality.accuracy_score == 0.9

    def test_create_governance_policy(self):
        """Test creating a governance policy."""
        policy = GovernancePolicy(
            name="Data Privacy Policy",
            description="Data sharing rules",
            policy_type="PRIVACY",
            rules=[{"rule": "no_pii"}],
        )
        assert policy.name == "Data Privacy Policy"


class TestMarketplaceStore:
    """Tests for marketplace store."""

    def setup_method(self):
        """Set up test store."""
        reset_marketplace_store()
        self.store = get_marketplace_store()

    def test_store_feed(self):
        """Test storing a feed."""
        feed = ThreatFeed(
            name="Test Feed",
            description="Test",
            feed_type=FeedType.IP_REPUTATION,
            provider="Test",
            provider_id="test-001",
        )
        self.store.store_feed(feed)
        retrieved = self.store.get_feed(feed.feed_id)
        assert retrieved is not None
        assert retrieved.name == "Test Feed"

    def test_get_feeds_by_type(self):
        """Test getting feeds by type."""
        self.store.store_feed(ThreatFeed(
            name="IP Feed",
            description="Test",
            feed_type=FeedType.IP_REPUTATION,
            provider="Test",
            provider_id="test-001",
        ))
        results = self.store.get_feeds_by_type(FeedType.IP_REPUTATION)
        assert len(results) >= 1

    def test_subscribe_to_feed(self):
        """Test subscribing to a feed."""
        sub = FeedSubscription(
            feed_id="feed-001",
            subscriber_id="user-001",
        )
        self.store.subscribe_to_feed(sub)
        subs = self.store.get_subscriptions_by_subscriber("user-001")
        assert len(subs) >= 1

    def test_store_dataset(self):
        """Test storing a dataset."""
        dataset = Dataset(
            name="Test Dataset",
            description="Test",
            provider="Test",
            provider_id="test-001",
        )
        self.store.store_dataset(dataset)
        retrieved = self.store.get_dataset(dataset.dataset_id)
        assert retrieved is not None

    def test_store_quality(self):
        """Test storing quality metrics."""
        quality = FeedQuality(
            feed_id="feed-001",
            accuracy_score=0.9,
            freshness_score=0.8,
            coverage_score=0.85,
            reliability_score=0.9,
        )
        self.store.store_quality(quality)
        retrieved = self.store.get_quality("feed-001")
        assert retrieved is not None
        assert retrieved.accuracy_score == 0.9

    def test_get_metrics(self):
        """Test getting metrics."""
        self.store.store_feed(ThreatFeed(
            name="Test",
            description="Test",
            feed_type=FeedType.MALWARE,
            provider="Test",
            provider_id="test-001",
        ))
        metrics = self.store.get_metrics()
        assert metrics.total_feeds >= 1


class TestMarketplaceService:
    """Tests for marketplace service."""

    def setup_method(self):
        """Set up test service."""
        reset_marketplace_store()
        self.service = MarketplaceService()

    def test_publish_feed(self):
        """Test publishing a feed."""
        feed = self.service.publish_feed(
            name="New Feed",
            description="A new threat feed",
            feed_type=FeedType.MALWARE,
            provider="Security Team",
            provider_id="sec-001",
        )
        assert feed.feed_id is not None
        assert feed.status == FeedStatus.ACTIVE

    def test_get_feed(self):
        """Test getting a feed."""
        published = self.service.publish_feed(
            name="Test Feed",
            description="Test",
            feed_type=FeedType.VULNERABILITY,
            provider="Test",
            provider_id="test-001",
        )
        retrieved = self.service.get_feed(published.feed_id)
        assert retrieved is not None
        assert retrieved.name == "Test Feed"

    def test_subscribe_to_feed(self):
        """Test subscribing to a feed."""
        feed = self.service.publish_feed(
            name="Premium Feed",
            description="Test",
            feed_type=FeedType.DOMAIN_REPUTATION,
            provider="Test",
            provider_id="test-001",
        )
        sub = self.service.subscribe_to_feed(
            feed_id=feed.feed_id,
            subscriber_id="user-001",
            tier=SubscriptionTier.PREMIUM,
        )
        assert sub.tier == SubscriptionTier.PREMIUM

    def test_publish_dataset(self):
        """Test publishing a dataset."""
        dataset = self.service.publish_dataset(
            name="Threat Dataset",
            description="Test dataset",
            provider="Research",
            provider_id="res-001",
            price_usd=99.99,
        )
        assert dataset.price_usd == 99.99

    def test_rate_feed(self):
        """Test rating a feed."""
        feed = self.service.publish_feed(
            name="Rated Feed",
            description="Test",
            feed_type=FeedType.FILE_HASH,
            provider="Test",
            provider_id="test-001",
        )
        quality = self.service.rate_feed(
            feed_id=feed.feed_id,
            accuracy=0.95,
            freshness=0.9,
            coverage=0.85,
            reliability=0.92,
        )
        assert quality.overall_score > 0.9

    def test_search_feeds(self):
        """Test searching feeds."""
        self.service.publish_feed(
            name="Malware Indicators",
            description="Daily malware IOCs",
            feed_type=FeedType.MALWARE,
            provider="Test",
            provider_id="test-001",
            tags=["malware", "ioc"],
        )
        results = self.service.search_feeds(
            query="malware",
            tags=["malware"],
        )
        assert len(results) >= 1

    def test_get_top_rated_feeds(self):
        """Test getting top-rated feeds."""
        feed1 = self.service.publish_feed(
            name="Top Feed",
            description="Test",
            feed_type=FeedType.MALWARE,
            provider="Test",
            provider_id="test-001",
        )
        self.service.rate_feed(
            feed_id=feed1.feed_id,
            accuracy=0.95,
            freshness=0.9,
            coverage=0.85,
            reliability=0.92,
        )
        top = self.service.get_top_rated_feeds(limit=5)
        assert len(top) >= 1


class TestMarketplaceIntegration:
    """Integration tests for marketplace."""

    def setup_method(self):
        """Set up test environment."""
        reset_marketplace_store()
        self.service = MarketplaceService()

    def test_full_publishing_lifecycle(self):
        """Test complete publishing lifecycle."""
        feed = self.service.publish_feed(
            name="Integration Test Feed",
            description="Testing full lifecycle",
            feed_type=FeedType.CAMPAIGN,
            provider="Test Provider",
            provider_id="test-001",
            tags=["test", "integration"],
        )

        sub = self.service.subscribe_to_feed(
            feed_id=feed.feed_id,
            subscriber_id="user-001",
            tier=SubscriptionTier.ENTERPRISE,
        )
        assert sub.subscription_id

        quality = self.service.rate_feed(
            feed_id=feed.feed_id,
            accuracy=0.9,
            freshness=0.85,
            coverage=0.88,
            reliability=0.9,
        )
        assert quality.overall_score

        metrics = self.service.get_metrics()
        assert metrics.total_feeds >= 1
        assert metrics.total_subscribers >= 1

        self.service.create_governance_policy(
            name="Test Policy",
            description="Policy for testing",
            policy_type="COMPLIANCE",
            rules=[{"rule": "test_rule"}],
        )

        policies = self.service.get_governance_policies()
        assert len(policies) >= 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
