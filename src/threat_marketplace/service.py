"""
Threat Intelligence Marketplace Service - Core business logic
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .models import (
    ThreatFeed,
    FeedSubscription,
    Dataset,
    FeedQuality,
    MarketplaceMetrics,
    GovernancePolicy,
    FeedType,
    FeedStatus,
    SubscriptionTier,
    AccessLevel,
)
from .store import get_marketplace_store, MarketplaceStore, reset_marketplace_store


class MarketplaceService:
    """Core marketplace service."""

    def __init__(self, store: Optional[MarketplaceStore] = None):
        self._store = store or get_marketplace_store()

    def publish_feed(
        self,
        name: str,
        description: str,
        feed_type: FeedType,
        provider: str,
        provider_id: str,
        **kwargs: Any,
    ) -> ThreatFeed:
        """Publish a new threat feed."""
        feed = ThreatFeed(
            name=name,
            description=description,
            feed_type=feed_type,
            provider=provider,
            provider_id=provider_id,
            **kwargs,
        )
        self._store.store_feed(feed)
        return feed

    def get_feed(self, feed_id: str) -> Optional[ThreatFeed]:
        """Get feed by ID."""
        return self._store.get_feed(feed_id)

    def get_feeds(
        self,
        feed_type: Optional[FeedType] = None,
        status: Optional[FeedStatus] = None,
        access_level: Optional[AccessLevel] = None,
    ) -> List[ThreatFeed]:
        """Get feeds with optional filters."""
        feeds = self._store.get_all_feeds()

        if feed_type:
            feeds = [f for f in feeds if f.feed_type == feed_type]
        if status:
            feeds = [f for f in feeds if f.status == status]
        if access_level:
            feeds = [f for f in feeds if f.access_level == access_level]

        return feeds

    def update_feed_status(
        self,
        feed_id: str,
        status: FeedStatus,
    ) -> Optional[ThreatFeed]:
        """Update feed status."""
        feed = self._store.get_feed(feed_id)
        if feed:
            feed.status = status
            self._store.store_feed(feed)
        return feed

    def subscribe_to_feed(
        self,
        feed_id: str,
        subscriber_id: str,
        tier: SubscriptionTier = SubscriptionTier.FREE,
        **kwargs: Any,
    ) -> FeedSubscription:
        """Subscribe to a feed."""
        subscription = FeedSubscription(
            feed_id=feed_id,
            subscriber_id=subscriber_id,
            tier=tier,
            **kwargs,
        )
        self._store.subscribe_to_feed(subscription)
        return subscription

    def get_subscriptions(self, subscriber_id: str) -> List[FeedSubscription]:
        """Get subscriptions for a subscriber."""
        return self._store.get_subscriptions_by_subscriber(subscriber_id)

    def publish_dataset(
        self,
        name: str,
        description: str,
        provider: str,
        provider_id: str,
        **kwargs: Any,
    ) -> Dataset:
        """Publish a dataset."""
        dataset = Dataset(
            name=name,
            description=description,
            provider=provider,
            provider_id=provider_id,
            **kwargs,
        )
        self._store.store_dataset(dataset)
        return dataset

    def get_dataset(self, dataset_id: str) -> Optional[Dataset]:
        """Get dataset by ID."""
        return self._store.get_dataset(dataset_id)

    def get_all_datasets(self) -> List[Dataset]:
        """Get all datasets."""
        return self._store.get_all_datasets()

    def rate_feed(
        self,
        feed_id: str,
        accuracy: float,
        freshness: float,
        coverage: float,
        reliability: float,
        **kwargs: Any,
    ) -> FeedQuality:
        """Rate a feed's quality."""
        overall = (accuracy + freshness + coverage + reliability) / 4.0

        quality = FeedQuality(
            feed_id=feed_id,
            accuracy_score=accuracy,
            freshness_score=freshness,
            coverage_score=coverage,
            reliability_score=reliability,
            overall_score=overall,
            **kwargs,
        )
        self._store.store_quality(quality)
        return quality

    def get_feed_quality(self, feed_id: str) -> Optional[FeedQuality]:
        """Get feed quality metrics."""
        return self._store.get_quality(feed_id)

    def create_governance_policy(
        self,
        name: str,
        description: str,
        policy_type: str,
        rules: List[Dict[str, Any]],
        **kwargs: Any,
    ) -> GovernancePolicy:
        """Create a governance policy."""
        policy = GovernancePolicy(
            name=name,
            description=description,
            policy_type=policy_type,
            rules=rules,
            **kwargs,
        )
        self._store.store_policy(policy)
        return policy

    def get_governance_policies(self) -> List[GovernancePolicy]:
        """Get all governance policies."""
        return self._store.get_policies()

    def get_metrics(self) -> MarketplaceMetrics:
        """Get marketplace metrics."""
        return self._store.get_metrics()

    def search_feeds(
        self,
        query: str,
        tags: Optional[List[str]] = None,
        feed_type: Optional[FeedType] = None,
    ) -> List[ThreatFeed]:
        """Search for feeds."""
        feeds = self._store.get_active_feeds()
        results = []

        query_lower = query.lower()
        for feed in feeds:
            if (query_lower in feed.name.lower() or
                    query_lower in feed.description.lower()):
                if tags:
                    if any(tag in feed.tags for tag in tags):
                        results.append(feed)
                elif feed_type:
                    if feed.feed_type == feed_type:
                        results.append(feed)
                else:
                    results.append(feed)

        return results

    def get_top_rated_feeds(self, limit: int = 10) -> List[ThreatFeed]:
        """Get top-rated feeds."""
        feeds = self._store.get_all_feeds()
        feed_ids = [f.feed_id for f in feeds]

        rated = [
            (fid, self._store.get_quality(fid))
            for fid in feed_ids
        ]
        rated = [(fid, q) for fid, q in rated if q]

        rated.sort(key=lambda x: x[1].overall_score if x[1] else 0, reverse=True)

        top_ids = [fid for fid, _ in rated[:limit]]
        return [f for f in feeds if f.feed_id in top_ids]

    def clear(self) -> None:
        """Clear all data."""
        reset_marketplace_store()


_marketplace_service: Optional[MarketplaceService] = None


def get_marketplace_service() -> MarketplaceService:
    global _marketplace_service
    if _marketplace_service is None:
        _marketplace_service = MarketplaceService()
    return _marketplace_service


def reset_marketplace_service() -> None:
    global _marketplace_service
    _marketplace_service = None
    reset_marketplace_store()
