"""
Threat Intelligence Marketplace Store - Thread-safe storage
"""

from __future__ import annotations

from threading import Lock
from typing import Dict, List, Optional

from .models import (
    ThreatFeed,
    FeedSubscription,
    Dataset,
    FeedQuality,
    MarketplaceMetrics,
    GovernancePolicy,
    FeedType,
    FeedStatus,
)


class MarketplaceStore:
    """Thread-safe storage for marketplace data."""

    def __init__(self):
        self._lock = Lock()
        self._feeds: Dict[str, ThreatFeed] = {}
        self._subscriptions: Dict[str, FeedSubscription] = {}
        self._datasets: Dict[str, Dataset] = {}
        self._quality_metrics: Dict[str, FeedQuality] = {}
        self._policies: Dict[str, GovernancePolicy] = {}

    def store_feed(self, feed: ThreatFeed) -> ThreatFeed:
        with self._lock:
            self._feeds[feed.feed_id] = feed
        return feed

    def get_feed(self, feed_id: str) -> Optional[ThreatFeed]:
        return self._feeds.get(feed_id)

    def get_feeds_by_type(self, feed_type: FeedType) -> List[ThreatFeed]:
        return [
            f for f in self._feeds.values()
            if f.feed_type == feed_type
        ]

    def get_feeds_by_status(self, status: FeedStatus) -> List[ThreatFeed]:
        return [
            f for f in self._feeds.values()
            if f.status == status
        ]

    def get_active_feeds(self) -> List[ThreatFeed]:
        return self.get_feeds_by_status(FeedStatus.ACTIVE)

    def get_all_feeds(self) -> List[ThreatFeed]:
        return list(self._feeds.values())

    def subscribe_to_feed(
        self, subscription: FeedSubscription
    ) -> FeedSubscription:
        with self._lock:
            self._subscriptions[subscription.subscription_id] = subscription
        return subscription

    def get_subscription(
        self, subscription_id: str
    ) -> Optional[FeedSubscription]:
        return self._subscriptions.get(subscription_id)

    def get_subscriptions_by_subscriber(
        self, subscriber_id: str
    ) -> List[FeedSubscription]:
        return [
            s for s in self._subscriptions.values()
            if s.subscriber_id == subscriber_id
        ]

    def get_subscriptions_by_feed(self, feed_id: str) -> List[FeedSubscription]:
        return [
            s for s in self._subscriptions.values()
            if s.feed_id == feed_id
        ]

    def store_dataset(self, dataset: Dataset) -> Dataset:
        with self._lock:
            self._datasets[dataset.dataset_id] = dataset
        return dataset

    def get_dataset(self, dataset_id: str) -> Optional[Dataset]:
        return self._datasets.get(dataset_id)

    def get_all_datasets(self) -> List[Dataset]:
        return list(self._datasets.values())

    def store_quality(self, quality: FeedQuality) -> FeedQuality:
        with self._lock:
            self._quality_metrics[quality.feed_id] = quality
        return quality

    def get_quality(self, feed_id: str) -> Optional[FeedQuality]:
        return self._quality_metrics.get(feed_id)

    def store_policy(self, policy: GovernancePolicy) -> GovernancePolicy:
        with self._lock:
            self._policies[policy.policy_id] = policy
        return policy

    def get_policies(self) -> List[GovernancePolicy]:
        return list(self._policies.values())

    def get_metrics(self) -> MarketplaceMetrics:
        feeds = list(self._feeds.values())
        type_counts: Dict[str, int] = {}

        for feed in feeds:
            type_counts[feed.feed_type.value] = (
                type_counts.get(feed.feed_type.value, 0) + 1
            )

        top_rated = [
            {"feed_id": q.feed_id, "score": q.overall_score}
            for q in sorted(
                self._quality_metrics.values(),
                key=lambda x: x.overall_score,
                reverse=True,
            )[:5]
        ]

        return MarketplaceMetrics(
            total_feeds=len(feeds),
            active_feeds=len(self.get_active_feeds()),
            total_subscribers=len(set(s.subscriber_id for s in self._subscriptions.values())),
            total_datasets=len(self._datasets),
            feeds_by_type=type_counts,
            top_rated_feeds=top_rated,
        )


_marketplace_store: Optional[MarketplaceStore] = None
_store_lock = Lock()


def get_marketplace_store() -> MarketplaceStore:
    global _marketplace_store
    with _store_lock:
        if _marketplace_store is None:
            _marketplace_store = MarketplaceStore()
        return _marketplace_store


def reset_marketplace_store() -> None:
    global _marketplace_store
    with _store_lock:
        _marketplace_store = MarketplaceStore()
