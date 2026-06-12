"""
Security Intelligence Data Marketplace Engine
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

from .models import (
    MarketplaceListing,
    ListingType,
    ListingStatus,
    AccessType,
    Subscription,
    SubscriptionTier,
    Dataset,
    ThreatFeed,
)


class ListingManager:
    """Manager for marketplace listings."""
    
    def __init__(self):
        self.listings: Dict[str, MarketplaceListing] = {}
        self._initialize_default_listings()
    
    def _initialize_default_listings(self):
        """Initialize with default listings."""
        defaults = [
            MarketplaceListing(
                listing_id="list-001",
                name="Global Fraud Indicators",
                description="Real-time fraud indicators from global sources",
                listing_type=ListingType.THREAT_FEED,
                publisher_id="system",
                status=ListingStatus.PUBLISHED,
            ),
            MarketplaceListing(
                listing_id="list-002",
                name="AML Training Data",
                description="Anti-money laundering training dataset",
                listing_type=ListingType.DATASET,
                publisher_id="system",
                status=ListingStatus.PUBLISHED,
                access_type=AccessType.PAID,
                price=999.99,
            ),
        ]
        for listing in defaults:
            self.listings[listing.listing_id] = listing
    
    def create_listing(
        self,
        name: str,
        description: str,
        listing_type: ListingType,
        publisher_id: str,
        tags: Optional[List[str]] = None,
        price: float = 0.0,
    ) -> str:
        """Create a new listing."""
        listing_id = str(uuid4())
        listing = MarketplaceListing(
            listing_id=listing_id,
            name=name,
            description=description,
            listing_type=listing_type,
            publisher_id=publisher_id,
            tags=tags or [],
            price=price,
        )
        self.listings[listing_id] = listing
        return listing_id
    
    def get_listing(self, listing_id: str) -> Optional[MarketplaceListing]:
        """Get a listing by ID."""
        return self.listings.get(listing_id)
    
    def update_listing(
        self,
        listing_id: str,
        status: Optional[ListingStatus] = None,
    ) -> bool:
        """Update a listing."""
        listing = self.listings.get(listing_id)
        if not listing:
            return False
        if status:
            listing.status = status
        listing.updated_at = datetime.now(timezone.utc)
        return True
    
    def search_listings(
        self,
        query: str = "",
        tags: Optional[List[str]] = None,
        listing_type: Optional[ListingType] = None,
    ) -> List[MarketplaceListing]:
        """Search listings."""
        results = list(self.listings.values())
        if query:
            query_lower = query.lower()
            results = [
                l for l in results
                if query_lower in l.name.lower() or query_lower in l.description.lower()
            ]
        if tags:
            results = [l for l in results if any(t in l.tags for t in tags)]
        if listing_type:
            results = [l for l in results if l.listing_type == listing_type]
        return results
    
    def get_listings_by_publisher(self, publisher_id: str) -> List[MarketplaceListing]:
        """Get listings by publisher."""
        return [l for l in self.listings.values() if l.publisher_id == publisher_id]


class SubscriptionManager:
    """Manager for subscriptions."""
    
    def __init__(self):
        self.subscriptions: Dict[str, Subscription] = {}
    
    def subscribe(
        self,
        listing_id: str,
        subscriber_id: str,
        tier: SubscriptionTier = SubscriptionTier.STANDARD,
    ) -> str:
        """Subscribe to a listing."""
        subscription_id = str(uuid4())
        subscription = Subscription(
            subscription_id=subscription_id,
            listing_id=listing_id,
            subscriber_id=subscriber_id,
            tier=tier,
        )
        self.subscriptions[subscription_id] = subscription
        return subscription_id
    
    def get_subscription(self, subscription_id: str) -> Optional[Subscription]:
        """Get a subscription."""
        return self.subscriptions.get(subscription_id)
    
    def get_subscriptions_by_subscriber(self, subscriber_id: str) -> List[Subscription]:
        """Get subscriptions for a subscriber."""
        return [
            s for s in self.subscriptions.values()
            if s.subscriber_id == subscriber_id
        ]
    
    def cancel_subscription(self, subscription_id: str) -> bool:
        """Cancel a subscription."""
        subscription = self.subscriptions.get(subscription_id)
        if not subscription:
            return False
        subscription.status = "CANCELLED"
        return True


class DatasetRegistry:
    """Registry for datasets."""
    
    def __init__(self):
        self.datasets: Dict[str, Dataset] = {}
        self._initialize_default_datasets()
    
    def _initialize_default_datasets(self):
        """Initialize with default datasets."""
        defaults = [
            Dataset(
                dataset_id="ds-001",
                listing_id="list-002",
                name="AML Training Data",
                size=1000000,
                format="JSON",
                features=["amount", "frequency", "location", "timestamp"],
                labels=["fraud", "legitimate", "suspicious"],
            ),
        ]
        for ds in defaults:
            self.datasets[ds.dataset_id] = ds
    
    def register_dataset(
        self,
        listing_id: str,
        name: str,
        size: int,
        format: str,
        features: List[str],
        labels: List[str],
    ) -> str:
        """Register a dataset."""
        dataset_id = str(uuid4())
        dataset = Dataset(
            dataset_id=dataset_id,
            listing_id=listing_id,
            name=name,
            size=size,
            format=format,
            features=features,
            labels=labels,
        )
        self.datasets[dataset_id] = dataset
        return dataset_id
    
    def get_dataset(self, dataset_id: str) -> Optional[Dataset]:
        """Get a dataset."""
        return self.datasets.get(dataset_id)


class ThreatFeedExchange:
    """Exchange for threat feeds."""
    
    def __init__(self):
        self.feeds: Dict[str, ThreatFeed] = {}
        self._initialize_default_feeds()
    
    def _initialize_default_feeds(self):
        """Initialize with default feeds."""
        defaults = [
            ThreatFeed(
                feed_id="feed-001",
                listing_id="list-001",
                name="Global Fraud Indicators",
                feed_type="INDICATORS",
                indicators=[
                    {"type": "ip", "value": "192.168.1.1", "confidence": 0.9},
                    {"type": "domain", "value": "fraud.example.com", "confidence": 0.85},
                ],
            ),
        ]
        for feed in defaults:
            self.feeds[feed.feed_id] = feed
    
    def publish_feed(
        self,
        listing_id: str,
        name: str,
        feed_type: str,
        indicators: Optional[List[Dict[str, Any]]] = None,
    ) -> str:
        """Publish a threat feed."""
        feed_id = str(uuid4())
        feed = ThreatFeed(
            feed_id=feed_id,
            listing_id=listing_id,
            name=name,
            feed_type=feed_type,
            indicators=indicators or [],
        )
        self.feeds[feed_id] = feed
        return feed_id
    
    def get_feed(self, feed_id: str) -> Optional[ThreatFeed]:
        """Get a feed."""
        return self.feeds.get(feed_id)
    
    def get_feed_indicators(self, feed_id: str) -> List[Dict[str, Any]]:
        """Get feed indicators."""
        feed = self.feeds.get(feed_id)
        if not feed:
            return []
        return feed.indicators


class MarketplaceEngine:
    """Main marketplace engine."""
    
    def __init__(self):
        self.listing_manager = ListingManager()
        self.subscription_manager = SubscriptionManager()
        self.dataset_registry = DatasetRegistry()
        self.feed_exchange = ThreatFeedExchange()
    
    def publish_listing(
        self,
        name: str,
        description: str,
        listing_type: ListingType,
        publisher_id: str,
        tags: Optional[List[str]] = None,
    ) -> str:
        """Publish a listing."""
        listing_id = self.listing_manager.create_listing(
            name=name,
            description=description,
            listing_type=listing_type,
            publisher_id=publisher_id,
            tags=tags,
        )
        self.listing_manager.update_listing(listing_id, ListingStatus.PUBLISHED)
        return listing_id
    
    def subscribe_to_listing(
        self,
        listing_id: str,
        subscriber_id: str,
        tier: SubscriptionTier = SubscriptionTier.STANDARD,
    ) -> str:
        """Subscribe to a listing."""
        return self.subscription_manager.subscribe(listing_id, subscriber_id, tier)
    
    def get_dashboard(self) -> Dict[str, Any]:
        """Get marketplace dashboard."""
        listings = list(self.listing_manager.listings.values())
        by_type = {}
        for listing in listings:
            lt = listing.listing_type.value
            by_type[lt] = by_type.get(lt, 0) + 1
        
        return {
            "total_listings": len(listings),
            "by_type": by_type,
            "total_subscriptions": len(self.subscription_manager.subscriptions),
            "total_datasets": len(self.dataset_registry.datasets),
            "total_feeds": len(self.feed_exchange.feeds),
        }


def get_marketplace_engine() -> MarketplaceEngine:
    """Get the global marketplace engine."""
    global _marketplace_engine
    if _marketplace_engine is None:
        _marketplace_engine = MarketplaceEngine()
    return _marketplace_engine


_marketplace_engine: Optional[MarketplaceEngine] = None