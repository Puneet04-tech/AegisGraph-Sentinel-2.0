"""Intelligence Marketplace Catalog"""
from typing import Any, Dict, List, Optional
from uuid import uuid4
from datetime import datetime, timedelta
from .marketplace_models import (
    IntelligenceAsset, Subscription, Publisher,
    AssetType, AssetStatus, SubscriptionStatus
)

class Catalog:
    """Intelligence asset catalog"""
    
    def __init__(self) -> None:
        self.assets: Dict[str, IntelligenceAsset] = {}
        self.subscriptions: Dict[str, Subscription] = {}
        self.publishers: Dict[str, Publisher] = {}
    
    def add_asset(self, asset: IntelligenceAsset) -> str:
        """Add an asset to the catalog"""
        self.assets[asset.asset_id] = asset
        # Update publisher stats
        publisher = self.publishers.get(asset.publisher_id)
        if publisher:
            publisher.total_assets += 1
        return asset.asset_id
    
    def get_asset(self, asset_id: str) -> Optional[IntelligenceAsset]:
        """Get an asset by ID"""
        return self.assets.get(asset_id)
    
    def search_assets(
        self,
        query: Optional[str] = None,
        asset_type: Optional[str] = None,
        tags: Optional[List[str]] = None,
        status: Optional[str] = None
    ) -> List[IntelligenceAsset]:
        """Search assets in the catalog"""
        results = list(self.assets.values())
        
        if query:
            query_lower = query.lower()
            results = [
                a for a in results
                if query_lower in a.name.lower() or query_lower in a.description.lower()
            ]
        
        if asset_type:
            results = [a for a in results if a.asset_type.value == asset_type]
        
        if tags:
            results = [
                a for a in results
                if any(tag in a.tags for tag in tags)
            ]
        
        if status:
            results = [a for a in results if a.status.value == status]
        
        return sorted(results, key=lambda a: a.downloads, reverse=True)
    
    def publish_asset(
        self,
        name: str,
        description: str,
        asset_type: str,
        publisher_id: str,
        version: str,
        tags: List[str],
        metadata: Optional[Dict[str, Any]] = None
    ) -> IntelligenceAsset:
        """Publish a new asset"""
        asset = IntelligenceAsset(
            asset_id=str(uuid4()),
            name=name,
            description=description,
            asset_type=AssetType(asset_type),
            publisher_id=publisher_id,
            version=version,
            status=AssetStatus.PUBLISHED,
            tags=tags,
            metadata=metadata or {}
        )
        self.add_asset(asset)
        return asset
    
    def subscribe(
        self,
        asset_id: str,
        subscriber_id: str,
        duration_days: int = 30,
        price: float = 0.0
    ) -> Optional[Subscription]:
        """Subscribe to an asset"""
        if asset_id not in self.assets:
            return None
        
        subscription = Subscription(
            subscription_id=str(uuid4()),
            asset_id=asset_id,
            subscriber_id=subscriber_id,
            status=SubscriptionStatus.ACTIVE,
            start_date=datetime.utcnow(),
            end_date=datetime.utcnow() + timedelta(days=duration_days),
            price_paid=price
        )
        self.subscriptions[subscription.subscription_id] = subscription
        
        # Update asset downloads
        asset = self.assets[asset_id]
        asset.downloads += 1
        
        # Update publisher subscribers
        publisher = self.publishers.get(asset.publisher_id)
        if publisher:
            publisher.total_subscribers += 1
        
        return subscription
    
    def get_asset_subscriptions(self, asset_id: str) -> List[Subscription]:
        """Get all subscriptions for an asset"""
        return [s for s in self.subscriptions.values() if s.asset_id == asset_id]
    
    def get_user_subscriptions(self, subscriber_id: str) -> List[Subscription]:
        """Get all subscriptions for a user"""
        return [s for s in self.subscriptions.values() if s.subscriber_id == subscriber_id]
    
    def add_publisher(self, publisher: Publisher) -> str:
        """Add a publisher"""
        self.publishers[publisher.publisher_id] = publisher
        return publisher.publisher_id
    
    def get_publisher(self, publisher_id: str) -> Optional[Publisher]:
        """Get a publisher by ID"""
        return self.publishers.get(publisher_id)
    
    def get_top_publishers(self, limit: int = 10) -> List[Publisher]:
        """Get top publishers by assets"""
        return sorted(
            self.publishers.values(),
            key=lambda p: p.total_assets,
            reverse=True
        )[:limit]
    
    def get_catalog_stats(self) -> Dict[str, Any]:
        """Get catalog statistics"""
        by_type: Dict[str, int] = {}
        by_status: Dict[str, int] = {}
        
        for asset in self.assets.values():
            by_type[asset.asset_type.value] = by_type.get(asset.asset_type.value, 0) + 1
            by_status[asset.status.value] = by_status.get(asset.status.value, 0) + 1
        
        return {
            "total_assets": len(self.assets),
            "total_subscriptions": len(self.subscriptions),
            "total_publishers": len(self.publishers),
            "by_type": by_type,
            "by_status": by_status,
            "total_downloads": sum(a.downloads for a in self.assets.values())
        }