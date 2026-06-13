"""Intelligence Marketplace Service"""
from typing import Any, Dict, List, Optional
from .marketplace_models import IntelligenceAsset, Subscription, Publisher
from .catalog import Catalog

class MarketplaceService:
    """Main service for Intelligence Marketplace"""
    
    def __init__(self) -> None:
        self.catalog = Catalog()
        self._init_sample_data()
    
    def _init_sample_data(self) -> None:
        """Initialize with sample data"""
        # Add sample publisher
        publisher = Publisher(
            publisher_id="aegisgraph",
            name="AegisGraph Security",
            description="Official AegisGraph intelligence assets",
            verified=True,
            total_assets=0,
            total_subscribers=0
        )
        self.catalog.add_publisher(publisher)
    
    def publish_asset(
        self,
        name: str,
        description: str,
        asset_type: str,
        publisher_id: str,
        version: str,
        tags: List[str],
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Publish an asset"""
        asset = self.catalog.publish_asset(
            name=name,
            description=description,
            asset_type=asset_type,
            publisher_id=publisher_id,
            version=version,
            tags=tags,
            metadata=metadata
        )
        return asset.to_dict()
    
    def get_asset(self, asset_id: str) -> Optional[Dict[str, Any]]:
        """Get an asset by ID"""
        asset = self.catalog.get_asset(asset_id)
        return asset.to_dict() if asset else None
    
    def search_assets(
        self,
        query: Optional[str] = None,
        asset_type: Optional[str] = None,
        tags: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """Search assets"""
        assets = self.catalog.search_assets(query, asset_type, tags)
        return [a.to_dict() for a in assets]
    
    def subscribe(
        self,
        asset_id: str,
        subscriber_id: str,
        duration_days: int = 30,
        price: float = 0.0
    ) -> Optional[Dict[str, Any]]:
        """Subscribe to an asset"""
        subscription = self.catalog.subscribe(
            asset_id=asset_id,
            subscriber_id=subscriber_id,
            duration_days=duration_days,
            price=price
        )
        return subscription.to_dict() if subscription else None
    
    def get_user_subscriptions(self, subscriber_id: str) -> List[Dict[str, Any]]:
        """Get user's subscriptions"""
        return [s.to_dict() for s in self.catalog.get_user_subscriptions(subscriber_id)]
    
    def get_publisher(self, publisher_id: str) -> Optional[Dict[str, Any]]:
        """Get a publisher"""
        publisher = self.catalog.get_publisher(publisher_id)
        return publisher.to_dict() if publisher else None
    
    def get_top_publishers(self) -> List[Dict[str, Any]]:
        """Get top publishers"""
        return [p.to_dict() for p in self.catalog.get_top_publishers()]
    
    def get_catalog_stats(self) -> Dict[str, Any]:
        """Get catalog statistics"""
        return self.catalog.get_catalog_stats()
    
    def get_assets_by_type(self, asset_type: str) -> List[Dict[str, Any]]:
        """Get assets by type"""
        assets = self.catalog.search_assets(asset_type=asset_type)
        return [a.to_dict() for a in assets]
    
    def get_featured_assets(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get featured/popular assets"""
        assets = self.catalog.search_assets(status="PUBLISHED")[:limit]
        return [a.to_dict() for a in assets]


# Global service instance
_marketplace_service: Optional[MarketplaceService] = None

def get_marketplace_service() -> MarketplaceService:
    """Get the global service instance"""
    global _marketplace_service
    if _marketplace_service is None:
        _marketplace_service = MarketplaceService()
    return _marketplace_service