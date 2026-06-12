"""
Security Intelligence Data Marketplace API Routes
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Header, Query
from pydantic import BaseModel

from src.intelligence_marketplace import (
    MarketplaceEngine,
    get_marketplace_engine,
    ListingType,
    ListingStatus,
    SubscriptionTier,
)


router = APIRouter(prefix="/api/v1/marketplace", tags=["marketplace"])


class CreateListingRequest(BaseModel):
    name: str
    description: str
    listing_type: str
    publisher_id: str
    tags: List[str] = []
    price: float = 0.0


class SubscribeRequest(BaseModel):
    listing_id: str
    subscriber_id: str
    tier: str = "STANDARD"


def verify_api_key(x_api_key: str = Header(None)) -> str:
    """Verify API key."""
    if x_api_key != "SUPER_ADMIN":
        raise HTTPException(status_code=401, detail="Invalid API key")
    return x_api_key


@router.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "module": "marketplace",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.post("/listings")
async def create_listing(
    request: CreateListingRequest,
    api_key: str = Header(None),
):
    """Create a new listing."""
    verify_api_key(api_key)
    engine = get_marketplace_engine()
    
    try:
        listing_type = ListingType(request.listing_type)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid listing type")
    
    listing_id = engine.publish_listing(
        name=request.name,
        description=request.description,
        listing_type=listing_type,
        publisher_id=request.publisher_id,
        tags=request.tags,
    )
    
    return {"listing_id": listing_id, "status": "published"}


@router.get("/listings")
async def list_listings(
    query: Optional[str] = None,
    listing_type: Optional[str] = None,
    api_key: str = Header(None),
):
    """List marketplace listings."""
    verify_api_key(api_key)
    engine = get_marketplace_engine()
    
    lt = None
    if listing_type:
        try:
            lt = ListingType(listing_type)
        except ValueError:
            pass
    
    listings = engine.listing_manager.search_listings(
        query=query or "",
        listing_type=lt,
    )
    
    return {
        "count": len(listings),
        "listings": [l.to_dict() for l in listings],
    }


@router.get("/listings/{listing_id}")
async def get_listing(
    listing_id: str,
    api_key: str = Header(None),
):
    """Get a listing by ID."""
    verify_api_key(api_key)
    engine = get_marketplace_engine()
    
    listing = engine.listing_manager.get_listing(listing_id)
    if not listing:
        raise HTTPException(status_code=404, detail="Listing not found")
    
    return {"listing": listing.to_dict()}


@router.post("/subscribe")
async def subscribe(
    request: SubscribeRequest,
    api_key: str = Header(None),
):
    """Subscribe to a listing."""
    verify_api_key(api_key)
    engine = get_marketplace_engine()
    
    try:
        tier = SubscriptionTier(request.tier)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid tier")
    
    subscription_id = engine.subscribe_to_listing(
        listing_id=request.listing_id,
        subscriber_id=request.subscriber_id,
        tier=tier,
    )
    
    return {"subscription_id": subscription_id, "status": "subscribed"}


@router.get("/dashboard")
async def get_dashboard(api_key: str = Header(None)):
    """Get marketplace dashboard."""
    verify_api_key(api_key)
    return get_marketplace_engine().get_dashboard()