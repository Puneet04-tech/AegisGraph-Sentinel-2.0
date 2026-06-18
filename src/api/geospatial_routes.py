"""
API routes for Issue #1021 - Geospatial Encryption.
"""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from src.api.security import Role, require_role
from src.geospatial.models import Asset
from src.geospatial.service import GeospatialCryptor, AccessAuditLogger, GeospatialTrackingService

router = APIRouter(prefix="/api/v1/geospatial", tags=["Geospatial Tracking"])

cryptor = GeospatialCryptor()
audit_logger = AccessAuditLogger()
tracking_service = GeospatialTrackingService(cryptor, audit_logger)


class LocationUpdateRequestModel(BaseModel):
    asset_id: str
    latitude: float
    longitude: float
    accuracy: float = 1.0


@router.post(
    "/update",
    summary="Submit asset location update",
    dependencies=[Depends(require_role(Role.ANALYST))]
)
async def submit_location_update(request: LocationUpdateRequestModel):
    """Submits location update and stores encrypted coordinates."""
    tracking_service.process_location_update(
        asset_id=request.asset_id,
        lat=request.latitude,
        lon=request.longitude,
        accuracy=request.accuracy
    )
    return {"status": "success", "asset_id": request.asset_id}


@router.get(
    "/assets/{asset_id}",
    summary="Retrieve audited asset current location",
    dependencies=[Depends(require_role(Role.ANALYST))]
)
async def get_asset_location(asset_id: str, user_id: str = "analyst_1"):
    """Decrypted asset coordinates with security access logging."""
    if asset_id not in tracking_service.assets:
        raise HTTPException(status_code=404, detail="Asset not found")

    asset = tracking_service.assets[asset_id]
    tenant_id = "default_tenant"
    tenant_key = cryptor.get_tenant_key(tenant_id)

    # Access logging audit trail
    audit_logger.log_access(user_id, "read_current_location", asset_id, tenant_id)

    try:
        lat = cryptor.decrypt_coordinate(asset.encrypted_last_lat, tenant_key)
        lon = cryptor.decrypt_coordinate(asset.encrypted_last_lon, tenant_key)
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to decrypt coordinates")

    return {
        "asset_id": asset.asset_id,
        "name": asset.name,
        "latitude": lat,
        "longitude": lon,
        "last_updated": asset.last_updated.isoformat() if asset.last_updated else None,
        "accuracy": asset.accuracy
    }


def register_routes(app):
    app.include_router(router)
