"""
API routes for Issue #1022 - Real-Time Update Pipeline.
"""

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
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
    """Enqueues location update to the async queue for non-blocking processing."""
    await tracking_service.add_update_to_queue(
        asset_id=request.asset_id,
        lat=request.latitude,
        lon=request.longitude,
        accuracy=request.accuracy
    )
    return {"status": "queued", "asset_id": request.asset_id}


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


@router.websocket("/stream")
async def stream_geospatial_updates(websocket: WebSocket):
    """WebSocket endpoint to broadcast compressed real-time coordinates updates."""
    await websocket.accept()
    tracking_service.websocket_listeners.add(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        if websocket in tracking_service.websocket_listeners:
            tracking_service.websocket_listeners.remove(websocket)


def register_routes(app):
    app.include_router(router)
