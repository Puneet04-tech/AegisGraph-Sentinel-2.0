"""
API routes for the Geospatial Asset Tracking Suite.
"""

from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field

from src.api.security import Role, require_role
from src.geospatial.models import Geofence, GeofenceBreach, Route
from src.geospatial.service import (
    GeospatialCryptor,
    AccessAuditLogger,
    GeospatialTrackingService,
    RouteOptimizationEngine,
)

router = APIRouter(prefix="/api/v1/geospatial", tags=["Geospatial Tracking"])

# Initialize singletons
cryptor = GeospatialCryptor()
audit_logger = AccessAuditLogger()
tracking_service = GeospatialTrackingService(cryptor, audit_logger)
routing_engine = RouteOptimizationEngine()


# Pydantic models for request payloads
class LocationUpdateRequestModel(BaseModel):
    asset_id: str
    latitude: float
    longitude: float
    accuracy: float = 1.0
    signal_strength: float = 1.0


class GeofenceRequestModel(BaseModel):
    geofence_id: str
    name: str
    boundary_type: str = "circle"  # "circle" or "polygon"
    center_lat: Optional[float] = None
    center_lon: Optional[float] = None
    radius_meters: Optional[float] = None
    coordinates: Optional[List[List[float]]] = None  # for polygon: [[lat, lon], ...]
    tenant_id: str = "default_tenant"


class WebhookRequestModel(BaseModel):
    url: str


class RouteOptimizeRequestModel(BaseModel):
    asset_id: str
    source_x: int
    source_y: int
    target_x: int
    target_y: int


# ========== Endpoints ==========

@router.post(
    "/update",
    summary="Submit asset location update",
    dependencies=[Depends(require_role(Role.ANALYST))]
)
async def submit_location_update(request: LocationUpdateRequestModel):
    """Enqueues a new location update for an asset."""
    await tracking_service.add_update_to_queue(
        asset_id=request.asset_id,
        lat=request.latitude,
        lon=request.longitude,
        accuracy=request.accuracy,
        signal_strength=request.signal_strength
    )
    return {"status": "queued", "asset_id": request.asset_id}


@router.post(
    "/geofences",
    summary="Create a new geofence boundary",
    dependencies=[Depends(require_role(Role.ANALYST))]
)
async def create_geofence(request: GeofenceRequestModel):
    """Register a new circular or polygonal geofence."""
    tenant_key = cryptor.get_tenant_key(request.tenant_id)
    
    enc_center_lat = None
    enc_center_lon = None
    enc_coordinates = None

    if request.boundary_type == "circle":
        if request.center_lat is None or request.center_lon is None or request.radius_meters is None:
            raise HTTPException(status_code=400, detail="Circle geofence requires center_lat, center_lon, and radius_meters")
        enc_center_lat = cryptor.encrypt_coordinate(request.center_lat, tenant_key)
        enc_center_lon = cryptor.encrypt_coordinate(request.center_lon, tenant_key)
    elif request.boundary_type == "polygon":
        if not request.coordinates:
            raise HTTPException(status_code=400, detail="Polygon geofence requires coordinate list")
        enc_coordinates = cryptor.encrypt_string(json.dumps(request.coordinates), tenant_key)
    else:
        raise HTTPException(status_code=400, detail="Invalid boundary type. Must be circle or polygon")

    fence = Geofence(
        geofence_id=request.geofence_id,
        name=request.name,
        boundary_type=request.boundary_type,
        encrypted_center_lat=enc_center_lat,
        encrypted_center_lon=enc_center_lon,
        radius_meters=request.radius_meters,
        encrypted_coordinates=enc_coordinates,
        tenant_id=request.tenant_id
    )

    tracking_service.register_geofence(fence)
    return {"status": "created", "geofence_id": request.geofence_id}


@router.get(
    "/geofences",
    summary="List geofences",
    dependencies=[Depends(require_role(Role.ANALYST))]
)
async def list_geofences():
    """Lists metadata for all active geofences (coordinates remain encrypted)."""
    return [
        {
            "geofence_id": f.geofence_id,
            "name": f.name,
            "boundary_type": f.boundary_type,
            "radius_meters": f.radius_meters,
            "tenant_id": f.tenant_id
        }
        for f in tracking_service.geofences.values()
    ]


@router.get(
    "/breaches",
    summary="List geofence breach events",
    dependencies=[Depends(require_role(Role.ANALYST))]
)
async def list_breaches():
    """Returns the history of geofence breach events (decrypted for auditor/analyst)."""
    tenant_id = "default_tenant"
    tenant_key = cryptor.get_tenant_key(tenant_id)
    
    results = []
    for b in tracking_service.breach_history:
        try:
            lat = cryptor.decrypt_coordinate(b.encrypted_lat, tenant_key)
            lon = cryptor.decrypt_coordinate(b.encrypted_lon, tenant_key)
        except Exception:
            lat, lon = 0.0, 0.0

        results.append({
            "alert_id": b.alert_id,
            "asset_id": b.asset_id,
            "geofence_id": b.geofence_id,
            "breach_type": b.breach_type,
            "timestamp": b.timestamp.isoformat(),
            "latitude": lat,
            "longitude": lon,
            "resolved": b.resolved
        })
    return results


@router.post(
    "/webhooks",
    summary="Register a webhook URL for breach alerts",
    dependencies=[Depends(require_role(Role.ANALYST))]
)
async def register_webhook_url(request: WebhookRequestModel):
    """Registers a webhook URL for immediate geofence breach events notification."""
    tracking_service.register_webhook(request.url)
    return {"status": "registered", "url": request.url}


@router.post(
    "/routes/optimize",
    summary="Optimize route using A* and simulate traffic",
    dependencies=[Depends(require_role(Role.ANALYST))]
)
async def optimize_route(request: RouteOptimizeRequestModel):
    """Calculates shortest route from source to target grids avoiding congestion."""
    route = routing_engine.optimize_route(
        asset_id=request.asset_id,
        source=(request.source_x, request.source_y),
        target=(request.target_x, request.target_y)
    )
    return {
        "route_id": route.route_id,
        "asset_id": route.asset_id,
        "points": route.points,
        "eta_minutes": route.eta_minutes
    }


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


@router.get(
    "/assets/{asset_id}/predict",
    summary="Predict next location based on velocity",
    dependencies=[Depends(require_role(Role.ANALYST))]
)
async def predict_asset_location(asset_id: str, dt_seconds: float = 10.0):
    """Uses Kalman filter state vectors to predict next location."""
    if asset_id not in tracking_service.active_trackers:
        raise HTTPException(status_code=404, detail="No active tracker found for asset")

    tracker = tracking_service.active_trackers[asset_id]
    pred_lat, pred_lon = routing_engine.predict_next_location(tracker, dt=dt_seconds)
    
    return {
        "asset_id": asset_id,
        "predicted_latitude": pred_lat,
        "predicted_longitude": pred_lon,
        "dt_seconds": dt_seconds
    }


@router.websocket("/stream")
async def stream_geospatial_updates(websocket: WebSocket):
    """Establishes zlib-compressed real-time telemetry stream."""
    await websocket.accept()
    tracking_service.websocket_listeners.add(websocket)
    try:
        while True:
            # Standard heartbeat/keepalive
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        if websocket in tracking_service.websocket_listeners:
            tracking_service.websocket_listeners.remove(websocket)


def register_routes(app):
    app.include_router(router)
