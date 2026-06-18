"""
API routes for Issue #1024 - Drift Correction and Kalman Filtering.
"""

import json
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

from src.api.security import Role, require_role
from src.geospatial.models import Geofence, GeofenceBreach, Route
from src.geospatial.service import GeospatialCryptor, AccessAuditLogger, GeospatialTrackingService, RouteOptimizationEngine

router = APIRouter(prefix="/api/v1/geospatial", tags=["Geospatial Tracking"])

cryptor = GeospatialCryptor()
audit_logger = AccessAuditLogger()
tracking_service = GeospatialTrackingService(cryptor, audit_logger)
route_engine = RouteOptimizationEngine()


class LocationUpdateRequestModel(BaseModel):
    asset_id: str
    latitude: float
    longitude: float
    accuracy: float = 1.0
    signal_strength: float = 1.0


class GeofenceRequestModel(BaseModel):
    geofence_id: str
    name: str
    boundary_type: str = "circle"
    center_lat: Optional[float] = None
    center_lon: Optional[float] = None
    radius_meters: Optional[float] = None
    coordinates: Optional[List[List[float]]] = None
    tenant_id: str = "default_tenant"


class WebhookRequestModel(BaseModel):
    url: str


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
    """Returns the history of geofence breach events (decrypted)."""
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
    """Registers a webhook URL for immediate geofence breach alerts."""
    tracking_service.register_webhook(request.url)
    return {"status": "registered", "url": request.url}


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


class OptimizeRouteRequestModel(BaseModel):
    asset_id: str
    source: List[int]
    target: List[int]


@router.post(
    "/routes/optimize",
    summary="Optimize route for asset",
    response_model=Route,
    dependencies=[Depends(require_role(Role.ANALYST))]
)
async def optimize_route(request: OptimizeRouteRequestModel):
    """Calculates A* optimized route on 2D grid with traffic multipliers."""
    if len(request.source) != 2 or len(request.target) != 2:
        raise HTTPException(status_code=400, detail="Source and target must be 2D grid coordinates")
    try:
        source_tuple = (request.source[0], request.source[1])
        target_tuple = (request.target[0], request.target[1])
        route = route_engine.optimize_route(request.asset_id, source_tuple, target_tuple)
        return route
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get(
    "/assets/{asset_id}/predict",
    summary="Predict asset next location using Kalman Filter tracker",
    dependencies=[Depends(require_role(Role.ANALYST))]
)
async def predict_asset_location(asset_id: str, dt: float = 10.0):
    """Predicts next location using Kalman tracking state."""
    tracker = tracking_service.active_trackers.get(asset_id)
    if not tracker:
        raise HTTPException(status_code=404, detail="No active tracker found for asset")
    
    try:
        lat, lon = route_engine.predict_next_location(tracker, dt)
        return {
            "asset_id": asset_id,
            "predicted_latitude": lat,
            "predicted_longitude": lon,
            "dt": dt
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def register_routes(app):
    app.include_router(router)
