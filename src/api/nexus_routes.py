"""
Nexus Platform API Routes
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Header, Query
from pydantic import BaseModel

from src.nexus_platform import (
    NexusPlatform,
    get_nexus_platform,
    IntelligenceLayer,
    IntegrationStatus,
)


router = APIRouter(prefix="/api/v1/nexus", tags=["nexus"])


class CrossLayerAnalysisRequest(BaseModel):
    """Request for cross-layer analysis."""
    entity_id: str
    layers: Optional[List[str]] = None


class LayerStatusUpdateRequest(BaseModel):
    """Request to update layer status."""
    status: str
    metrics: Optional[Dict[str, float]] = None
    error: Optional[str] = None


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
        "module": "nexus_platform",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/info")
async def get_platform_info(api_key: str = Header(None)):
    """Get platform information."""
    verify_api_key(api_key)
    platform = get_nexus_platform()
    return platform.get_platform_info()


@router.get("/dashboard")
async def get_dashboard(api_key: str = Header(None)):
    """Get executive dashboard."""
    verify_api_key(api_key)
    platform = get_nexus_platform()
    dashboard = platform.generate_dashboard()
    return dashboard.to_dict()


@router.get("/layers")
async def list_layers(api_key: str = Header(None)):
    """List all intelligence layers."""
    verify_api_key(api_key)
    platform = get_nexus_platform()
    
    layers = []
    for layer in IntelligenceLayer:
        status = platform.get_layer_status(layer)
        layers.append(status.to_dict())
    
    return {
        "count": len(layers),
        "layers": layers,
    }


@router.get("/layers/{layer}")
async def get_layer(
    layer: str,
    api_key: str = Header(None),
):
    """Get status of a specific layer."""
    verify_api_key(api_key)
    
    try:
        layer_enum = IntelligenceLayer(layer)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid layer: {layer}")
    
    platform = get_nexus_platform()
    status = platform.get_layer_status(layer_enum)
    
    return {"layer_status": status.to_dict()}


@router.patch("/layers/{layer}")
async def update_layer(
    layer: str,
    request: LayerStatusUpdateRequest,
    api_key: str = Header(None),
):
    """Update layer status."""
    verify_api_key(api_key)
    
    try:
        layer_enum = IntelligenceLayer(layer)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid layer: {layer}")
    
    try:
        status_enum = IntegrationStatus(request.status)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid status: {request.status}")
    
    platform = get_nexus_platform()
    platform.update_layer_status(
        layer=layer_enum,
        status=status_enum,
        metrics=request.metrics,
        error=request.error,
    )
    
    return {"status": "updated"}


@router.get("/capabilities")
async def list_capabilities(
    enabled_only: bool = Query(default=False),
    api_key: str = Header(None),
):
    """List all capabilities."""
    verify_api_key(api_key)
    platform = get_nexus_platform()
    
    capabilities = platform.capabilities
    if enabled_only:
        capabilities = platform.get_enabled_capabilities()
    
    return {
        "count": len(capabilities),
        "capabilities": [c.to_dict() for c in capabilities],
    }


@router.get("/capabilities/{capability_id}")
async def get_capability(
    capability_id: str,
    api_key: str = Header(None),
):
    """Get a specific capability."""
    verify_api_key(api_key)
    platform = get_nexus_platform()
    
    capability = platform.get_capability(capability_id)
    if not capability:
        raise HTTPException(status_code=404, detail="Capability not found")
    
    return {"capability": capability.to_dict()}


@router.post("/analysis/cross-layer")
async def cross_layer_analysis(
    request: CrossLayerAnalysisRequest,
    api_key: str = Header(None),
):
    """Perform cross-layer analysis."""
    verify_api_key(api_key)
    platform = get_nexus_platform()
    
    layers = None
    if request.layers:
        layers = []
        for layer_str in request.layers:
            try:
                layers.append(IntelligenceLayer(layer_str))
            except ValueError:
                raise HTTPException(status_code=400, detail=f"Invalid layer: {layer_str}")
    
    analysis = platform.cross_layer_analysis(
        entity_id=request.entity_id,
        layers=layers,
    )
    
    return {"analysis": analysis.to_dict()}


@router.get("/status")
async def get_platform_status(api_key: str = Header(None)):
    """Get overall platform status."""
    verify_api_key(api_key)
    platform = get_nexus_platform()
    
    connected = sum(
        1 for s in platform.layer_statuses.values()
        if s.status == IntegrationStatus.CONNECTED
    )
    
    total = len(platform.layer_statuses)
    
    return {
        "platform_id": platform.platform_id,
        "status": platform.status.value,
        "layers_connected": connected,
        "layers_total": total,
        "health_percentage": (connected / total * 100) if total > 0 else 0,
    }


@router.get("/integrations")
async def get_integrations(api_key: str = Header(None)):
    """Get all integrations."""
    verify_api_key(api_key)
    platform = get_nexus_platform()
    
    integrations = []
    for layer in IntelligenceLayer:
        status = platform.get_layer_status(layer)
        integrations.append({
            "layer": layer.value,
            "status": status.status.value,
            "available": True,
            "last_sync": status.last_sync.isoformat(),
        })
    
    return {
        "count": len(integrations),
        "integrations": integrations,
    }