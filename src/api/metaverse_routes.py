"""
Metaverse Intelligence API Routes
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Header, Query
from pydantic import BaseModel

from src.api.security import verify_api_key
from src.metaverse_intelligence import (
    VisualizationEngine,
    get_visualization_engine,
    FraudRingDiscovery,
    InvestigationManager,
    get_fraud_ring_discovery,
    get_investigation_manager,
    VisualizationType,
    InvestigationStatus,
)


router = APIRouter(prefix="/api/v1/metaverse", tags=["metaverse"])


class VisualizationRequest(BaseModel):
    """Request to create a visualization."""
    title: str
    visualization_type: str
    entities: List[Dict[str, Any]]
    connections: Optional[List[Dict[str, Any]]] = None
    events: Optional[List[Dict[str, Any]]] = None
    heatmap_data: Optional[Dict[str, float]] = None


class CaseCreateRequest(BaseModel):
    """Request to create a case."""
    title: str
    description: str
    priority: str = "MEDIUM"


class FraudRingRequest(BaseModel):
    """Request to discover fraud ring."""
    entities: List[Dict[str, Any]]
    connections: List[Dict[str, Any]]
    threshold: float = 0.7


class TimelineEventRequest(BaseModel):
    """Request to add timeline event."""
    event_type: str
    title: str
    description: Optional[str] = None
    data: Optional[Dict[str, Any]] = None


@router.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "module": "metaverse_intelligence",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.post("/visualizations/network")
async def create_network_graph(
    request: VisualizationRequest,
    api_key: str = Header(None),
):
    """Create a network graph visualization."""
    verify_api_key(api_key)
    engine = get_visualization_engine()
    
    scene = engine.create_network_graph(
        title=request.title,
        entities=request.entities,
        relationships=request.connections or [],
    )
    
    return {"scene": scene.to_dict()}


@router.post("/visualizations/3d")
async def create_3d_graph(
    request: VisualizationRequest,
    api_key: str = Header(None),
):
    """Create a 3D graph visualization."""
    verify_api_key(api_key)
    engine = get_visualization_engine()
    
    scene = engine.create_3d_graph(
        title=request.title,
        entities=request.entities,
        connections=request.connections or [],
    )
    
    return {"scene": scene.to_dict()}


@router.post("/visualizations/timeline")
async def create_timeline(
    request: VisualizationRequest,
    api_key: str = Header(None),
):
    """Create a timeline visualization."""
    verify_api_key(api_key)
    engine = get_visualization_engine()
    
    scene = engine.create_timeline(
        title=request.title,
        events=request.events or [],
    )
    
    return {"scene": scene.to_dict()}


@router.post("/visualizations/heatmap")
async def create_heatmap(
    request: VisualizationRequest,
    api_key: str = Header(None),
):
    """Create a heatmap visualization."""
    verify_api_key(api_key)
    engine = get_visualization_engine()
    
    scene = engine.create_heatmap(
        title=request.title,
        data=request.heatmap_data or {},
    )
    
    return {"scene": scene.to_dict()}


@router.get("/visualizations/{scene_id}")
async def get_visualization(
    scene_id: str,
    api_key: str = Header(None),
):
    """Get a visualization scene by ID."""
    verify_api_key(api_key)
    engine = get_visualization_engine()
    
    scene = engine.get_scene(scene_id)
    if not scene:
        raise HTTPException(status_code=404, detail="Scene not found")
    
    return {"scene": scene.to_dict()}


@router.get("/rings")
async def list_fraud_rings(
    min_risk: float = Query(default=0.0, ge=0, le=1),
    api_key: str = Header(None),
):
    """List fraud rings."""
    verify_api_key(api_key)
    discovery = get_fraud_ring_discovery()
    
    rings = discovery.get_all_rings()
    if min_risk > 0:
        rings = [r for r in rings if r.risk_score >= min_risk]
    
    return {
        "count": len(rings),
        "rings": [r.to_dict() for r in rings],
    }


@router.post("/rings/discover")
async def discover_fraud_ring(
    request: FraudRingRequest,
    api_key: str = Header(None),
):
    """Discover a fraud ring."""
    verify_api_key(api_key)
    discovery = get_fraud_ring_discovery()
    
    ring = discovery.discover_ring(
        entities=request.entities,
        connections=request.connections,
        threshold=request.threshold,
    )
    
    return {"ring": ring.to_dict()}


@router.get("/rings/{ring_id}")
async def get_fraud_ring(
    ring_id: str,
    api_key: str = Header(None),
):
    """Get a fraud ring by ID."""
    verify_api_key(api_key)
    discovery = get_fraud_ring_discovery()
    
    ring = discovery.get_ring(ring_id)
    if not ring:
        raise HTTPException(status_code=404, detail="Ring not found")
    
    return {"ring": ring.to_dict()}


@router.get("/rings/{ring_id}/analysis")
async def analyze_fraud_ring(
    ring_id: str,
    api_key: str = Header(None),
):
    """Analyze a fraud ring."""
    verify_api_key(api_key)
    discovery = get_fraud_ring_discovery()
    
    analysis = discovery.analyze_ring_connections(ring_id)
    
    return analysis


@router.get("/cases")
async def list_cases(
    status: Optional[str] = None,
    api_key: str = Header(None),
):
    """List investigation cases."""
    verify_api_key(api_key)
    manager = get_investigation_manager()
    
    cases = manager.get_active_cases() if status == "ACTIVE" else list(manager.cases.values())
    
    return {
        "count": len(cases),
        "cases": [c.to_dict() for c in cases],
    }


@router.post("/cases")
async def create_case(
    request: CaseCreateRequest,
    api_key: str = Header(None),
):
    """Create a new investigation case."""
    verify_api_key(api_key)
    manager = get_investigation_manager()
    
    case = manager.create_case(
        title=request.title,
        description=request.description,
        priority=request.priority,
    )
    
    return {"case": case.to_dict()}


@router.get("/cases/{case_id}")
async def get_case(
    case_id: str,
    api_key: str = Header(None),
):
    """Get a case by ID."""
    verify_api_key(api_key)
    manager = get_investigation_manager()
    
    case = manager.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    
    return {"case": case.to_dict()}


@router.patch("/cases/{case_id}")
async def update_case(
    case_id: str,
    status: Optional[str] = None,
    api_key: str = Header(None),
):
    """Update a case."""
    verify_api_key(api_key)
    manager = get_investigation_manager()
    
    status_enum = InvestigationStatus(status) if status else None
    success = manager.update_case(case_id, status=status_enum)
    
    if not success:
        raise HTTPException(status_code=404, detail="Case not found")
    
    return {"status": "updated"}


@router.post("/cases/{case_id}/timeline")
async def add_timeline_event(
    case_id: str,
    request: TimelineEventRequest,
    api_key: str = Header(None),
):
    """Add a timeline event to a case."""
    verify_api_key(api_key)
    manager = get_investigation_manager()
    
    event = {
        "type": request.event_type,
        "title": request.title,
        "description": request.description,
        "data": request.data,
    }
    
    success = manager.add_timeline_event(case_id, event)
    
    if not success:
        raise HTTPException(status_code=404, detail="Case not found")
    
    return {"status": "event_added"}