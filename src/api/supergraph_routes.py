"""
Supergraph API Routes
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Header, Query
from pydantic import BaseModel

from src.threat_supergraph import (
    ThreatSupergraphEngine,
    get_supergraph_engine,
    EntityResolutionEngine,
    get_entity_resolution_engine,
    CrossDomainCorrelationEngine,
    get_correlation_engine,
    GlobalIntelligenceDashboard,
    get_dashboard,
    EntityType,
    RelationshipType,
    ConfidenceLevel,
    SupergraphNode,
    SupergraphEdge,
)


router = APIRouter(prefix="/api/v1/supergraph", tags=["supergraph"])


class EntityCreateRequest(BaseModel):
    """Request to create an entity."""
    entity_type: str
    name: str
    properties: Optional[Dict[str, Any]] = None
    threat_score: float = 0.0
    risk_level: str = "UNKNOWN"
    tags: Optional[List[str]] = None


class EdgeCreateRequest(BaseModel):
    """Request to create an edge."""
    source_id: str
    target_id: str
    relationship: str
    confidence: str = "UNKNOWN"
    weight: float = 1.0
    evidence: Optional[List[str]] = None
    properties: Optional[Dict[str, Any]] = None


class CorrelationRequest(BaseModel):
    """Request to create a correlation."""
    source_domain: str
    target_domain: str
    source_id: str
    target_id: str
    correlation_type: str
    confidence: str = "POSSIBLE"
    evidence: Optional[List[str]] = None


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
        "module": "threat_supergraph",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/stats")
async def get_stats(api_key: str = Header(None)):
    """Get supergraph statistics."""
    verify_api_key(api_key)
    engine = get_supergraph_engine()
    stats = engine.store.get_graph_stats()
    return {"stats": stats}


@router.post("/entities")
async def create_entity(
    request: EntityCreateRequest,
    api_key: str = Header(None),
):
    """Create a new entity in the supergraph."""
    verify_api_key(api_key)
    engine = get_supergraph_engine()
    
    entity_type = EntityType(request.entity_type)
    
    entity_id = engine.add_entity(
        entity_type=entity_type,
        name=request.name,
        properties=request.properties,
        threat_score=request.threat_score,
        risk_level=request.risk_level,
        tags=request.tags,
    )
    
    return {
        "entity_id": entity_id,
        "status": "created",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/entities/{entity_id}")
async def get_entity(
    entity_id: str,
    api_key: str = Header(None),
):
    """Get an entity by ID."""
    verify_api_key(api_key)
    engine = get_supergraph_engine()
    
    node = engine.store.get_node(entity_id)
    if not node:
        raise HTTPException(status_code=404, detail="Entity not found")
    
    return {"entity": node.to_dict()}


@router.post("/edges")
async def create_edge(
    request: EdgeCreateRequest,
    api_key: str = Header(None),
):
    """Create a new edge in the supergraph."""
    verify_api_key(api_key)
    engine = get_supergraph_engine()
    
    relationship = RelationshipType(request.relationship)
    confidence = ConfidenceLevel(request.confidence)
    
    edge_id = engine.connect_entities(
        source_id=request.source_id,
        target_id=request.target_id,
        relationship=relationship,
        confidence=confidence,
        weight=request.weight,
        evidence=request.evidence,
        properties=request.properties,
    )
    
    return {
        "edge_id": edge_id,
        "status": "created",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/entities/{entity_id}/cluster")
async def get_entity_cluster(
    entity_id: str,
    depth: int = Query(default=2, ge=1, le=5),
    api_key: str = Header(None),
):
    """Get the cluster of entities connected to an entity."""
    verify_api_key(api_key)
    engine = get_supergraph_engine()
    
    cluster = engine.get_entity_cluster(entity_id, depth=depth)
    
    return {
        "entity_id": entity_id,
        "cluster_size": len(cluster),
        "entities": [node.to_dict() for node in cluster],
    }


@router.get("/entities/{entity_id}/path/{target_id}")
async def find_path(
    entity_id: str,
    target_id: str,
    max_hops: int = Query(default=5, ge=1, le=10),
    api_key: str = Header(None),
):
    """Find paths between two entities."""
    verify_api_key(api_key)
    engine = get_supergraph_engine()
    
    paths = engine.find_entity_path(entity_id, target_id, max_hops=max_hops)
    
    return {
        "source_id": entity_id,
        "target_id": target_id,
        "path_count": len(paths),
        "paths": paths,
    }


@router.get("/entities/{entity_id}/risk")
async def get_entity_risk(
    entity_id: str,
    api_key: str = Header(None),
):
    """Get risk score for an entity."""
    verify_api_key(api_key)
    engine = get_supergraph_engine()
    
    risk_score = engine.get_risk_score(entity_id)
    
    return {
        "entity_id": entity_id,
        "risk_score": risk_score,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.post("/correlations")
async def create_correlation(
    request: CorrelationRequest,
    api_key: str = Header(None),
):
    """Create a cross-domain correlation."""
    verify_api_key(api_key)
    engine = get_correlation_engine()
    
    confidence = ConfidenceLevel(request.confidence)
    
    correlation_id = engine.correlate(
        source_domain=request.source_domain,
        target_domain=request.target_domain,
        source_id=request.source_id,
        target_id=request.target_id,
        correlation_type=request.correlation_type,
        confidence=confidence,
        evidence=request.evidence,
    )
    
    return {
        "correlation_id": correlation_id,
        "status": "created",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/entities/{entity_id}/correlations")
async def get_entity_correlations(
    entity_id: str,
    domain: Optional[str] = None,
    api_key: str = Header(None),
):
    """Get correlations for an entity."""
    verify_api_key(api_key)
    engine = get_correlation_engine()
    
    correlations = engine.find_correlations(entity_id, domain=domain)
    
    return {
        "entity_id": entity_id,
        "correlation_count": len(correlations),
        "correlations": correlations,
    }


@router.get("/dashboard")
async def get_dashboard_data(
    time_range_days: int = Query(default=30, ge=1, le=365),
    api_key: str = Header(None),
):
    """Get the global intelligence dashboard."""
    verify_api_key(api_key)
    dashboard = get_dashboard()
    
    data = dashboard.generate_dashboard(time_range_days=time_range_days)
    
    return data


@router.get("/entities/{entity_id}/insights")
async def get_entity_insights(
    entity_id: str,
    api_key: str = Header(None),
):
    """Get detailed insights for an entity."""
    verify_api_key(api_key)
    dashboard = get_dashboard()
    
    insights = dashboard.get_entity_insights(entity_id)
    
    return insights


@router.get("/resolution/stats")
async def get_resolution_stats(api_key: str = Header(None)):
    """Get entity resolution statistics."""
    verify_api_key(api_key)
    engine = get_entity_resolution_engine()
    
    stats = engine.get_resolution_stats()
    
    return {"stats": stats}


@router.get("/correlation/stats")
async def get_correlation_stats(api_key: str = Header(None)):
    """Get cross-domain correlation statistics."""
    verify_api_key(api_key)
    engine = get_correlation_engine()
    
    stats = engine.get_domain_stats()
    
    return {"stats": stats}