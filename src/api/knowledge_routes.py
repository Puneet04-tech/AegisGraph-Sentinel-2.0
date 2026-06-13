"""
Knowledge Operating System API Routes
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Header, Query
from pydantic import BaseModel

from src.knowledge_os import (
    KnowledgeEngine,
    get_knowledge_engine,
    KnowledgeType,
    KnowledgeStatus,
    AccessLevel,
    KnowledgeGraphManager,
    KnowledgeRetrievalEngine,
)


router = APIRouter(prefix="/api/v1/knowledge", tags=["knowledge"])


class StoreRequest(BaseModel):
    """Request to store knowledge."""
    title: str
    content: str
    knowledge_type: str
    tags: List[str] = []
    access_level: str = "PUBLIC"
    created_by: str = ""


class SearchRequest(BaseModel):
    """Request to search knowledge."""
    query: str
    knowledge_type: Optional[str] = None
    tags: Optional[List[str]] = None
    access_level: Optional[str] = None
    limit: int = 10


class GraphCreateRequest(BaseModel):
    """Request to create a graph."""
    name: str
    entry_ids: List[str] = []


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
        "module": "knowledge_os",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.post("/store")
async def store_knowledge(
    request: StoreRequest,
    api_key: str = Header(None),
):
    """Store a new knowledge entry."""
    verify_api_key(api_key)
    engine = get_knowledge_engine()
    
    try:
        ktype = KnowledgeType(request.knowledge_type)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid knowledge type")
    
    try:
        alevel = AccessLevel(request.access_level)
    except ValueError:
        alevel = AccessLevel.PUBLIC
    
    entry_id = engine.store_entry(
        title=request.title,
        content=request.content,
        knowledge_type=ktype,
        created_by=request.created_by,
        tags=request.tags,
        access_level=alevel,
    )
    
    return {
        "entry_id": entry_id,
        "status": "stored",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.post("/search")
async def search_knowledge(
    request: SearchRequest,
    api_key: str = Header(None),
):
    """Search knowledge entries."""
    verify_api_key(api_key)
    engine = get_knowledge_engine()
    
    ktype = None
    if request.knowledge_type:
        try:
            ktype = KnowledgeType(request.knowledge_type)
        except ValueError:
            pass
    
    alevel = None
    if request.access_level:
        try:
            alevel = AccessLevel(request.access_level)
        except ValueError:
            pass
    
    results = engine.search(
        query=request.query,
        knowledge_type=ktype,
        tags=request.tags,
        access_level=alevel,
        limit=request.limit,
    )
    
    return {
        "count": len(results),
        "results": [e.to_dict() for e in results],
    }


@router.get("/retrieve/{entry_id}")
async def retrieve_knowledge(
    entry_id: str,
    api_key: str = Header(None),
):
    """Retrieve a knowledge entry."""
    verify_api_key(api_key)
    engine = get_knowledge_engine()
    
    entry = engine.get_entry(entry_id)
    if not entry:
        raise HTTPException(status_code=404, detail="Entry not found")
    
    return {"entry": entry.to_dict()}


@router.get("/entries")
async def list_entries(
    knowledge_type: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = Query(default=50, ge=1, le=100),
    api_key: str = Header(None),
):
    """List all knowledge entries."""
    verify_api_key(api_key)
    engine = get_knowledge_engine()
    
    entries = list(engine.entries.values())
    
    if knowledge_type:
        try:
            ktype = KnowledgeType(knowledge_type)
            entries = [e for e in entries if e.knowledge_type == ktype]
        except ValueError:
            pass
    
    if status:
        try:
            st = KnowledgeStatus(status)
            entries = [e for e in entries if e.status == st]
        except ValueError:
            pass
    
    return {
        "count": len(entries),
        "entries": [e.to_dict() for e in entries[:limit]],
    }


@router.patch("/entries/{entry_id}")
async def update_entry(
    entry_id: str,
    status: Optional[str] = None,
    content: Optional[str] = None,
    tags: Optional[List[str]] = None,
    api_key: str = Header(None),
):
    """Update a knowledge entry."""
    verify_api_key(api_key)
    engine = get_knowledge_engine()
    
    st = KnowledgeStatus(status) if status else None
    
    success = engine.update_entry(
        entry_id=entry_id,
        status=st,
        content=content,
        tags=tags,
    )
    
    if not success:
        raise HTTPException(status_code=404, detail="Entry not found")
    
    return {"status": "updated"}


@router.post("/graph/create")
async def create_graph(
    request: GraphCreateRequest,
    api_key: str = Header(None),
):
    """Create a knowledge graph."""
    verify_api_key(api_key)
    
    engine = get_knowledge_engine()
    graph_manager = KnowledgeGraphManager(engine)
    
    graph_id = graph_manager.create_graph(
        name=request.name,
        entry_ids=request.entry_ids,
    )
    
    return {
        "graph_id": graph_id,
        "status": "created",
    }


@router.get("/graph/{graph_id}")
async def get_graph(
    graph_id: str,
    api_key: str = Header(None),
):
    """Get a knowledge graph."""
    verify_api_key(api_key)
    
    engine = get_knowledge_engine()
    graph_manager = KnowledgeGraphManager(engine)
    
    graph = graph_manager.get_graph(graph_id)
    if not graph:
        raise HTTPException(status_code=404, detail="Graph not found")
    
    return {"graph": graph.to_dict()}


@router.post("/correlate")
async def correlate_entries(
    entry_ids: List[str],
    api_key: str = Header(None),
):
    """Correlate knowledge entries."""
    verify_api_key(api_key)
    
    engine = get_knowledge_engine()
    graph_manager = KnowledgeGraphManager(engine)
    
    correlations = graph_manager.correlate_entries(entry_ids)
    
    return {
        "count": len(correlations),
        "correlations": correlations,
    }


@router.get("/recommendations")
async def get_recommendations(
    user_id: str = Query(...),
    context: Optional[Dict[str, Any]] = None,
    limit: int = Query(default=5, ge=1, le=20),
    api_key: str = Header(None),
):
    """Get knowledge recommendations."""
    verify_api_key(api_key)
    
    engine = get_knowledge_engine()
    retrieval = KnowledgeRetrievalEngine(engine)
    
    recommendations = retrieval.get_recommendations(
        user_id=user_id,
        context=context or {},
        limit=limit,
    )
    
    return {
        "count": len(recommendations),
        "recommendations": [r.to_dict() for r in recommendations],
    }


@router.get("/related/{entry_id}")
async def get_related(
    entry_id: str,
    api_key: str = Header(None),
):
    """Get related knowledge entries."""
    verify_api_key(api_key)
    engine = get_knowledge_engine()
    
    related = engine.get_related(entry_id)
    
    return {
        "count": len(related),
        "entries": [e.to_dict() for e in related],
    }