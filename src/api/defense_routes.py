"""
API routes for Autonomous Enterprise Defense Grid.

Provides endpoints for autonomous defense, containment, and self-healing.
"""

from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from ..security import require_api_key, Role, require_role


router = APIRouter(prefix="/api/v1/defense", tags=["Defense Grid"])


# Request/Response Models
class ThreatReport(BaseModel):
    type: str
    severity: str
    source: Optional[str] = None
    affected_entities: List[str] = []
    metadata: dict = {}


class ContainmentRequest(BaseModel):
    target_entity: str
    containment_type: str
    duration_seconds: int = 3600
    reason: str = ""


class HealingRequest(BaseModel):
    entity_id: str
    entity_type: str
    healing_type: str = "AUTO"


class PolicyCreate(BaseModel):
    name: str
    type: str
    description: str = ""
    priority: str = "MEDIUM"
    conditions: dict = {}
    actions: List[dict] = []


# Store dependency
def get_defense_store():
    from src.defense_grid import get_defense_store
    return get_defense_store()


def get_defense_controller():
    from src.defense_grid import get_defense_controller
    return get_defense_controller()


def get_self_healing():
    from src.defense_grid import get_self_healing_engine
    return get_self_healing_engine()


# Endpoints
@router.get("/status")
async def get_defense_status(
    controller=Depends(get_defense_controller),
):
    """Get defense grid status."""
    return controller.get_grid_status()


@router.post("/threats/process")
async def process_threat(
    threat: ThreatReport,
    controller=Depends(get_defense_controller),
):
    """Process a detected threat."""
    threat_data = {
        "threat_id": str(hashlib.md5(f"{threat.type}{datetime.now()}".encode()).hexdigest()[:16]),
        "type": threat.type,
        "severity": threat.severity,
        "source": threat.source,
        "affected_entities": threat.affected_entities,
    }
    
    result = controller.process_threat(threat_data)
    return result


@router.get("/containments")
async def list_containments(
    status: Optional[str] = Query(None),
    active_only: bool = Query(False),
    store=Depends(get_defense_store),
):
    """List containment actions."""
    containments = store.list_containment_actions(status=status, active_only=active_only)
    return {"containments": containments, "count": len(containments)}


@router.post("/containments")
async def initiate_containment(
    request: ContainmentRequest,
    controller=Depends(get_defense_controller),
):
    """Initiate containment action."""
    result = controller._initiate_containment(
        entity_id=request.target_entity,
        containment_type=request.containment_type,
        reason=request.reason,
    )
    return result


@router.delete("/containments/{action_id}")
async def release_containment(
    action_id: str,
    controller=Depends(get_defense_controller),
):
    """Release a containment action."""
    result = controller.release_containment(action_id)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


@router.post("/recover")
async def initiate_recovery(
    entity_id: str,
    entity_type: str,
    controller=Depends(get_defense_controller),
):
    """Initiate recovery for an entity."""
    result = controller.initiate_recovery(entity_id, entity_type)
    return result


@router.post("/heal")
async def heal_entity(
    request: HealingRequest,
    healing=Depends(get_self_healing),
):
    """Heal an entity."""
    result = healing.heal_entity(
        entity_id=request.entity_id,
        entity_type=request.entity_type,
        healing_type=request.healing_type,
    )
    return {
        "action_id": result.action_id,
        "action_type": result.action_type,
        "status": result.status,
        "target_entity": result.target_entity,
        "result": result.result,
        "execution_time_ms": result.execution_time_ms,
        "success": result.success,
    }


@router.get("/heal/history")
async def get_healing_history(
    entity_id: Optional[str] = Query(None),
    limit: int = Query(100),
    healing=Depends(get_self_healing),
):
    """Get healing history."""
    history = healing.get_healing_history(entity_id=entity_id, limit=limit)
    return {"history": history, "count": len(history)}


@router.get("/heal/stats")
async def get_healing_stats(
    healing=Depends(get_self_healing),
):
    """Get healing statistics."""
    return healing.get_healing_stats()


@router.get("/policies")
async def list_policies(
    enabled: Optional[bool] = Query(None),
    policy_type: Optional[str] = Query(None),
    store=Depends(get_defense_store),
):
    """List defense policies."""
    policies = store.list_policies(enabled=enabled, policy_type=policy_type)
    return {"policies": policies, "count": len(policies)}


@router.post("/policies")
async def create_policy(
    policy: PolicyCreate,
    store=Depends(get_defense_store),
):
    """Create a new defense policy."""
    policy_data = {
        "name": policy.name,
        "type": policy.type,
        "description": policy.description,
        "priority": policy.priority,
        "conditions": policy.conditions,
        "actions": policy.actions,
        "enabled": True,
    }
    policy_id = store.add_policy(policy_data)
    return {"policy_id": policy_id}


@router.get("/events")
async def list_defense_events(
    severity: Optional[str] = Query(None),
    resolved: Optional[bool] = Query(None),
    limit: int = Query(100),
    store=Depends(get_defense_store),
):
    """List defense events."""
    events = store.list_defense_events(severity=severity, resolved=resolved, limit=limit)
    return {"events": events, "count": len(events)}


@router.get("/nodes")
async def list_grid_nodes(
    status: Optional[str] = Query(None),
    store=Depends(get_defense_store),
):
    """List defense grid nodes."""
    nodes = store.list_grid_nodes(status=status)
    return {"nodes": nodes, "count": len(nodes)}


@router.get("/stats")
async def get_defense_stats(
    store=Depends(get_defense_store),
):
    """Get defense grid statistics."""
    return store.get_defense_stats()


import hashlib
from datetime import datetime