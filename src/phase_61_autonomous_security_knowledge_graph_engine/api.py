from fastapi import APIRouter, Depends, HTTPException
from typing import List, Dict, Any
from .schemas import SecurityKnowledgeGraphEntityRelationCreateSchema, SecurityKnowledgeGraphRiskPropagationPathCreateSchema, SecurityKnowledgeGraphFederatedKnowledgeNodeCreateSchema
from .store import get_store, SecurityKnowledgeGraphStore
from .service import SecurityKnowledgeGraphService
from .analytics import SecurityKnowledgeGraphAnalytics
from src.api.security import require_role, Role
from src.api.tenant_dependency import resolve_tenant

router = APIRouter(prefix="/api/v1/phase61", tags=["Phase 61: Autonomous Security Knowledge Graph Engine"])


def get_svc(store: SecurityKnowledgeGraphStore = Depends(get_store)) -> SecurityKnowledgeGraphService:
    return SecurityKnowledgeGraphService(store)



@router.post("/records", dependencies=[Depends(require_role(Role.ADMIN))])
def create_record(
    payload: SecurityKnowledgeGraphEntityRelationCreateSchema,
    tenant_id: str = Depends(resolve_tenant),
    svc: SecurityKnowledgeGraphService = Depends(get_svc)
):
    if payload.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Tenant mismatch")
    item = svc.create_entityrelation(
        tenant_id=payload.tenant_id,
        record_id=payload.record_id, relation_id=payload.relation_id, source_entity=payload.source_entity, target_entity=payload.target_entity, relation_type=payload.relation_type, confidence=payload.confidence
    )
    return {"status": "RECORD_CREATED", "record_id": item.record_id}


@router.get("/records", dependencies=[Depends(require_role(Role.ADMIN))])
def list_records(
    tenant_id: str = Depends(resolve_tenant),
    svc: SecurityKnowledgeGraphService = Depends(get_svc)
):
    records = svc.list_entityrelations(tenant_id)
    return {"tenant_id": tenant_id, "count": len(records), "records": [
        {"record_id": r.record_id} for r in records
    ]}


@router.get("/records/{record_id}", dependencies=[Depends(require_role(Role.ADMIN))])
def get_record(
    record_id: str,
    tenant_id: str = Depends(resolve_tenant),
    svc: SecurityKnowledgeGraphService = Depends(get_svc)
):
    record = svc.get_entityrelation(tenant_id, record_id)
    if not record:
        raise HTTPException(status_code=404, detail="Record not found")
    return {"record_id": record.record_id}


@router.get("/analytics", dependencies=[Depends(require_role(Role.ADMIN))])
def get_analytics(
    tenant_id: str = Depends(resolve_tenant),
    store: SecurityKnowledgeGraphStore = Depends(get_store)
):
    analytics = SecurityKnowledgeGraphAnalytics(store)
    return analytics.compute_kpis(tenant_id)
