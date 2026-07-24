from fastapi import APIRouter, Depends, HTTPException, Header
from typing import List, Dict, Any
from .schemas import SecurityIntelligenceNexusGlobalIntelligenceHubStateCreateSchema, SecurityIntelligenceNexusUnifiedAnalyticsReportCreateSchema, SecurityIntelligenceNexusIntelligenceRouteCreateSchema
from .store import get_store, SecurityIntelligenceNexusStore
from .service import SecurityIntelligenceNexusService
from .analytics import SecurityIntelligenceNexusAnalytics
from src.api.security import require_role, Role

router = APIRouter(prefix="/api/v1/phase70", tags=["Phase 70: Enterprise Security Intelligence Nexus 2.0"])


def resolve_tenant(x_api_key: str = Header(...)) -> str:
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Missing API key")
    if x_api_key.startswith("tenant_"):
        return x_api_key.split("_", 1)[1]
    return "system"


def get_svc(store: SecurityIntelligenceNexusStore = Depends(get_store)) -> SecurityIntelligenceNexusService:
    return SecurityIntelligenceNexusService(store)



@router.post("/records", dependencies=[Depends(require_role(Role.ADMIN))])
def create_record(
    payload: SecurityIntelligenceNexusGlobalIntelligenceHubStateCreateSchema,
    tenant_id: str = Depends(resolve_tenant),
    svc: SecurityIntelligenceNexusService = Depends(get_svc)
):
    if tenant_id != "system" and payload.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Tenant mismatch")
    item = svc.create_globalintelligencehubstate(
        tenant_id=payload.tenant_id,
        record_id=payload.record_id, hub_id=payload.hub_id, connected_domains=payload.connected_domains, ingestion_rate=payload.ingestion_rate, is_healthy=payload.is_healthy
    )
    return {"status": "RECORD_CREATED", "record_id": item.record_id}


@router.get("/records", dependencies=[Depends(require_role(Role.ADMIN))])
def list_records(
    tenant_id: str = Depends(resolve_tenant),
    svc: SecurityIntelligenceNexusService = Depends(get_svc)
):
    records = svc.list_globalintelligencehubstates(tenant_id)
    return {"tenant_id": tenant_id, "count": len(records), "records": [
        {"record_id": r.record_id} for r in records
    ]}


@router.get("/records/{record_id}", dependencies=[Depends(require_role(Role.ADMIN))])
def get_record(
    record_id: str,
    tenant_id: str = Depends(resolve_tenant),
    svc: SecurityIntelligenceNexusService = Depends(get_svc)
):
    record = svc.get_globalintelligencehubstate(tenant_id, record_id)
    if not record:
        raise HTTPException(status_code=404, detail="Record not found")
    return {"record_id": record.record_id}


@router.get("/analytics", dependencies=[Depends(require_role(Role.ADMIN))])
def get_analytics(
    tenant_id: str = Depends(resolve_tenant),
    store: SecurityIntelligenceNexusStore = Depends(get_store)
):
    analytics = SecurityIntelligenceNexusAnalytics(store)
    return analytics.compute_kpis(tenant_id)
