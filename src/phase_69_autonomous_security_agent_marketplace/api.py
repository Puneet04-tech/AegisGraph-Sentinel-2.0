from fastapi import APIRouter, Depends, HTTPException, Header
from typing import List, Dict, Any
from .schemas import SecurityAgentMarketplaceAgentRegistrationCreateSchema, SecurityAgentMarketplaceOrchestrationSessionCreateSchema, SecurityAgentMarketplaceAgentCapabilityCreateSchema
from .store import get_store, SecurityAgentMarketplaceStore
from .service import SecurityAgentMarketplaceService
from .analytics import SecurityAgentMarketplaceAnalytics

router = APIRouter(prefix="/api/v1/phase69", tags=["Phase 69: Autonomous Security Agent Marketplace"])


def verify_auth(x_api_key: str = Header(...)) -> str:
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Missing API key")
    if x_api_key.startswith("tenant_"):
        return x_api_key.split("_", 1)[1]
    elif x_api_key == "SUPER_ADMIN":
        return "system"
    raise HTTPException(status_code=403, detail="Unauthorized")


def get_svc(store: SecurityAgentMarketplaceStore = Depends(get_store)) -> SecurityAgentMarketplaceService:
    return SecurityAgentMarketplaceService(store)



@router.post("/records")
def create_record(
    payload: SecurityAgentMarketplaceAgentRegistrationCreateSchema,
    tenant_id: str = Depends(verify_auth),
    svc: SecurityAgentMarketplaceService = Depends(get_svc)
):
    if tenant_id != "system" and payload.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Tenant mismatch")
    item = svc.create_agentregistration(
        tenant_id=payload.tenant_id,
        record_id=payload.record_id, agent_id=payload.agent_id, agent_name=payload.agent_name, capabilities=payload.capabilities, status=payload.status
    )
    return {"status": "RECORD_CREATED", "record_id": item.record_id}


@router.get("/records")
def list_records(
    tenant_id: str = Depends(verify_auth),
    svc: SecurityAgentMarketplaceService = Depends(get_svc)
):
    records = svc.list_agentregistrations(tenant_id)
    return {"tenant_id": tenant_id, "count": len(records), "records": [
        {"record_id": r.record_id} for r in records
    ]}


@router.get("/records/{record_id}")
def get_record(
    record_id: str,
    tenant_id: str = Depends(verify_auth),
    svc: SecurityAgentMarketplaceService = Depends(get_svc)
):
    record = svc.get_agentregistration(tenant_id, record_id)
    if not record:
        raise HTTPException(status_code=404, detail="Record not found")
    return {"record_id": record.record_id}


@router.get("/analytics")
def get_analytics(
    tenant_id: str = Depends(verify_auth),
    store: SecurityAgentMarketplaceStore = Depends(get_store)
):
    analytics = SecurityAgentMarketplaceAnalytics(store)
    return analytics.compute_kpis(tenant_id)
