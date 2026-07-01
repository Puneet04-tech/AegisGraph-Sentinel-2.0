from fastapi import APIRouter, Depends, HTTPException, Header
from typing import List, Dict, Any
from .schemas import DecisionIntelligencePlatformDecisionContextCreateSchema, DecisionIntelligencePlatformExplainabilityReportCreateSchema, DecisionIntelligencePlatformRiskRecommendationCreateSchema
from .store import get_store, DecisionIntelligencePlatformStore
from .service import DecisionIntelligencePlatformService
from .analytics import DecisionIntelligencePlatformAnalytics
from src.api.security import require_role, Role

router = APIRouter(prefix="/api/v1/phase63", tags=["Phase 63: Enterprise Security Decision Intelligence Platform"])


def resolve_tenant(x_api_key: str = Header(...)) -> str:
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Missing API key")
    if x_api_key.startswith("tenant_"):
        return x_api_key.split("_", 1)[1]
    return "system"


def get_svc(store: DecisionIntelligencePlatformStore = Depends(get_store)) -> DecisionIntelligencePlatformService:
    return DecisionIntelligencePlatformService(store)



@router.post("/records", dependencies=[Depends(require_role(Role.ADMIN))])
def create_record(
    payload: DecisionIntelligencePlatformDecisionContextCreateSchema,
    tenant_id: str = Depends(resolve_tenant),
    svc: DecisionIntelligencePlatformService = Depends(get_svc)
):
    if tenant_id != "system" and payload.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Tenant mismatch")
    item = svc.create_decisioncontext(
        tenant_id=payload.tenant_id,
        record_id=payload.record_id, decision_id=payload.decision_id, action_taken=payload.action_taken, rationales=payload.rationales, confidence=payload.confidence
    )
    return {"status": "RECORD_CREATED", "record_id": item.record_id}


@router.get("/records", dependencies=[Depends(require_role(Role.ADMIN))])
def list_records(
    tenant_id: str = Depends(resolve_tenant),
    svc: DecisionIntelligencePlatformService = Depends(get_svc)
):
    records = svc.list_decisioncontexts(tenant_id)
    return {"tenant_id": tenant_id, "count": len(records), "records": [
        {"record_id": r.record_id} for r in records
    ]}


@router.get("/records/{record_id}", dependencies=[Depends(require_role(Role.ADMIN))])
def get_record(
    record_id: str,
    tenant_id: str = Depends(resolve_tenant),
    svc: DecisionIntelligencePlatformService = Depends(get_svc)
):
    record = svc.get_decisioncontext(tenant_id, record_id)
    if not record:
        raise HTTPException(status_code=404, detail="Record not found")
    return {"record_id": record.record_id}


@router.get("/analytics", dependencies=[Depends(require_role(Role.ADMIN))])
def get_analytics(
    tenant_id: str = Depends(resolve_tenant),
    store: DecisionIntelligencePlatformStore = Depends(get_store)
):
    analytics = DecisionIntelligencePlatformAnalytics(store)
    return analytics.compute_kpis(tenant_id)
