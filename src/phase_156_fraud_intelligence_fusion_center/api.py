from fastapi import APIRouter, Depends, HTTPException, Header
from typing import List, Dict, Any
from .schemas import FraudIntelligenceFusionCenterCreateSchema, FraudIntelligenceFusionCenterAlertSchema
from .store import get_store, FraudIntelligenceFusionCenterStore
from .service import FraudIntelligenceFusionCenterService
from .analytics import FraudIntelligenceFusionCenterAnalytics
from src.api.security import require_role, Role

router = APIRouter(prefix="/api/v1/phase156", tags=["Phase 156: Fraud Intelligence Fusion Center"])


def resolve_tenant(x_api_key: str = Header(...)) -> str:
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Missing API key")
    if x_api_key.startswith("tenant_"):
        return x_api_key.split("_", 1)[1]
    return "system"


def get_svc(store: FraudIntelligenceFusionCenterStore = Depends(get_store)) -> FraudIntelligenceFusionCenterService:
    return FraudIntelligenceFusionCenterService(store)


@router.post("/records", dependencies=[Depends(require_role(Role.ADMIN))])
def create_record(
    payload: FraudIntelligenceFusionCenterCreateSchema,
    tenant_id: str = Depends(resolve_tenant),
    svc: FraudIntelligenceFusionCenterService = Depends(get_svc)
):
    if tenant_id != "system" and payload.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Tenant mismatch")
    record = svc.create_record(
        tenant_id=payload.tenant_id,
        record_id=payload.record_id,
        name=payload.name,
        status=payload.status,
        metadata=payload.metadata or {}
    )
    return {"status": "RECORD_CREATED", "record_id": record.record_id}


@router.get("/records", dependencies=[Depends(require_role(Role.ADMIN))])
def list_records(
    tenant_id: str = Depends(resolve_tenant),
    svc: FraudIntelligenceFusionCenterService = Depends(get_svc)
):
    records = svc.list_records(tenant_id)
    return {"tenant_id": tenant_id, "count": len(records), "records": [
        {"record_id": r.record_id, "name": r.name, "status": r.status} for r in records
    ]}


@router.get("/records/{record_id}", dependencies=[Depends(require_role(Role.ADMIN))])
def get_record(
    record_id: str,
    tenant_id: str = Depends(resolve_tenant),
    svc: FraudIntelligenceFusionCenterService = Depends(get_svc)
):
    record = svc.get_record(tenant_id, record_id)
    if not record:
        raise HTTPException(status_code=404, detail="Record not found")
    return {"record_id": record.record_id, "name": record.name, "status": record.status}


@router.post("/alerts", dependencies=[Depends(require_role(Role.ADMIN))])
def create_alert(
    payload: FraudIntelligenceFusionCenterAlertSchema,
    tenant_id: str = Depends(resolve_tenant),
    svc: FraudIntelligenceFusionCenterService = Depends(get_svc)
):
    alert = svc.create_alert(
        tenant_id=tenant_id,
        alert_id=payload.alert_id,
        title=payload.title,
        severity=payload.severity
    )
    return {"status": "ALERT_CREATED", "alert_id": alert.alert_id}


@router.get("/analytics", dependencies=[Depends(require_role(Role.ADMIN))])
def get_analytics(
    tenant_id: str = Depends(resolve_tenant),
    store: FraudIntelligenceFusionCenterStore = Depends(get_store)
):
    analytics = FraudIntelligenceFusionCenterAnalytics(store)
    return analytics.compute_kpis(tenant_id)
