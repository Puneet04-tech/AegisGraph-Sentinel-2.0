from fastapi import APIRouter, Depends, HTTPException, Header
from typing import List, Dict, Any
from .schemas import ThreatForecastingEngineThreatForecastCreateSchema, ThreatForecastingEngineTrendIndicatorCreateSchema, ThreatForecastingEngineCampaignPredictionCreateSchema
from .store import get_store, ThreatForecastingEngineStore
from .service import ThreatForecastingEngineService
from .analytics import ThreatForecastingEngineAnalytics
from src.api.security import require_role, Role

router = APIRouter(prefix="/api/v1/phase67", tags=["Phase 67: Global Threat Forecasting Engine"])


def resolve_tenant(x_api_key: str = Header(...)) -> str:
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Missing API key")
    if x_api_key.startswith("tenant_"):
        return x_api_key.split("_", 1)[1]
    return "system"


def get_svc(store: ThreatForecastingEngineStore = Depends(get_store)) -> ThreatForecastingEngineService:
    return ThreatForecastingEngineService(store)



@router.post("/records", dependencies=[Depends(require_role(Role.ADMIN))])
def create_record(
    payload: ThreatForecastingEngineThreatForecastCreateSchema,
    tenant_id: str = Depends(resolve_tenant),
    svc: ThreatForecastingEngineService = Depends(get_svc)
):
    if tenant_id != "system" and payload.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Tenant mismatch")
    item = svc.create_threatforecast(
        tenant_id=payload.tenant_id,
        record_id=payload.record_id, forecast_id=payload.forecast_id, predicted_threat_type=payload.predicted_threat_type, likelihood=payload.likelihood, target_sectors=payload.target_sectors
    )
    return {"status": "RECORD_CREATED", "record_id": item.record_id}


@router.get("/records", dependencies=[Depends(require_role(Role.ADMIN))])
def list_records(
    tenant_id: str = Depends(resolve_tenant),
    svc: ThreatForecastingEngineService = Depends(get_svc)
):
    records = svc.list_threatforecasts(tenant_id)
    return {"tenant_id": tenant_id, "count": len(records), "records": [
        {"record_id": r.record_id} for r in records
    ]}


@router.get("/records/{record_id}", dependencies=[Depends(require_role(Role.ADMIN))])
def get_record(
    record_id: str,
    tenant_id: str = Depends(resolve_tenant),
    svc: ThreatForecastingEngineService = Depends(get_svc)
):
    record = svc.get_threatforecast(tenant_id, record_id)
    if not record:
        raise HTTPException(status_code=404, detail="Record not found")
    return {"record_id": record.record_id}


@router.get("/analytics", dependencies=[Depends(require_role(Role.ADMIN))])
def get_analytics(
    tenant_id: str = Depends(resolve_tenant),
    store: ThreatForecastingEngineStore = Depends(get_store)
):
    analytics = ThreatForecastingEngineAnalytics(store)
    return analytics.compute_kpis(tenant_id)
