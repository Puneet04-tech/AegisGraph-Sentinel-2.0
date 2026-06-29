from fastapi import APIRouter, Depends, HTTPException, Header
from typing import List, Dict, Any
from .schemas import SecurityDigitalTwinDigitalTwinStateCreateSchema, SecurityDigitalTwinRiskVisualizationNodeCreateSchema, SecurityDigitalTwinForecastingScenarioCreateSchema
from .store import get_store, SecurityDigitalTwinStore
from .service import SecurityDigitalTwinService
from .analytics import SecurityDigitalTwinAnalytics

router = APIRouter(prefix="/api/v1/phase65", tags=["Phase 65: Enterprise Security Digital Twin"])

def verify_auth(x_api_key: str = Header(...)) -> str:
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Missing API key")
    if x_api_key.startswith("tenant_"):
        return x_api_key.split("_", 1)[1]
    elif x_api_key == "SUPER_ADMIN":
        return "system"
    raise HTTPException(status_code=403, detail="Unauthorized")

def get_svc(store: SecurityDigitalTwinStore = Depends(get_store)) -> SecurityDigitalTwinService:
    return SecurityDigitalTwinService(store)

@router.post("/records")
def create_record(
    payload: SecurityDigitalTwinDigitalTwinStateCreateSchema,
    tenant_id: str = Depends(verify_auth),
    svc: SecurityDigitalTwinService = Depends(get_svc)
):
    if tenant_id != "system" and payload.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Tenant mismatch")
    item = svc.create_digitaltwinstate(
        tenant_id=payload.tenant_id,
        record_id=payload.record_id, state_id=payload.state_id, entity_id=payload.entity_id, posture_score=payload.posture_score, anomaly_detected=payload.anomaly_detected
    )
    return {"status": "RECORD_CREATED", "record_id": item.record_id}

@router.get("/records")
def list_records(
    tenant_id: str = Depends(verify_auth),
    svc: SecurityDigitalTwinService = Depends(get_svc)
):
    records = svc.list_digitaltwinstates(tenant_id)
    return {"tenant_id": tenant_id, "count": len(records), "records": [
        {"record_id": r.record_id} for r in records
    ]}

@router.get("/records/{record_id}")
def get_record(
    record_id: str,
    tenant_id: str = Depends(verify_auth),
    svc: SecurityDigitalTwinService = Depends(get_svc)
):
    record = svc.get_digitaltwinstate(tenant_id, record_id)
    if not record:
        raise HTTPException(status_code=404, detail="Record not found")
    return {"record_id": record.record_id}

@router.get("/analytics")
def get_analytics(
    tenant_id: str = Depends(verify_auth),
    store: SecurityDigitalTwinStore = Depends(get_store)
):
    analytics = SecurityDigitalTwinAnalytics(store)
    return analytics.compute_kpis(tenant_id)
