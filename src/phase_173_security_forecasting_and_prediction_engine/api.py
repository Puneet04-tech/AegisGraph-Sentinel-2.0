from fastapi import APIRouter, Depends, HTTPException
from typing import List, Dict, Any, Optional
from .schemas import SecurityForecastingandPredictionEngineCreateSchema, SecurityForecastingandPredictionEngineAlertSchema
from .store import get_store, SecurityForecastingandPredictionEngineStore
from .service import SecurityForecastingandPredictionEngineService
from .analytics import SecurityForecastingandPredictionEngineAnalytics
from src.api.security import require_role, Role
from src.api.middleware.multi_tenancy import get_current_tenant

router = APIRouter(prefix="/api/v1/phase173", tags=["Phase 173: Security Forecasting and Prediction Engine"])


def resolve_tenant() -> str:
    """Resolve the tenant from the authenticated request context.

    API-key validation itself is handled by the route-level
    require_role dependency; tenant identity comes from the
    multi-tenancy middleware, never from the raw key contents.
    """
    tenant_id = get_current_tenant()
    if not tenant_id:
        raise HTTPException(status_code=401, detail="Tenant context not available")
    return tenant_id


def get_svc(store: SecurityForecastingandPredictionEngineStore = Depends(get_store)) -> SecurityForecastingandPredictionEngineService:
    return SecurityForecastingandPredictionEngineService(store)


@router.post("/records", dependencies=[Depends(require_role(Role.ADMIN))])
def create_record(
    payload: SecurityForecastingandPredictionEngineCreateSchema,
    tenant_id: str = Depends(resolve_tenant),
    svc: SecurityForecastingandPredictionEngineService = Depends(get_svc)
):
    if payload.tenant_id != tenant_id:
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
    svc: SecurityForecastingandPredictionEngineService = Depends(get_svc)
):
    records = svc.list_records(tenant_id)
    return {"tenant_id": tenant_id, "count": len(records), "records": [
        {"record_id": r.record_id, "name": r.name, "status": r.status} for r in records
    ]}


@router.get("/records/{record_id}", dependencies=[Depends(require_role(Role.ADMIN))])
def get_record(
    record_id: str,
    tenant_id: str = Depends(resolve_tenant),
    svc: SecurityForecastingandPredictionEngineService = Depends(get_svc)
):
    record = svc.get_record(tenant_id, record_id)
    if not record:
        raise HTTPException(status_code=404, detail="Record not found")
    return {"record_id": record.record_id, "name": record.name, "status": record.status}


@router.post("/alerts", dependencies=[Depends(require_role(Role.ADMIN))])
def create_alert(
    payload: SecurityForecastingandPredictionEngineAlertSchema,
    tenant_id: str = Depends(resolve_tenant),
    svc: SecurityForecastingandPredictionEngineService = Depends(get_svc)
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
    store: SecurityForecastingandPredictionEngineStore = Depends(get_store)
):
    analytics = SecurityForecastingandPredictionEngineAnalytics(store)
    return analytics.compute_kpis(tenant_id)
