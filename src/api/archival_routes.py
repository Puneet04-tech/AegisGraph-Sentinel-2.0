"""
Sentinel Log Archival API Routes  (Issue #1477)

Exposes endpoints to:
  - Manually trigger an archival run
  - Query the cold-storage archive (only when user filters for historical dates)
  - Inspect archival run history and statistics
  - Check the health of the archival service

All write endpoints require the ADMIN role; read endpoints require ANALYST or
above, matching the existing authorization pattern in this project.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, field_validator

from src.api.security import Role, require_role
from src.archival.archival_service import ArchivalService, DEFAULT_THRESHOLD_DAYS
from src.archival.store import get_sentinel_log_store
from src.archival.scheduler import get_archival_scheduler

router = APIRouter(prefix="/api/v1/archival", tags=["archival"])


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------


class TriggerArchivalRequest(BaseModel):
    """Body for a manual archival run."""

    threshold_days: int = Field(
        default=DEFAULT_THRESHOLD_DAYS,
        ge=1,
        le=3650,
        description="Migrate logs older than this many days to cold storage.",
    )
    batch_size: int = Field(
        default=500,
        ge=1,
        le=5000,
        description="Documents to process per internal batch.",
    )


class TriggerArchivalResponse(BaseModel):
    run_id: str
    status: str
    threshold_days: int
    documents_scanned: int
    documents_archived: int
    documents_failed: int
    started_at: str
    completed_at: Optional[str]
    error_message: Optional[str]


class ArchiveQueryResponse(BaseModel):
    total: int
    offset: int
    limit: int
    records: List[Dict[str, Any]]


class ArchivalStatsResponse(BaseModel):
    hot_collection_count: int
    archive_collection_count: int
    archive_stats: Dict[str, Any]
    scheduler_running: bool


class RunHistoryResponse(BaseModel):
    count: int
    runs: List[Dict[str, Any]]


class AddLogRequest(BaseModel):
    """Helper endpoint to seed the hot collection during development / testing."""

    event_type: str = Field(..., min_length=1, max_length=100)
    risk_score: float = Field(..., ge=0.0, le=1.0)
    decision: str = Field(..., pattern="^(ALLOW|REVIEW|BLOCK)$")
    source_account: Optional[str] = None
    target_account: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: Optional[str] = Field(
        default=None,
        description=(
            "ISO 8601 timestamp. Pass a past date to create aged logs that are "
            "immediately eligible for archival."
        ),
    )

    @field_validator("created_at", mode="before")
    @classmethod
    def parse_created_at(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        try:
            datetime.fromisoformat(v.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(f"Invalid ISO 8601 timestamp: {v}") from exc
        return v


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/health")
async def health_check() -> Dict[str, Any]:
    """Liveness check for the archival subsystem."""
    store = get_sentinel_log_store()
    scheduler = get_archival_scheduler()
    return {
        "status": "healthy",
        "module": "archival",
        "scheduler_running": scheduler.is_running,
        "hot_collection_count": store.hot_count(),
        "archive_collection_count": store.archive_count(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.post(
    "/trigger",
    response_model=TriggerArchivalResponse,
    dependencies=[Depends(require_role(Role.ADMIN))],
)
async def trigger_archival(body: TriggerArchivalRequest) -> TriggerArchivalResponse:
    """
    Manually kick off one archival cycle outside the daily schedule.

    Useful for on-demand housekeeping or after a bulk data import.
    Runs synchronously (in the request thread) so the caller receives the
    full result immediately.  For large datasets, consider increasing
    `batch_size` to speed up the run.
    """
    store = get_sentinel_log_store()
    service = ArchivalService(
        store=store,
        threshold_days=body.threshold_days,
        batch_size=body.batch_size,
    )
    summary = service.run()

    return TriggerArchivalResponse(
        run_id=summary.run_id,
        status=summary.status.value,
        threshold_days=summary.threshold_days,
        documents_scanned=summary.documents_scanned,
        documents_archived=summary.documents_archived,
        documents_failed=summary.documents_failed,
        started_at=summary.started_at.isoformat(),
        completed_at=summary.completed_at.isoformat() if summary.completed_at else None,
        error_message=summary.error_message,
    )


@router.get(
    "/archive",
    response_model=ArchiveQueryResponse,
    dependencies=[Depends(require_role(Role.ANALYST))],
)
async def query_archive(
    start_date: Optional[str] = Query(
        default=None,
        description="ISO 8601 start of the date range (inclusive).",
    ),
    end_date: Optional[str] = Query(
        default=None,
        description="ISO 8601 end of the date range (inclusive).",
    ),
    decision: Optional[str] = Query(
        default=None,
        description="Filter by decision: ALLOW | REVIEW | BLOCK",
    ),
    event_type: Optional[str] = Query(
        default=None,
        description="Filter by event type (e.g. 'fraud_check').",
    ),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> ArchiveQueryResponse:
    """
    Query the cold-storage archive.

    This endpoint is only intended for historical analysis — the real-time
    graph UI queries the hot collection via existing fraud-check endpoints.
    At least one of `start_date` or `end_date` should be supplied so the
    query is scoped; an unscopped call returns the *offset/limit* page of the
    full archive sorted newest-first.
    """
    if decision and decision.upper() not in {"ALLOW", "REVIEW", "BLOCK"}:
        raise HTTPException(status_code=400, detail="decision must be ALLOW, REVIEW, or BLOCK")

    start_dt: Optional[datetime] = None
    end_dt: Optional[datetime] = None

    try:
        if start_date:
            start_dt = datetime.fromisoformat(start_date.replace("Z", "+00:00"))
            if start_dt.tzinfo is None:
                start_dt = start_dt.replace(tzinfo=timezone.utc)
        if end_date:
            end_dt = datetime.fromisoformat(end_date.replace("Z", "+00:00"))
            if end_dt.tzinfo is None:
                end_dt = end_dt.replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid date format: {exc}") from exc

    store = get_sentinel_log_store()
    records, total = store.get_archive_logs(
        start_date=start_dt,
        end_date=end_dt,
        decision=decision,
        event_type=event_type,
        limit=limit,
        offset=offset,
    )

    return ArchiveQueryResponse(
        total=total,
        offset=offset,
        limit=limit,
        records=[r.to_dict() for r in records],
    )


@router.get(
    "/stats",
    response_model=ArchivalStatsResponse,
    dependencies=[Depends(require_role(Role.ANALYST))],
)
async def get_archival_stats() -> ArchivalStatsResponse:
    """Return collection sizes and archive summary statistics."""
    store = get_sentinel_log_store()
    scheduler = get_archival_scheduler()
    return ArchivalStatsResponse(
        hot_collection_count=store.hot_count(),
        archive_collection_count=store.archive_count(),
        archive_stats=store.get_archive_stats(),
        scheduler_running=scheduler.is_running,
    )


@router.get(
    "/runs",
    response_model=RunHistoryResponse,
    dependencies=[Depends(require_role(Role.ANALYST))],
)
async def get_run_history(
    limit: int = Query(default=30, ge=1, le=365),
) -> RunHistoryResponse:
    """
    Return the history of archival runs (newest first).

    Useful for auditing data lifecycle compliance and spotting gaps or
    failures in the daily schedule.
    """
    store = get_sentinel_log_store()
    runs = store.get_run_history(limit=limit)
    return RunHistoryResponse(
        count=len(runs),
        runs=[r.to_dict() for r in runs],
    )


@router.get(
    "/hot",
    dependencies=[Depends(require_role(Role.ANALYST))],
)
async def query_hot_logs(
    decision: Optional[str] = Query(default=None),
    event_type: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
) -> Dict[str, Any]:
    """
    Query recent hot-collection logs (fast path, real-time data only).

    Does NOT touch the archive.  For historical data use GET /archive.
    """
    if decision and decision.upper() not in {"ALLOW", "REVIEW", "BLOCK"}:
        raise HTTPException(status_code=400, detail="decision must be ALLOW, REVIEW, or BLOCK")

    store = get_sentinel_log_store()
    logs = store.get_hot_logs(
        limit=limit,
        decision=decision,
        event_type=event_type,
    )
    return {
        "count": len(logs),
        "source": "hot_collection",
        "logs": [l.to_dict() for l in logs],
    }


@router.post(
    "/logs",
    status_code=201,
    dependencies=[Depends(require_role(Role.ADMIN))],
)
async def add_sentinel_log(body: AddLogRequest) -> Dict[str, Any]:
    """
    Insert a new Sentinel log into the hot collection.

    Primarily intended for development and integration testing.  Pass a past
    `created_at` value to seed aged logs that can be immediately archived.
    """
    store = get_sentinel_log_store()

    created_at: Optional[datetime] = None
    if body.created_at:
        created_at = datetime.fromisoformat(body.created_at.replace("Z", "+00:00"))
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)

    log = store.add_log(
        event_type=body.event_type,
        risk_score=body.risk_score,
        decision=body.decision,
        source_account=body.source_account,
        target_account=body.target_account,
        metadata=body.metadata,
        created_at=created_at,
    )
    return {"log_id": log.log_id, "status": "created"}


def register_routes(app) -> None:
    """Register archival routes with the main FastAPI application."""
    app.include_router(router)
