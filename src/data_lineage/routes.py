"""
API Routes for Data Lineage & Provenance Platform
"""

from __future__ import annotations

from typing import List
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query

from src.api.security import require_role, Role

from .models import RecordType, SourceType, ImpactLevel
from .service import get_lineage_service
from .schemas import (
    LineageRecordCreateRequest,
    LineageRecordResponse,
    LineageLinkRequest,
    ProvenanceChainResponse,
    DependencyGraphResponse,
    ImpactAnalysisResponse,
    LineageStatsResponse,
    LineageQueryRequest,
    LineageReportResponse,
    TraceabilityRecordResponse,
    LineageDashboardResponse,
)


router = APIRouter(prefix="/api/v1/lineage", tags=["Data Lineage"])


def get_service():
    return get_lineage_service()


@router.post(
    "/records",
    response_model=LineageRecordResponse,
    summary="Create a new lineage record",
    dependencies=[Depends(require_role(Role.ANALYST))],
)
async def create_record(request: LineageRecordCreateRequest, service=Depends(get_service)):
    """Create a new data record with lineage tracking."""
    try:
        record_type = RecordType(request.record_type)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Invalid record type",
        )

    record = service.create_record(
        record_type=record_type,
        data=request.data,
        source=None,
        created_by="api",
        tags=request.tags,
    )

    return LineageRecordResponse(**record.to_dict())


@router.get(
    "/records/{record_id}",
    response_model=LineageRecordResponse,
    summary="Get a lineage record",
    dependencies=[Depends(require_role(Role.ANALYST))],
)
async def get_record(record_id: str, service=Depends(get_service)):
    """Get a data record by ID."""
    record = service._store.get_record(record_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"Record not found: {record_id}")
    return LineageRecordResponse(**record.to_dict())


@router.post(
    "/records/{record_id}/link",
    summary="Link records in lineage",
    dependencies=[Depends(require_role(Role.ANALYST))],
)
async def link_records(record_id: str, request: LineageLinkRequest, service=Depends(get_service)):
    """Link two records with a lineage relationship."""
    try:
        impact_level = ImpactLevel(request.impact_level)
    except ValueError:
        impact_level = ImpactLevel.MEDIUM

    success = service.link_records(
        parent_id=request.parent_id,
        child_id=record_id,
        relationship_type=request.relationship_type,
        impact_level=impact_level,
    )

    if not success:
        raise HTTPException(
            status_code=400,
            detail="Failed to link records. Parent or child record not found."
        )

    return {"status": "success", "message": "Records linked successfully"}


@router.get(
    "/records/{record_id}/provenance",
    response_model=ProvenanceChainResponse,
    summary="Get provenance chain",
    dependencies=[Depends(require_role(Role.ANALYST))],
)
async def get_provenance_chain(
    record_id: str,
    max_depth: int = Query(default=10, ge=1, le=50),
    service=Depends(get_service),
):
    """Get the complete provenance chain for a record."""
    chain = service.get_provenance_chain(record_id, max_depth=max_depth)
    if not chain:
        raise HTTPException(status_code=404, detail=f"Record not found: {record_id}")
    return ProvenanceChainResponse(**chain.to_dict())


@router.get(
    "/records/{record_id}/graph",
    response_model=DependencyGraphResponse,
    summary="Get dependency graph",
    dependencies=[Depends(require_role(Role.ANALYST))],
)
async def get_dependency_graph(
    record_id: str,
    max_depth: int = Query(default=10, ge=1, le=50),
    direction: str = Query(default="downstream", regex="^(downstream|upstream)$"),
    service=Depends(get_service),
):
    """Build and return a dependency graph starting from a record."""
    graph = service.build_dependency_graph(record_id, max_depth=max_depth, direction=direction)
    if not graph:
        raise HTTPException(status_code=404, detail=f"Record not found: {record_id}")
    return DependencyGraphResponse(**graph.to_dict())


@router.get(
    "/records/{record_id}/impact",
    response_model=ImpactAnalysisResponse,
    summary="Get impact analysis",
    dependencies=[Depends(require_role(Role.ANALYST))],
)
async def get_impact_analysis(
    record_id: str,
    max_depth: int = Query(default=10, ge=1, le=50),
    service=Depends(get_service),
):
    """Analyze the impact of a data record."""
    analysis = service.analyze_impact(record_id, max_depth=max_depth)
    if not analysis:
        raise HTTPException(status_code=404, detail=f"Record not found: {record_id}")
    return ImpactAnalysisResponse(**analysis.to_dict())


@router.get(
    "/records/{record_id}/history",
    response_model=List[TraceabilityRecordResponse],
    summary="Get record history",
    dependencies=[Depends(require_role(Role.ANALYST))],
)
async def get_record_history(record_id: str, service=Depends(get_service)):
    """Get the complete traceability history for a record."""
    history = service.get_record_history(record_id)
    if not history:
        raise HTTPException(status_code=404, detail=f"Record not found: {record_id}")
    return [TraceabilityRecordResponse(**h.to_dict()) for h in history]


@router.get(
    "/records/{record_id}/verify",
    summary="Verify provenance integrity",
    dependencies=[Depends(require_role(Role.ANALYST))],
)
async def verify_provenance(record_id: str, service=Depends(get_service)):
    """Verify the provenance chain integrity for a record."""
    is_valid = service.verify_provenance(record_id)
    return {
        "record_id": record_id,
        "is_valid": is_valid,
        "verified_at": datetime.now(timezone.utc).isoformat(),
    }


@router.get(
    "/records/{record_id}/report",
    response_model=LineageReportResponse,
    summary="Get lineage report",
    dependencies=[Depends(require_role(Role.ANALYST))],
)
async def get_lineage_report(
    record_id: str,
    include_graph: bool = Query(default=True),
    include_impact: bool = Query(default=True),
    service=Depends(get_service),
):
    """Export a comprehensive lineage report for a record."""
    report = service.export_lineage_report(
        record_id,
        include_graph=include_graph,
        include_impact=include_impact,
    )
    if "error" in report:
        raise HTTPException(status_code=404, detail=report["error"])
    return LineageReportResponse(**report)


@router.post(
    "/query",
    response_model=List[LineageRecordResponse],
    summary="Query lineage records",
    dependencies=[Depends(require_role(Role.ANALYST))],
)
async def query_records(request: LineageQueryRequest, service=Depends(get_service)):
    """Search records based on query parameters."""
    from .models import LineageQuery as ModelLineageQuery

    query = ModelLineageQuery(
        record_id=request.record_id,
        record_type=RecordType(request.record_type) if request.record_type else None,
        source_type=SourceType(request.source_type) if request.source_type else None,
        start_date=request.start_date,
        end_date=request.end_date,
        tags=request.tags,
        depth_limit=request.depth_limit,
        include_derivatives=request.include_derivatives,
        include_ancestors=request.include_ancestors,
    )

    records = service.search_records(query)
    return [LineageRecordResponse(**r.to_dict()) for r in records]


@router.get(
    "/stats",
    response_model=LineageStatsResponse,
    summary="Get lineage statistics",
    dependencies=[Depends(require_role(Role.ANALYST))],
)
async def get_stats(service=Depends(get_service)):
    """Get lineage system statistics."""
    stats = service.get_lineage_stats()
    return LineageStatsResponse(**stats.to_dict())


@router.get(
    "/dashboard",
    response_model=LineageDashboardResponse,
    summary="Get lineage dashboard",
    dependencies=[Depends(require_role(Role.ANALYST))],
)
async def get_dashboard(service=Depends(get_service)):
    """Get lineage dashboard data."""
    stats = service.get_lineage_stats()

    # Get recent records
    recent = sorted(
        [r for r in service._store._records.values()],
        key=lambda x: x.created_at,
        reverse=True,
    )[:10]

    recent_records = [r.to_dict() for r in recent]

    # Calculate top sources
    source_counts = {}
    for record in service._store._records.values():
        if record.source:
            source_name = record.source.source_name
            source_counts[source_name] = source_counts.get(source_name, 0) + 1

    top_sources = [
        {"source": k, "count": v} for k, v in sorted(source_counts.items(), key=lambda x: -x[1])[:5]
    ]

    return LineageDashboardResponse(
        statistics=stats.to_dict(),
        recent_records=recent_records,
        top_sources=top_sources,
        integrity_score=stats.chain_integrity,
    )


@router.delete(
    "/records/{record_id}",
    summary="Delete a lineage record",
    dependencies=[Depends(require_role(Role.ADMIN))],
)
async def delete_record(record_id: str, service=Depends(get_service)):
    """Delete a lineage record (soft delete)."""
    record = service._store.get_record(record_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"Record not found: {record_id}")

    record.is_active = False
    record.updated_at = datetime.now(timezone.utc).isoformat()
    service._store.store_record(record)

    return {"status": "success", "message": "Record deleted"}
