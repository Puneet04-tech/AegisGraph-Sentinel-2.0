from fastapi import APIRouter, Depends, Header, Query, HTTPException
from typing import Optional
from datetime import datetime, timezone
from src.api.security import require_role, Role
from src.case_management.store import get_case_store, CaseStatus, CasePriority, EvidenceType
from src.api.schemas import *
from src.api.main import _serialise_case, _api_logger

router = APIRouter()

@router.post(
    "/api/v1/cases",
    response_model=FraudCaseResponse,
    tags=["Case Management"],
    dependencies=[Depends(require_role(Role.ANALYST))],
    summary="Create a new fraud investigation case",
)
async def create_case(
    request: CreateCaseRequest,
    x_analyst_id: Optional[str] = Header(default="system", alias="X-Analyst-ID"),
):
    """Open a new fraud investigation case from a detected alert."""
    store = get_case_store()
    priority = CasePriority(request.priority or "MEDIUM")
    case = store.create_case(
        transaction_id=request.transaction_id,
        risk_score=request.risk_score,
        decision=request.decision,
        analyst_id=x_analyst_id or "system",
        priority=priority,
        tags=request.tags or [],
    )
    return _serialise_case(case)


@router.get(
    "/api/v1/cases",
    response_model=CaseListResponse,
    tags=["Case Management"],
    dependencies=[Depends(require_role(Role.ANALYST))],
    summary="List all fraud investigation cases with filters and pagination",
)
async def list_cases(
    status: Optional[str] = Query(default=None, description="Filter by status"),
    priority: Optional[str] = Query(default=None, description="Filter by priority"),
    assigned_analyst: Optional[str] = Query(default=None, description="Filter by analyst ID"),
    page: int = Query(default=1, ge=1, description="Page number"),
    page_size: int = Query(default=20, ge=1, le=100, description="Page size"),
):
    """Return a paginated, filterable list of all fraud cases."""
    store = get_case_store()
    status_filter = CaseStatus(status) if status else None
    priority_filter = CasePriority(priority) if priority else None
    cases, total = store.list_cases(
        status=status_filter,
        priority=priority_filter,
        assigned_analyst=assigned_analyst,
        page=page,
        page_size=page_size,
    )
    import math
    total_pages = math.ceil(total / page_size) if total > 0 else 1
    return CaseListResponse(
        cases=[_serialise_case(c) for c in cases],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@router.get(
    "/api/v1/cases/dashboard",
    response_model=CaseDashboardResponse,
    tags=["Case Management"],
    dependencies=[Depends(require_role(Role.ANALYST))],
    summary="Aggregated case management dashboard statistics",
)
async def get_case_dashboard():
    """Return aggregated counts of cases by status and priority."""
    store = get_case_store()
    stats = store.get_dashboard_stats()
    return CaseDashboardResponse(**stats)


@router.get(
    "/api/v1/cases/{case_id}",
    response_model=FraudCaseResponse,
    tags=["Case Management"],
    dependencies=[Depends(require_role(Role.ANALYST))],
    summary="Get full details of a fraud case",
)
async def get_case(case_id: str):
    """Return full details of a specific fraud case."""
    store = get_case_store()
    case = store.get_case(case_id)
    if case is None:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")
    return _serialise_case(case)


@router.patch(
    "/api/v1/cases/{case_id}",
    response_model=FraudCaseResponse,
    tags=["Case Management"],
    dependencies=[Depends(require_role(Role.ADMIN))],
    summary="Update status, assignment, or priority of a case",
    description=(
        "Partially update a fraud case (status, assigned analyst, or priority). "
        "**Required role: ADMIN** — this is a privileged mutation that changes "
        "authoritative case data."
    ),
)
async def update_case(
    case_id: str,
    request: UpdateCaseRequest,
    x_analyst_id: Optional[str] = Header(default="system", alias="X-Analyst-ID"),
):
    """Partially update a fraud case (status, assigned analyst, or priority)."""
    store = get_case_store()
    analyst = x_analyst_id or "system"
    try:
        case = store.get_case(case_id)
        if case is None:
            raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")
        if request.status:
            store.update_status(case_id, CaseStatus(request.status), analyst)
        if request.assigned_analyst:
            store.assign_analyst(case_id, request.assigned_analyst, analyst)
        if request.priority:
            store.update_priority(case_id, CasePriority(request.priority), analyst)
        case = store.get_case(case_id)
        return _serialise_case(case)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post(
    "/api/v1/cases/{case_id}/claim",
    response_model=FraudCaseResponse,
    tags=["Case Management"],
    dependencies=[Depends(require_role(Role.ANALYST))],
    summary="Claim an unassigned case",
)
async def claim_case(
    case_id: str,
    x_analyst_id: Optional[str] = Header(default="system", alias="X-Analyst-ID"),
):
    """Analyst claims an unassigned case to begin investigation."""
    store = get_case_store()
    analyst = x_analyst_id or "system"
    try:
        case = store.claim_case(case_id, analyst)
        return _serialise_case(case)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post(
    "/api/v1/cases/{case_id}/comments",
    response_model=CaseCommentResponse,
    tags=["Case Management"],
    dependencies=[Depends(require_role(Role.ANALYST))],
    summary="Add an investigation note to a case",
)
async def add_case_comment(
    case_id: str,
    request: AddCommentRequest,
    x_analyst_id: Optional[str] = Header(default="system", alias="X-Analyst-ID"),
):
    """Attach an investigation note or comment to a fraud case."""
    store = get_case_store()
    analyst = x_analyst_id or "system"
    try:
        comment = store.add_comment(case_id, analyst, request.text)
        return CaseCommentResponse(
            comment_id=comment.comment_id,
            case_id=comment.case_id,
            analyst_id=comment.analyst_id,
            text=comment.text,
            created_at=comment.created_at,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post(
    "/api/v1/cases/{case_id}/evidence",
    response_model=CaseEvidenceResponse,
    tags=["Case Management"],
    dependencies=[Depends(require_role(Role.ANALYST))],
    summary="Attach evidence to a fraud case",
)
async def add_case_evidence(
    case_id: str,
    request: AddEvidenceRequest,
    x_analyst_id: Optional[str] = Header(default="system", alias="X-Analyst-ID"),
):
    """Attach a piece of evidence (transaction link, graph snapshot, etc.) to a case."""
    store = get_case_store()
    analyst = x_analyst_id or "system"
    try:
        evidence = store.add_evidence(
            case_id=case_id,
            analyst_id=analyst,
            evidence_type=EvidenceType(request.evidence_type),
            description=request.description,
            reference_id=request.reference_id,
        )
        return CaseEvidenceResponse(
            evidence_id=evidence.evidence_id,
            case_id=evidence.case_id,
            analyst_id=evidence.analyst_id,
            evidence_type=evidence.evidence_type.value,
            description=evidence.description,
            reference_id=evidence.reference_id,
            created_at=evidence.created_at,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get(
    "/api/v1/cases/{case_id}/timeline",
    response_model=CaseTimelineResponse,
    tags=["Case Management"],
    dependencies=[Depends(require_role(Role.AUDITOR))],
    summary="Get the immutable audit trail for a case",
)
async def get_case_timeline(case_id: str):
    """Return the full chronological audit trail for a fraud case."""
    store = get_case_store()
    try:
        events = store.get_timeline(case_id)
        return CaseTimelineResponse(
            case_id=case_id,
            events=[
                CaseAuditEventResponse(
                    event_id=e.event_id,
                    case_id=e.case_id,
                    analyst_id=e.analyst_id,
                    action=e.action,
                    old_value=e.old_value,
                    new_value=e.new_value,
                    timestamp=e.timestamp,
                )
                for e in events
            ],
            total_events=len(events),
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# ============================================================================
# CASE SIMILARITY & SEMANTIC RETRIEVAL (RAG System)
# ============================================================================

@router.post(
    "/api/v1/cases/similar-cases",
    response_model=SimilarCaseResponse,
    tags=["Case Management"],
    dependencies=[Depends(require_role(Role.ANALYST))],
    summary="Find similar fraud cases using semantic retrieval",
)
@router.post(
    "/api/v1/cases/generate-embedding",
    response_model=GenerateEmbeddingResponse,
    tags=["Case Management"],
    dependencies=[Depends(require_role(Role.ANALYST))],
    summary="Generate semantic embedding for fraud investigation text",
)
async def generate_case_embedding(
    request: GenerateEmbeddingRequest,
):
    """
    Generate a semantic embedding for arbitrary fraud-related text.

    Useful for:
    - Investigation workflows
    - Semantic search validation
    - Embedding diagnostics
    - RAG pipeline verification
    """
    try:
        from src.embeddings import get_embedder

        embedder = get_embedder()

        embedding = embedder.embed_text(request.text)

        return GenerateEmbeddingResponse(
            embedding_dimension=len(embedding),
            embedding_preview=[
                float(x)
                for x in embedding[:10]
            ],
            timestamp=datetime.now(timezone.utc).isoformat() + "Z",
        )

    except Exception as e:
        _api_logger.error(f"Error generating embedding: {e}")

        raise HTTPException(
            status_code=500,
            detail=f"Error generating embedding: {str(e)}",
        )
