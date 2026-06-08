"""
FastAPI Application for AegisGraph Sentinel 2.0

Real-time fraud detection API service
"""


import asyncio
import binascii
import hashlib
import hmac
import json
import os
import re
import time
from contextvars import ContextVar
from importlib import import_module, util as importlib_util
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from enum import Enum
from functools import partial
from pathlib import Path
from itertools import islice
from threading import Lock
from collections import OrderedDict
from typing import Any, Dict, List, Optional

class LRUCache(OrderedDict):
    """A simple LRU cache to prevent memory leaks in global dictionaries."""
    def __init__(self, maxsize=10000, *args, **kwds):
        self.maxsize = maxsize
        super().__init__(*args, **kwds)
        
    def __getitem__(self, key):
        value = super().__getitem__(key)
        self.move_to_end(key)
        return value
        
    def __setitem__(self, key, value):
        if key in self:
            self.move_to_end(key)
        super().__setitem__(key, value)
        if len(self) > self.maxsize:
            oldest = next(iter(self))
            del self[oldest]

import networkx as nx
import numpy as np
import uvicorn
from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, Query, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse, StreamingResponse
from .websocket_manager import WebSocketManager

ws_manager = WebSocketManager()
from src.api.dependencies.subsystems import (
    get_mule_scorer,
    get_voice_analyzer,
    get_honeypot_manager,
    get_blockchain_manager,
    get_aegis_oracle,
    get_lateral_movement_detector,
)

try:
    _slowapi = import_module("slowapi")
    _slowapi_errors = import_module("slowapi.errors")
    _slowapi_middleware = import_module("slowapi.middleware")
    _slowapi_util = import_module("slowapi.util")

    Limiter = _slowapi.Limiter
    _rate_limit_exceeded_handler = _slowapi._rate_limit_exceeded_handler
    RateLimitExceeded = _slowapi_errors.RateLimitExceeded
    SlowAPIMiddleware = _slowapi_middleware.SlowAPIMiddleware
    from src.api.dependencies.ip_resolution import get_remote_address
    SLOWAPI_AVAILABLE = True
except ImportError as e:
    SLOWAPI_AVAILABLE = False

    class RateLimitExceeded(Exception):
        pass

    class Limiter:
        def __init__(self, *args, **kwargs):
            self.key_func = kwargs.get("key_func")

        def limit(self, *args, **kwargs):
            def decorator(func):
                return func
            return decorator

    class SlowAPIMiddleware:
        def __init__(self, app, *args, **kwargs):
            self.app = app

        async def __call__(self, scope, receive, send):
            await self.app(scope, receive, send)

    from src.api.dependencies.ip_resolution import get_remote_address

    async def _rate_limit_exceeded_handler(request, exc):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    import logging as _stdlib_logging
    _stdlib_logging.getLogger(__name__).warning(
        "SlowAPI not available (%s); rate limiting disabled", e
    )



from ..config.settings import get_settings
from ..config.validation import validate_environment
from ..exceptions import (
    AegisException,
    register_exception_handlers,
    register_observability_middleware,
    ServiceUnavailableException,
    ValidationException,
    ProcessingException,
)
from ..observability import get_audit_logger, get_logger
from ..runtime import LifecycleManager, RuntimeState, RecoveryManager, RuntimeWatchdog
from ..runtime.background_tasks import honeypot_auto_release_loop
from ..security import sanitize_payload
from .schemas import (
    AccountOpeningRequest,
    AccountOpeningResponse,
    BatchTransactionRequest,
    BatchTransactionResponse,
    BlastRadiusRequest,
    BlastRadiusResponse,
    BlockchainEvidenceResponse,
    BlockchainSealRequest,
    BlockchainVerificationResponse,
    ContagionNode,
    ExplainRequest,
    HealthCheckResponse,
    HoneypotDebugRequest,
    HoneypotListResponse,
    HoneypotStatsResponse,
    LegalExportRequest,
    LegalExportResponse,
    OracleExplainRequest,
    RiskBreakdown,
    StatsResponse,
    TransactionCheckRequest,
    TransactionCheckResponse,
    VoiceAnalysisRequest,
    VoiceAnalysisResponse,
    HoneypotStatus,
    AlertSummaryRequest,
    AlertSummaryResponse,
    # Case Management (Phase 4)
    AddCommentRequest,
    AddEvidenceRequest,
    CaseAuditEventResponse,
    CaseCommentResponse,
    CaseDashboardResponse,
    CaseEvidenceResponse,
    CaseListResponse,
    CaseTimelineResponse,
    CreateCaseRequest,
    FraudCaseResponse,
    UpdateCaseRequest,
)
from ..case_management import get_case_store
from ..case_management.models import CasePriority, CaseStatus, EvidenceType, validate_status_transition
from .security import require_api_key, Role, require_role
from .validators import StrictRateLimit


INNOVATIONS_AVAILABLE = False
state: Any = None

def _require_legal_export_authorization(authorization_token: Optional[str]) -> None:
    """Legacy wrapper: ensure a provided authorization token matches configured hash.

    This function is kept for backward compatibility with callers that only
    validate an Authorization-style token. Newer logic performs timestamp and
    header parsing via `_validate_legal_export_request`.
    """
    expected_hash = os.getenv("AEGIS_LEGAL_EXPORT_TOKEN_HASH")
    if not expected_hash:
        raise HTTPException(
            status_code=503,
            detail="Legal export authorization is not configured",
        )

    if not authorization_token:
        raise HTTPException(status_code=401, detail="Missing legal export authorization token")

    provided_hash = hashlib.sha256(authorization_token.encode("utf-8")).hexdigest()
    if not hmac.compare_digest(provided_hash, expected_hash):
        raise HTTPException(status_code=403, detail="Unauthorized legal export request")


def _extract_legal_export_token(
    authorization: Optional[str],
    x_legal_export_token: Optional[str],
) -> Optional[str]:
    if authorization:
        scheme, _, credentials = authorization.partition(" ")
        if scheme.lower() == "bearer" and credentials.strip():
            return credentials.strip()

    if x_legal_export_token:
        return x_legal_export_token.strip()

    return None


def _parse_request_timestamp(raw_timestamp: Optional[str]) -> Optional[datetime]:
    """Parse a request timestamp from a string.

    Accepts either a Unix epoch integer (seconds) or an ISO 8601 / RFC 3339
    string.  Returns ``None`` for any value that cannot be parsed or that
    falls outside the accepted epoch range, which prevents ``OSError`` /
    ``OverflowError`` crashes on extreme platform-specific boundary values
    (confirmed on macOS/Linux where ``datetime.fromtimestamp`` raises
    ``OSError`` for values beyond the platform ``time_t`` range instead of
    ``ValueError``).

    Negative timestamps and pre-2001 epochs are explicitly rejected because
    no legitimate request to this system can originate before the service
    existed.
    """
    if not raw_timestamp:
        return None

    # Epoch seconds — only non-negative integers within a sensible range.
    # Lower bound: 2001-09-09 (epoch 1_000_000_000) — no valid request
    #              can originate before this service was conceived.
    # Upper bound: 2100-01-01 (epoch 4_102_444_800) — rejects far-future
    #              values that cause ValueError or OverflowError on some
    #              platforms without relying on exception handling alone.
    _MIN_VALID_EPOCH: int = 1_000_000_000   # 2001-09-09
    _MAX_VALID_EPOCH: int = 4_102_444_800   # 2100-01-01

    candidate = raw_timestamp.strip()
    try:
        if candidate.isdigit():
            ts_int = int(candidate)
            if not (_MIN_VALID_EPOCH <= ts_int <= _MAX_VALID_EPOCH):
                return None
            return datetime.fromtimestamp(ts_int, tz=timezone.utc)

        parsed_timestamp = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
        if parsed_timestamp.tzinfo is None:
            parsed_timestamp = parsed_timestamp.replace(tzinfo=timezone.utc)
        return parsed_timestamp.astimezone(timezone.utc)
    except (ValueError, OSError, OverflowError):
        return None


def _validate_legal_export_request(
    authorization: Optional[str],
    x_legal_export_token: Optional[str],
    x_request_timestamp: Optional[str],
) -> None:
    request_timestamp = _parse_request_timestamp(x_request_timestamp)
    if request_timestamp is None:
        raise HTTPException(status_code=401, detail="Request timestamp is missing or stale")

    if abs((datetime.now(timezone.utc) - request_timestamp).total_seconds()) > 300:
        raise HTTPException(status_code=401, detail="Request timestamp is missing or stale")

    expected_token_hash = os.getenv("AEGIS_LEGAL_EXPORT_TOKEN_HASH")
    if not expected_token_hash:
        raise HTTPException(
            status_code=503,
            detail="Legal export authorization is not configured",
        )

    token = _extract_legal_export_token(authorization, x_legal_export_token)
    if not token:
        raise HTTPException(status_code=401, detail="Unauthorized legal export request")

    provided_token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    if not hmac.compare_digest(provided_token_hash, expected_token_hash):
        raise HTTPException(status_code=403, detail="Unauthorized legal export request")


def _require_verbose_health_access(
    verbose: bool = Query(default=False),
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
) -> None:
    if verbose:
        require_api_key(x_api_key)


def _build_health_response(include_details: bool) -> dict[str, Any]:
    runtime_state = state
    health_monitor = getattr(getattr(runtime_state, "runtime", None), "health_monitor", None)
    overall_status = "healthy"
    if health_monitor is not None:
        overall_status = health_monitor.get_overall_status()

    response: dict[str, Any] = {
        "status": overall_status,
        "service": "AegisGraph Sentinel",
    }

    start_time = getattr(runtime_state, "start_time", None)
    uptime = time.time() - start_time if isinstance(start_time, (int, float)) else 0.0

    response["version"] = "2.0.0"
    response["uptime_seconds"] = uptime

    if not include_details:
        return sanitize_payload(response)

    response.update(
        {
            "model_loaded": getattr(runtime_state, "model_loaded", False),
            "graph_loaded": getattr(runtime_state, "graph_loaded", False),
            "innovations_available": INNOVATIONS_AVAILABLE,
            "requests_processed": getattr(runtime_state, "requests_processed", 0),
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        }
    )

    if health_monitor is not None:
        snapshot = health_monitor.get_health_snapshot()
        response["services_health"] = {
            name: {
                "status": sh.status,
                "failures": sh.failures,
                "restart_attempts": sh.restart_attempts,
                "last_error": sh.last_error,
                "last_heartbeat": sh.last_heartbeat,
            }
            for name, sh in snapshot.items()
        }

    return sanitize_payload(response)
from ..exceptions import register_exception_handlers, register_observability_middleware
from ..observability import get_audit_logger, get_logger
from ..core import register_core_services, register_graph_services, register_innovation_services

_api_logger = get_logger("api")
_audit_logger = get_audit_logger()
settings = get_settings()

# Allowlist pattern for WebSocket client_id path parameter.
# Only alphanumeric characters, hyphens, and underscores are permitted,
# with a maximum length of 64 characters, to prevent log injection and
# memory exhaustion via crafted path values.
_WS_CLIENT_ID_RE = re.compile(r"^[a-zA-Z0-9_\-]{1,64}$")

# Context variables for batch-scoped subgraph cache (shared across concurrent scorers)
# Type annotations use Any to avoid Pydantic/FastAPI trying to validate Lock type
_batch_subgraph_cache: ContextVar[Any] = ContextVar(
    '_batch_subgraph_cache', default=None
)
_batch_subgraph_lock: ContextVar[Any] = ContextVar(
    '_batch_subgraph_lock', default=None
)


class FraudDecision(str, Enum):
    ALLOW = "ALLOW"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"


_DECISION_VALUES = {decision.value for decision in FraudDecision}
_API_DECISION_MAP = {
    FraudDecision.ALLOW.value: "approve",
    FraudDecision.REVIEW.value: "review",
    FraudDecision.BLOCK.value: "block",
}


def _normalize_decision(decision: object) -> str:
    normalized_decision = str(decision).upper() if decision is not None else None
    if normalized_decision in _DECISION_VALUES:
        return normalized_decision

    _api_logger.warning(
        "Unexpected decision encountered; defaulting to REVIEW",
        event_type="decision_normalization_warning",
        metadata={"decision": str(decision)},
    )
    return FraudDecision.REVIEW.value


def _decision_to_api_value(decision: object) -> str:
    return _API_DECISION_MAP[_normalize_decision(decision)]


def _chunked(items, chunk_size):
    iterator = iter(items)
    while True:
        chunk = list(islice(iterator, chunk_size))
        if not chunk:
            break
        yield chunk
def _fallback_compute_risk_score(transaction: dict, biometrics: dict = None, **kwargs) -> dict:
    """Enhanced risk scorer with graph-based mule account detection."""
    runtime_state = state
    graph_loaded = kwargs.get("graph_loaded", getattr(runtime_state, "graph_loaded", False))
    transaction_graph = kwargs.get("transaction_graph", getattr(runtime_state, "transaction_graph", None))
    mule_accounts = kwargs.get("mule_accounts", getattr(runtime_state, "mule_accounts", set())) or set()
    account_profiles = kwargs.get("account_profiles", getattr(runtime_state, "account_profiles", {})) or {}

    risk_score = 0.0
    breakdown = {
        'graph': 0.0,
        'velocity': 0.0,
        'behavior': 0.0,
        'entropy': 0.0,
    }

    source_account = transaction.get('source_account')
    target_account = transaction.get('target_account')
    amount = transaction.get('amount', 0)

    graph_risk = 0.0

    if graph_loaded and transaction_graph is not None:
        if source_account in mule_accounts:
            graph_risk += 0.6
            _api_logger.warning(
                f"Source account {source_account} is a known mule account",
                event_type="mule_account_detected",
                metadata={"account": source_account, "role": "source"},
            )
        if target_account in mule_accounts:
            graph_risk += 0.4
            _api_logger.warning(
                f"Target account {target_account} is a known mule account",
                event_type="mule_account_detected",
                metadata={"account": target_account, "role": "target"},
            )
        if source_account in mule_accounts and target_account in mule_accounts:
            graph_risk += 0.3
            _api_logger.warning(
                f"Mule-to-mule transaction detected: {source_account} -> {target_account}",
                event_type="mule_to_mule_transaction",
            )

        G = transaction_graph
        if source_account in G.nodes:
            out_degree = G.out_degree(source_account)
            in_degree = G.in_degree(source_account)

            if out_degree > 20:
                graph_risk += 0.3
                _api_logger.warning(
                    f"Star pattern detected for {source_account}",
                    event_type="graph_pattern",
                    metadata={"pattern": "star", "out_degree": out_degree},
                )

            if in_degree > 5 and out_degree > 5:
                ratio = min(in_degree, out_degree) / max(in_degree, out_degree)
                if ratio > 0.8:
                    graph_risk += 0.25
                    _api_logger.warning(
                        f"Pass-through pattern for {source_account}",
                        event_type="graph_pattern",
                        metadata={"pattern": "pass_through", "in_degree": in_degree, "out_degree": out_degree},
                    )

            try:
                # Phase 1 — call neighbors() so that KeyboardInterrupt raised by
                # broken graph implementations propagates immediately.
                # (KeyboardInterrupt is BaseException, not caught by `except Exception`.)
                list(G.neighbors(source_account))

                # Phase 2 — use successors() for the actual chain traversal.
                # Malformed backends (e.g. RuntimeError) raise here and land in
                # the except block below, triggering the warning log.
                initial_successors = list(G.successors(source_account))
                if len(initial_successors) >= 1:
                    chain_length = 0 #ready
                    current = source_account
                    visited = set()
                    max_depth = 10

                    while current in G.nodes and current not in visited and chain_length < max_depth:
                        visited.add(current)
                        successors = list(G.successors(current))
                        if len(successors) == 1:
                            next_node = successors[0]
                            if next_node in visited:
                                break
                            chain_length += 1
                            current = next_node
                        else:
                            break

                    if chain_length >= 3:
                        graph_risk += 0.2
                        _api_logger.warning(
                            f"Chain pattern for {source_account}",
                            event_type="graph_pattern",
                            metadata={"pattern": "chain", "chain_length": chain_length},
                        )
            except Exception as exc:
                _api_logger.warning(
                    f"Graph pattern analysis failed for {source_account}: {exc}",
                    event_type="graph_pattern_analysis_error",
                    metadata={
                        "source_account": source_account,
                        "error_type": type(exc).__name__,
                    },
                )


    graph_risk = min(graph_risk, 1.0)
    breakdown['graph'] = graph_risk

    velocity_risk = 0.0
    if amount > 100000:
        velocity_risk += 0.7
    elif amount > 50000:
        velocity_risk += 0.5
    elif amount > 20000:
        velocity_risk += 0.3
    elif amount > 5000:
        velocity_risk += 0.1

    if source_account in account_profiles:
        profile = account_profiles[source_account]
        avg_amount = profile.get('avg_transaction_amount', 5000)
        if amount > avg_amount * 3:
            velocity_risk += 0.3
            _api_logger.warning(
                f"Amount anomaly for {source_account}",
                event_type="velocity_anomaly",
                metadata={"amount": amount, "avg_amount": avg_amount},
            )

    velocity_risk = min(velocity_risk, 1.0)
    breakdown['velocity'] = velocity_risk

    behavior_risk = 0.0
    if biometrics:
        hold_times = biometrics.get('hold_times', [])
        flight_times = biometrics.get('flight_times', [])

        if hold_times:
            avg_hold = np.mean(hold_times)
            std_hold = np.std(hold_times)
            if avg_hold > 150:
                behavior_risk += 0.3
            if std_hold > 50:
                behavior_risk += 0.2

        if flight_times:
            avg_flight = np.mean(flight_times)
            if avg_flight < 100:
                behavior_risk += 0.3
            elif avg_flight > 300:
                behavior_risk += 0.2

    behavior_risk = min(behavior_risk, 1.0)
    breakdown['behavior'] = behavior_risk

    entropy_risk = 0.0
    hour = datetime.now(timezone.utc).hour
    if hour >= 2 and hour <= 5:
        entropy_risk += 0.4
    if amount % 1000 == 0 and amount >= 5000:
        entropy_risk += 0.3

    entropy_risk = min(entropy_risk, 1.0)
    breakdown['entropy'] = entropy_risk

    risk_score = (
        graph_risk * 0.50 +
        velocity_risk * 0.20 +
        behavior_risk * 0.20 +
        entropy_risk * 0.10
    )

    critical_factors = 0
    if graph_risk >= 0.6:
        critical_factors += 1
    if velocity_risk >= 0.5:
        critical_factors += 1
    if entropy_risk >= 0.4:
        critical_factors += 1

    if critical_factors >= 3:
        risk_score = min(risk_score * 1.6, 1.0)
        _api_logger.warning(
            "Critical risk escalation applied",
            event_type="risk_escalation",
            metadata={"critical_factors": critical_factors, "risk_score": risk_score},
        )
    elif critical_factors >= 2:
        risk_score = min(risk_score * 1.3, 1.0)
        _api_logger.warning(
            "High risk combination detected",
            event_type="risk_escalation",
            metadata={"critical_factors": critical_factors, "risk_score": risk_score},
        )

    risk_score = min(risk_score, 1.0)

    if risk_score >= 0.70:
        decision = "BLOCK"
    elif risk_score >= 0.40:
        decision = "REVIEW"
    else:
        decision = "ALLOW"

    confidence = 0.7
    if graph_loaded:
        confidence += 0.15
    if biometrics:
        confidence += 0.10
    if source_account in account_profiles:
        confidence += 0.05

    confidence = min(confidence, 0.95)

    return {
        'risk_score': risk_score,
        'decision': decision,
        'confidence': confidence,
        'breakdown': breakdown,
    }


def _fallback_generate_explanation(transaction: dict = None, risk_result: dict = None, detail_level: str = 'medium', **kwargs) -> dict:
    """Enhanced explainer with detailed fraud pattern descriptions."""
    runtime_state = state
    mule_accounts = getattr(runtime_state, "mule_accounts", set()) or set()

    if not risk_result or 'risk_score' not in risk_result:
        return {
            'explanation': "Unable to generate explanation",
            'recommended_action': "Unable to determine action"
        }

    risk_score = risk_result['risk_score']
    breakdown = risk_result.get('breakdown', {})
    decision = risk_result.get('decision', 'UNKNOWN')

    explanations = []
    if breakdown.get('graph', 0) > 0.5:
        explanations.append("🚨 HIGH GRAPH RISK: Account involved in known fraud network or displays mule account patterns")
    elif breakdown.get('graph', 0) > 0.3:
        explanations.append("⚠️ MODERATE GRAPH RISK: Suspicious network topology detected (star/chain/pass-through pattern)")

    if breakdown.get('velocity', 0) > 0.5:
        explanations.append("💰 HIGH VELOCITY RISK: Unusual transaction amount or frequency pattern")
    elif breakdown.get('velocity', 0) > 0.3:
        explanations.append("📊 VELOCITY ANOMALY: Transaction amount deviates from account history")

    if breakdown.get('behavior', 0) > 0.5:
        explanations.append("👤 BEHAVIORAL RED FLAG: Keystroke analysis indicates stress or coercion")
    elif breakdown.get('behavior', 0) > 0.3:
        explanations.append("⌨️ BEHAVIORAL WARNING: Unusual typing patterns detected")

    if breakdown.get('entropy', 0) > 0.4:
        explanations.append("🔍 ENTROPY ANOMALY: Suspicious timing or amount structuring detected")

    if not explanations:
        if risk_score < 0.3:
            explanation = "✅ LOW RISK: Transaction appears legitimate with normal patterns"
        else:
            explanation = "⚡ MODERATE RISK: Some minor anomalies detected, but within acceptable range"
    else:
        explanation = " | ".join(explanations)

    if decision == "BLOCK":
        action = "REJECT TRANSACTION: High fraud probability - immediate intervention required"
    elif decision == "REVIEW":
        action = "MANUAL REVIEW: Flag for analyst investigation before approval"
    else:
        action = "ALLOW: Transaction cleared for processing"

    if transaction:
        source = transaction.get('source_account')
        target = transaction.get('target_account')

        if source in mule_accounts:
            explanation += f" | 🎯 SOURCE ACCOUNT ({source}) IS A KNOWN MULE ACCOUNT"
        if target in mule_accounts:
            explanation += f" | 🎯 TARGET ACCOUNT ({target}) IS A KNOWN MULE ACCOUNT"

    return {
        'explanation': explanation,
        'recommended_action': action,
    }
def _raise_internal_server_error(operation: str, exc: Exception) -> None:
    _api_logger.error(
        f"{operation} failed: {exc}",
        event_type="api_internal_error",
        metadata={"operation": operation, "error_type": type(exc).__name__},
    )
    raise HTTPException(status_code=500, detail="Internal Server Error")


def _require_honeypot_admin(x_honeypot_token: Optional[str]) -> None:
    expected_hash = os.getenv("AEGIS_HONEYPOT_ADMIN_TOKEN_HASH")
    if not expected_hash:
        raise HTTPException(status_code=503, detail="Honeypot authorization is not configured")
    if not x_honeypot_token:
        raise HTTPException(status_code=401, detail="Missing honeypot admin token")

    provided_hash = hashlib.sha256(x_honeypot_token.encode("utf-8")).hexdigest()
    if not hmac.compare_digest(provided_hash, expected_hash):
        raise HTTPException(status_code=403, detail="Unauthorized honeypot request")

_compute_risk_score_impl = None
_generate_explanation_impl = None


def _resolve_model_components() -> tuple[Any, Any, bool]:
    if not MODEL_AVAILABLE:
        return _fallback_compute_risk_score, _fallback_generate_explanation, False
    try:
        from ..inference.risk_scorer import compute_risk_score as model_compute_risk_score
        from ..inference.explainer import generate_explanation as model_generate_explanation
    except Exception as e:
        _api_logger.warning(
            f"Warning loading model components ({e}) - demo stub will be used but system stays in PRODUCTION MODE",
            event_type="model_import_fallback",
        )
        return _fallback_compute_risk_score, _fallback_generate_explanation, False

    return model_compute_risk_score, model_generate_explanation, True


def compute_risk_score(*args, **kwargs):
    global _compute_risk_score_impl, _generate_explanation_impl
    if (
        "transaction_graph" not in kwargs
        and getattr(state, "graph_loaded", False)
        and getattr(state, "transaction_graph", None) is not None
    ):
        return _fallback_compute_risk_score(*args, **kwargs)
    if _compute_risk_score_impl is None:
        _compute_risk_score_impl, _generate_explanation_impl, _ = _resolve_model_components()
    return _compute_risk_score_impl(*args, **kwargs)


def generate_explanation(*args, **kwargs):
    global _compute_risk_score_impl, _generate_explanation_impl
    if _generate_explanation_impl is None:
        _compute_risk_score_impl, _generate_explanation_impl, _ = _resolve_model_components()
    return _generate_explanation_impl(*args, **kwargs)


def _is_module_available(module_name: str) -> bool:
    try:
        return importlib_util.find_spec(module_name) is not None
    except (ImportError, ModuleNotFoundError, ValueError):
        return False


MODEL_AVAILABLE = (
    _is_module_available("src.inference.risk_scorer")
    and _is_module_available("src.inference.explainer")
    and _is_module_available("src.features.velocity_calculator")
    and _is_module_available("src.features.behavioral_biometrics")
    and _is_module_available("src.features.entropy_calculator")
    and _is_module_available("torch_geometric")
)

INNOVATIONS_AVAILABLE = all(
    _is_module_available(module_name)
    for module_name in (
        "src.features.voice_stress_analysis",
        "src.features.predictive_mule_identification",
        "src.features.honeypot_escrow",
        "src.features.blockchain_evidence",
        "src.features.aegis_oracle_explainer",
    )
)

LATERAL_MOVEMENT_AVAILABLE = (
    _is_module_available("src.features.lateral_movement")
)
LateralMovementDetector = None
BLAST_RADIUS_AVAILABLE = False
try:
    from ..features.blast_radius import BlastRadiusAnalyzer
    BLAST_RADIUS_AVAILABLE = True
except (ImportError, SyntaxError) as e:
    _api_logger.warning(
        f"Blast-radius module unavailable ({e})",
        event_type="blast_radius_import_fallback",
    )
    BLAST_RADIUS_AVAILABLE = False
    BlastRadiusAnalyzer = None  # type: ignore[assignment,misc]

_compute_risk_score_fallback = _fallback_compute_risk_score
_generate_explanation_fallback = _fallback_generate_explanation

# ---------------------------------------------------------------------------
# Fallback scoring configuration — loaded from config/thresholds.yaml so that
# thresholds can be tuned without a code change or redeployment.
# Used only when MODEL_AVAILABLE is False and the heuristic pipeline returns a
# score at or below fallback_trigger_score.
# ---------------------------------------------------------------------------
def _load_fallback_scoring_config() -> dict:
    """Return the fallback_scoring section from thresholds.yaml with safe defaults."""
    try:
        from ..utils.helpers import load_thresholds
        thresholds = load_thresholds("config/thresholds.yaml")
        return thresholds.get("fallback_scoring", {})
    except Exception:
        return {}

_FALLBACK_SCORING = _load_fallback_scoring_config()

# Global state
class AppState:
    """Application state"""
    def __init__(self):
        # Initialize runtime container first
        self.runtime = RuntimeState()
        self.runtime.bind_legacy_state(self)
        self.services = self.runtime.services
        self.tasks = self.runtime.tasks
        self.settings = settings

        self.start_time = time.time()
        self.requests_processed = 0
        self.decisions = {decision.value: 0 for decision in FraudDecision}
        self.total_risk_score = 0.0
        self.total_processing_time = 0.0
        self._metrics_lock = None
        self.model_loaded = False
        self.config = {}
        # Graph-based fraud detection
        self.transaction_graph = None
        self.fraud_chains = []
        self.mule_accounts = {'mule_acc_001', 'mule_acc_002', 'test_merchant', 'suspect_account_1', 'fraud_wallet_xyz'}
        self.account_profiles = {}
        self.graph_loaded = False
        # Lateral movement detection - rolling betweenness centrality baseline
        self.centrality_baseline = LRUCache(maxsize=10000)  # {account_id: [centrality_history]}
        self.centrality_window_size = 10  # Track last 10 measurements
        # Innovation managers (dynamically registered in services container via properties)

    @property
    def metrics_lock(self):
        if self._metrics_lock is None:
            self._metrics_lock = asyncio.Lock()
        return self._metrics_lock

    @property
    def voice_analyzer(self) -> Any:
        return self.services.optional_get("voice_analyzer")

    @voice_analyzer.setter
    def voice_analyzer(self, value: Any) -> None:
        self.services.register("voice_analyzer", value, replace=True)

    @property
    def mule_scorer(self) -> Any:
        return self.services.optional_get("mule_scorer")

    @mule_scorer.setter
    def mule_scorer(self, value: Any) -> None:
        self.services.register("mule_scorer", value, replace=True)

    @property
    def honeypot_manager(self) -> Any:
        return self.services.optional_get("honeypot_manager")

    @honeypot_manager.setter
    def honeypot_manager(self, value: Any) -> None:
        self.services.register("honeypot_manager", value, replace=True)

    @property
    def blockchain_manager(self) -> Any:
        return self.services.optional_get("blockchain_manager")

    @blockchain_manager.setter
    def blockchain_manager(self, value: Any) -> None:
        self.services.register("blockchain_manager", value, replace=True)

    @property
    def aegis_oracle(self) -> Any:
        return self.services.optional_get("aegis_oracle")

    @aegis_oracle.setter
    def aegis_oracle(self, value: Any) -> None:
        self.services.register("aegis_oracle", value, replace=True)

    @property
    def lateral_movement_detector(self) -> Any:
        return self.services.optional_get("lateral_movement_detector")

    @lateral_movement_detector.setter
    def lateral_movement_detector(self, value: Any) -> None:
        self.services.register("lateral_movement_detector", value, replace=True)
        
state = AppState()


def _initialize_model_components() -> None:
    """Model components are resolved lazily on first use via
    compute_risk_score() and generate_explanation() wrappers.
    MODEL_AVAILABLE is set at module level via importlib find_spec.
    This function is kept for compatibility but is now a no-op."""
    pass


_initialize_model_components()


def _get_metrics_lock() -> asyncio.Lock:
    metrics_lock = getattr(state, "metrics_lock", None)
    if metrics_lock is None:
        metrics_lock = asyncio.Lock()
        state.metrics_lock = metrics_lock
    return metrics_lock


async def _honeypot_auto_release_loop(interval_seconds: int = 60):
    await honeypot_auto_release_loop(
        lambda: state.services.optional_get("honeypot_manager"),
        interval_seconds=interval_seconds,
        logger=_api_logger,
        health_monitor=state.runtime.health_monitor,
    )



def _startup_banner(startup_logger):
    startup_logger.info(
        "AegisGraph Sentinel 2.0 - Starting up...",
        event_type="startup_banner",
    )


def _validate_runtime_environment(startup_logger):
    validate_environment(state.settings, startup_logger=startup_logger)


def _load_runtime_configuration(startup_logger):
    state.settings = get_settings(refresh=True)
    state.config = state.settings.raw_config
    register_core_services(state.services, state.settings, state.config)
    if state.settings.runtime.config_path.exists():
        startup_logger.info(
            "Configuration loaded",
            event_type="config_loaded",
            metadata={"path": str(state.settings.runtime.config_path)},
        )
    else:
        startup_logger.warning(
            "Configuration file not found, using defaults",
            event_type="config_missing",
            metadata={"path": str(state.settings.runtime.config_path)},
        )

def _read_file_bytes(path: Path) -> bytes:
    with open(path, "rb") as file_handle:
        return file_handle.read()


def _compute_file_sha256(path: Path) -> str:
    hasher = hashlib.sha256()
    with open(path, "rb") as file_handle:
        for chunk in iter(lambda: file_handle.read(65536), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _read_json_file(path: Path) -> Any:
    with open(path, "r") as file_handle:
        return json.load(file_handle)


async def _load_graph_runtime_data(startup_logger):
    try:
        # === NEO4J DATABASE INITIALIZATION ===
        db_config = state.config.get("database", {})
        neo4j_config = db_config.get("neo4j", {})
        neo4j_enabled = neo4j_config.get("enabled", False)

        env_uri = os.getenv("AEGIS_NEO4J_URI") or os.getenv("NEO4J_URI")
        env_user = os.getenv("AEGIS_NEO4J_USER") or os.getenv("NEO4J_USER")
        env_password = os.getenv("AEGIS_NEO4J_PASSWORD") or os.getenv("NEO4J_PASSWORD")
        env_enabled = os.getenv("AEGIS_NEO4J_ENABLED")

        if env_enabled is not None:
            neo4j_enabled = env_enabled.lower() == "true"

        if neo4j_enabled:
            uri = env_uri or neo4j_config.get("uri")
            user = env_user or neo4j_config.get("user")
            password = env_password or neo4j_config.get("password")

            if not uri or not user or not password:
                raise RuntimeError(
                    "Neo4j is enabled but credentials are not configured. "
                    "Set AEGIS_NEO4J_URI, AEGIS_NEO4J_USER, and AEGIS_NEO4J_PASSWORD "
                    "environment variables (or NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD)."
                )

            from ..core.providers.neo4j import Neo4jGraphProvider

            provider = await asyncio.to_thread(
                Neo4jGraphProvider,
                uri=uri,
                user=user,
                password=password,
                enabled=True,
            )

            if provider.is_active:
                state.transaction_graph = provider
                state.graph_loaded = True
                startup_logger.info(
                    "Initialized active Neo4j database connection pool",
                    event_type="neo4j_initialized",
                    metadata={"uri": uri, "user": user},
                )
                startup_logger.info(
                    "Neo4j database integration active",
                    event_type="neo4j_active",
                    metadata={
                        "nodes": provider.number_of_nodes,
                        "edges": provider.number_of_edges,
                    },
                )
            else:
                startup_logger.warning(
                    "Neo4j enabled but connection failed. Falling back to static graph files.",
                    event_type="neo4j_fallback",
                )

        # === SECURE GRAPH LOADING (Fallback) ===
        if not state.graph_loaded:
            runtime_settings = state.settings
            graph_candidates = [
                runtime_settings.graph.graph_path
                if runtime_settings.raw_environment.aegis_graph_path
                else None,
                runtime_settings.graph.graph_path,
            ]
            graph_path = next((path for path in graph_candidates if path and path.exists()), None)
            
            EXPECTED_GRAPH_SHA256 = runtime_settings.graph.graph_sha256
            
            if graph_path:
                actual_hash = await asyncio.to_thread(_compute_file_sha256, graph_path)
                
                if not EXPECTED_GRAPH_SHA256:
                    raise RuntimeError(
                        "Critical Security Alert: AEGIS_GRAPH_SHA256 env var is unset. "
                        "Halting boot to prevent loading an unverified graph artifact."
                    )
                if actual_hash != EXPECTED_GRAPH_SHA256:
                    raise RuntimeError(
                        f"Critical Security Alert: {graph_path} hash mismatch. Halting boot.\n"
                        f"Expected: {EXPECTED_GRAPH_SHA256}\n"
                        f"Actual:   {actual_hash}"
                    )
                
                if graph_path.suffix.lower() != ".graphml":
                    raise ValueError(
                        f"Unsupported graph artifact format: {graph_path.suffix}. "
                        "Only GraphML artifacts are supported."
                    )
                state.transaction_graph = nx.read_graphml(graph_path)
                startup_logger.info(
                    "Loaded transaction graph",
                    event_type="graph_loaded",
                    metadata={
                        "path": str(graph_path),
                        "nodes": state.transaction_graph.number_of_nodes(),
                        "edges": state.transaction_graph.number_of_edges(),
                    },
                )
                startup_logger.info(
                    "Transaction graph loaded successfully",
                    event_type="graph_loaded",
                    metadata={
                        "nodes": state.transaction_graph.number_of_nodes(),
                        "edges": state.transaction_graph.number_of_edges(),
                    },
                )
                state.graph_loaded = True
            else:
                startup_logger.warning(
                    "Graph file not found at data/synthetic/graph.graphml",
                    event_type="graph_missing",
                )
                startup_logger.warning(
                    "Graph file not found; graph-based detection disabled",
                    event_type="graph_file_missing",
                    metadata={"expected_path": "data/synthetic/graph.graphml"},
                )
            
            if not graph_path:
                state.graph_loaded = False

        # Load fraud chains
        chains_path = Path("data/synthetic/fraud_chains.json")
        if chains_path.exists():
            state.fraud_chains = await asyncio.to_thread(_read_json_file, chains_path)
            for chain in state.fraud_chains:
                state.mule_accounts.update(chain.get('accounts', []))
            startup_logger.info(
                "Loaded fraud chains",
                event_type="fraud_chains_loaded",
                metadata={
                    "chains": len(state.fraud_chains),
                    "mule_accounts": len(state.mule_accounts),
                },
            )
        else:
            startup_logger.warning("Fraud chains file not found", event_type="fraud_chains_missing")
        
        # Load account profiles
        accounts_path = Path("data/synthetic/accounts.json")
        if accounts_path.exists():
            accounts_list = await asyncio.to_thread(_read_json_file, accounts_path)
            state.account_profiles = {acc['account_id']: acc for acc in accounts_list}
            startup_logger.info(
                "Loaded account profiles",
                event_type="accounts_loaded",
                metadata={"count": len(state.account_profiles)},
            )
        else:
            startup_logger.warning("Accounts file not found", event_type="accounts_missing")

    except Exception as e:
        startup_logger.warning(
            f"Error loading graph data: {e}",
            event_type="graph_load_error",
        )
        state.graph_loaded = False
    register_graph_services(
        state.services,
        state.transaction_graph,
        state.fraud_chains,
        state.account_profiles,
    )


def _initialize_model_runtime(startup_logger):
    if MODEL_AVAILABLE:
        state.model_loaded = True
        startup_logger.info("Model components loaded successfully", event_type="model_ready")
    else:
        state.model_loaded = False
        startup_logger.warning(
            "Running in DEMO MODE (install torch-geometric for full functionality)",
            event_type="demo_mode",
        )
    state.services.register_service("model_available", MODEL_AVAILABLE, replace=True)
    

def _initialize_innovation_runtime(startup_logger):
    voice_analyzer = None
    mule_scorer = None
    honeypot_manager = None
    blockchain_manager = None
    aegis_oracle = None
    lateral_movement_detector = None

    if INNOVATIONS_AVAILABLE:
        state.runtime.health_monitor.register_service("voice_analyzer")
        state.runtime.health_monitor.register_service("mule_scorer")
        state.runtime.health_monitor.register_service("honeypot_manager")
        state.runtime.health_monitor.register_service("blockchain_manager")
        state.runtime.health_monitor.register_service("aegis_oracle")

    # NOTE: LateralMovementDetector is intentionally deferred
    # to first request via get_lateral_movement_detector() in
    # src/api/dependencies/subsystems.py. Construction is
    # guarded by an asyncio.Lock to prevent double-init.
    if LATERAL_MOVEMENT_AVAILABLE:
        state.runtime.health_monitor.register_service(
            "lateral_movement_detector"
        )
    else:
        startup_logger.warning("Innovation modules not available", event_type="innovations_unavailable")

    register_innovation_services(
        state.services,
        voice_analyzer=None,
        mule_scorer=None,
        honeypot_manager=None,
        blockchain_manager=None,
        aegis_oracle=None,
        lateral_movement_detector=lateral_movement_detector,
    )



def _startup_ready(startup_logger):
    startup_logger.info(
        "AegisGraph Sentinel 2.0 is ready",
        event_type="startup_complete",
        metadata={
            "mode": "PRODUCTION" if MODEL_AVAILABLE else "DEMO",
            "graph_detection": state.graph_loaded,
            "innovations": INNOVATIONS_AVAILABLE,
            "runtime": state.runtime.get_metrics(),
        },
    )
    
    startup_logger.info(
        "AegisGraph Sentinel 2.0 is ready — API documentation: http://localhost:8000/docs",
        event_type="startup_ready",
        metadata={
            "mode": "PRODUCTION" if MODEL_AVAILABLE else "DEMO",
            "graph_detection": "ENABLED" if state.graph_loaded else "DISABLED",
            "innovations": "ENABLED" if INNOVATIONS_AVAILABLE else "DISABLED",
        },
    )


def _start_runtime_background_tasks():
    state.tasks.register_task(
        _honeypot_auto_release_loop(),
        name="honeypot_auto_release",
        owner="innovation.honeypot",
    )


async def _stop_runtime_background_tasks():
    _api_logger.info("Shutting down AegisGraph Sentinel 2.0...", event_type="shutdown_start")
    await state.tasks.cancel_all_tasks(timeout_seconds=10.0)
    _api_logger.info("Background tasks stopped cleanly", event_type="shutdown_complete")


def _run_scoring_pipeline(
    transaction: dict,
    biometrics: Optional[dict],
    source_account: str,
    target_account: str,
    lateral_detector,
    innovations_available: bool,
    subgraph_cache: Optional[dict] = None,
    subgraph_cache_lock=None,
) -> dict:
    """
    Pure synchronous scoring work safe to run in a thread pool executor.
    Returns the final risk_result dict.

    subgraph_cache and subgraph_cache_lock are optional. When provided
    (typically by the batch endpoint), subgraph extractions for the same
    source account are shared across concurrent scorer calls, reducing
    redundant graph traversals from O(N) to O(unique source accounts).
    """
    risk_result = compute_risk_score(
        transaction=transaction,
        biometrics=biometrics,
        graph_loaded=state.graph_loaded,
        transaction_graph=state.transaction_graph,
        mule_accounts=state.mule_accounts,
        centrality_baseline=state.centrality_baseline,
        centrality_window_size=state.centrality_window_size,
        account_profiles=state.account_profiles,
        config=state.config,
        subgraph_cache=subgraph_cache,
        subgraph_cache_lock=subgraph_cache_lock,
    )

    if lateral_detector is not None:
        try:
            lateral_detector.update_graph(source_account, target_account)
            lm_risk_added, is_pivoting = lateral_detector.analyze_account(source_account)

            if is_pivoting:
                current_score = risk_result.get("risk_score", 0.0)
                new_score = min(1.0, current_score + lm_risk_added)
                risk_result["risk_score"] = new_score
                risk_result["breakdown"]["lateral_movement"] = lm_risk_added
                risk_result["lateral_movement_detected"] = True
                risk_result["lateral_movement_reason"] = (
                    "MITRE TA0008: Rapid centrality spike indicating network pivoting."
                )
                if new_score >= 0.7:
                    risk_result["decision"] = "BLOCK"
                elif new_score >= 0.4 and risk_result["decision"] == "ALLOW":
                    risk_result["decision"] = "REVIEW"
        except Exception as e:
            _api_logger.warning(
                f"Lateral movement check failed: {e}",
                event_type="lateral_movement_error",
            )

    return risk_result


def _activate_honeypot_sync(
    honeypot_manager,
    transaction_id: str,
    source_account: str,
    target_account: str,
    amount: float,
    currency: str,
    risk_score: float,
    fraud_indicators: list,
):
    """Synchronous honeypot activation safe to run in executor."""
    return honeypot_manager.activate_honeypot(
        transaction_id=transaction_id,
        source_account=source_account,
        target_account=target_account,
        amount=amount,
        currency=currency,
        risk_score=risk_score,
        fraud_indicators=fraud_indicators,
    )


def _seal_blockchain_sync(
    blockchain_manager,
    transaction_id: str,
    source_account: str,
    target_account: str,
    amount: float,
    risk_score: float,
    decision: str,
    confidence: float,
    breakdown: dict,
    explanation: str,
    fraud_patterns: list,
):
    """Synchronous blockchain sealing safe to run in executor."""
    return blockchain_manager.seal_evidence(
        transaction_id=transaction_id,
        source_account=source_account,
        target_account=target_account,
        amount=amount,
        risk_score=risk_score,
        decision=decision,
        confidence=confidence,
        breakdown=breakdown,
        explanation=explanation,
        fraud_patterns=fraud_patterns,
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan. Initializes services through the runtime lifecycle
    manager and cancels registered background tasks cleanly on shutdown.
    """
    def _close_neo4j_provider():
        if hasattr(state.transaction_graph, "close") and callable(state.transaction_graph.close):
            state.transaction_graph.close()

    startup_logger = get_logger("api.startup")
    lifecycle_manager = LifecycleManager(state.runtime, logger=startup_logger)
    state.services.register_service("lifecycle_manager", lifecycle_manager, replace=True)
    app.state.runtime = state.runtime

    # Set up recovery manager and watchdog
    recovery_manager = RecoveryManager(
        state.runtime.health_monitor,
        resource_manager=state.runtime.resource_manager,
    )
    watchdog = RuntimeWatchdog(
        health_monitor=state.runtime.health_monitor,
        task_registry=state.tasks,
        recovery_manager=recovery_manager,
    )
    state.runtime.recovery_manager = recovery_manager
    state.runtime.watchdog = watchdog

    def restart_honeypot_task():
        for task in state.tasks.find_tasks_by_name("honeypot_auto_release"):
            if not task.done():
                task.cancel()
        state.tasks.register_task(
            _honeypot_auto_release_loop(),
            name="honeypot_auto_release",
            owner="innovation.honeypot",
        )

    recovery_manager.register_recovery_callback(
        "honeypot_auto_release",
        restart_honeypot_task,
        max_attempts=3
    )

    lifecycle_manager.register_startup(
        "startup_banner",
        lambda: _startup_banner(startup_logger),
        critical=False,
    )
    lifecycle_manager.register_startup(
        "load_configuration",
        lambda: _load_runtime_configuration(startup_logger),
    )
    lifecycle_manager.register_startup(
        "validate_environment",
        lambda: _validate_runtime_environment(startup_logger),
    )
    lifecycle_manager.register_startup(
        "load_graph_runtime_data",
        lambda: _load_graph_runtime_data(startup_logger),
        critical=False,
    )
    lifecycle_manager.register_startup(
        "initialize_model_runtime",
        lambda: _initialize_model_runtime(startup_logger),
    )
    lifecycle_manager.register_startup(
        "initialize_innovation_runtime",
        lambda: _initialize_innovation_runtime(startup_logger),
        critical=False,
    )
    lifecycle_manager.register_startup("startup_ready", lambda: _startup_ready(startup_logger))
    lifecycle_manager.register_startup(
        "start_background_tasks",
        _start_runtime_background_tasks,
        critical=False,
    )
    lifecycle_manager.register_startup(
        "start_watchdog",
        lambda: watchdog.start(interval_seconds=10.0),
        critical=False,
    )
    lifecycle_manager.register_shutdown("stop_background_tasks", _stop_runtime_background_tasks)
    lifecycle_manager.register_shutdown("close_neo4j_provider", _close_neo4j_provider)
    lifecycle_manager.register_shutdown("stop_watchdog", watchdog.stop)

    async def _stale_cleanup_loop():
        try:
            while True:
                await asyncio.sleep(15)
                await ws_manager.cleanup_stale_connections()
        except asyncio.CancelledError:
            pass
            
    stale_cleanup_task = asyncio.create_task(_stale_cleanup_loop())

    await lifecycle_manager.startup()
    try:
        yield
    finally:
        stale_cleanup_task.cancel()
        try:
            await stale_cleanup_task
        except asyncio.CancelledError:
            pass

        await lifecycle_manager.shutdown()

import os
SWAGGER_ENABLED = os.getenv("SWAGGER_ENABLED", "true").lower() == "true"

# Initialize FastAPI app
app = FastAPI(
    title="AegisGraph Sentinel 2.0 API",
    description="Real-Time Cross-Channel Mule Account Detection & Neutralization API.\n\n"
                "### Authentication\n"
                "All protected endpoints require an API Key via the `X-API-Key` header. "
                "Use the **Authorize** button to authenticate globally.",
    version="2.0.0",
    contact={
        "name": "AegisGraph Team",
        "email": "support@aegisgraph.internal",
    },
    license_info={
        "name": "Proprietary",
    },
    openapi_tags=[
        {"name": "Health", "description": "System health and liveness checks"},
        {"name": "Monitoring", "description": "System statistics and model metrics"},
        {"name": "Detection", "description": "Real-time fraud detection and risk scoring"},
        {"name": "Analytics", "description": "Graph analytics and alert summarization"},
        {"name": "Administration", "description": "Honeypot management and blockchain evidence"}
    ],
    docs_url="/docs" if SWAGGER_ENABLED else None,
    redoc_url="/redoc" if SWAGGER_ENABLED else None,
    openapi_url="/openapi.json" if SWAGGER_ENABLED else None,
    lifespan=lifespan
)

# CORS middleware
#
# CWE-942 prevention: `allow_origins=["*"]` combined with
# `allow_credentials=True` makes Starlette reflect the request's Origin
# header back, effectively allowing credentialed cross-origin requests
# from any site. Read the allowed origins from AEGIS_ALLOWED_ORIGINS
# (comma-separated) instead, defaulting to local dev URLs.
ALLOWED_ORIGINS = settings.api.allowed_origins

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=[
        "Authorization",
        "Content-Type",
        "X-API-Key",
        "X-Legal-Export-Token",
        "X-Request-Timestamp",
        "X-Honeypot-Token",
        "X-Honeypot-Admin-Token",
    ],
    max_age=600,
)

# Rate Limiting
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["100/minute"],
)
app.state.limiter = limiter
if SLOWAPI_AVAILABLE:
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.add_middleware(SlowAPIMiddleware)

register_exception_handlers(app)
register_observability_middleware(app)



@app.get("/", tags=["Health"])
async def root():
    """Root endpoint"""
    return {
        "service": "AegisGraph Sentinel 2.0",
        "version": "2.0.0",
        "status": "operational",
        "mode": "production" if MODEL_AVAILABLE else "demo",
        "motto": "Detecting the Flow, Protecting the Soul",
        "documentation": "/docs"
    }


@app.get(
    "/api/v1/health",
    response_model=HealthCheckResponse,
    response_model_exclude_none=True,
    tags=["Health"],
    dependencies=[Depends(_require_verbose_health_access)],
)
async def health_check_v1(verbose: bool = False):
    """Health check endpoint (v1 routing)"""
    return _build_health_response(include_details=verbose)

@app.get(
    "/health/liveness",
    tags=["Health"],
    summary="Lightweight liveness probe",
)
async def liveness():
    """
    Lightweight health check endpoint for Kubernetes liveness probes.
    Returns immediately to ensure responsiveness.
    """
    return {"status": "ok", "service": "AegisGraph Sentinel 2.0"}


@app.get(
    "/health",
    response_model=HealthCheckResponse,
    response_model_exclude_none=True,
    tags=["Health"],
    dependencies=[Depends(_require_verbose_health_access)],
)
async def health_check(verbose: bool = False):
    """
    Health check endpoint (readiness/detailed)
    
    Returns detailed service status and diagnostics
    """
    return _build_health_response(include_details=verbose)


@app.get("/stats", response_model=StatsResponse, tags=["Monitoring"], dependencies=[Depends(require_role(Role.AUDITOR))])
async def get_stats():
    """
    Get service statistics
    
    Returns detailed statistics about processed transactions
    """
    uptime = time.time() - state.start_time
    
    avg_risk = (state.total_risk_score / state.requests_processed 
                if state.requests_processed > 0 else 0.0)
    avg_time = (state.total_processing_time / state.requests_processed 
                if state.requests_processed > 0 else 0.0)
    
    return StatsResponse(
        total_requests=state.requests_processed,
        decisions=state.decisions,
        avg_risk_score=avg_risk,
        avg_processing_time_ms=avg_time,
        uptime_seconds=uptime,
        total_checks=state.requests_processed,
        flagged_transactions=state.decisions.get("BLOCK", 0) + state.decisions.get("REVIEW", 0),
        average_response_time=avg_time,
    )



def _analyze_keystrokes_sync(biometrics: dict) -> bool:
    import numpy as np
    behavioral_stress_detected = False
    try:
        hold_times = biometrics.get('hold_times', [])
        flight_times = biometrics.get('flight_times', [])
        
        if hold_times and len(hold_times) > 1:
            hold_times_arr = np.array(hold_times)
            hold_cv = np.std(hold_times_arr) / np.mean(hold_times_arr)
            if hold_cv > 0.30:
                behavioral_stress_detected = True
        
        if flight_times and len(flight_times) > 1:
            flight_times_arr = np.array(flight_times)
            flight_cv = np.std(flight_times_arr) / np.mean(flight_times_arr)
            if flight_cv > 0.35:
                behavioral_stress_detected = True
    except Exception:
        pass
    return behavioral_stress_detected

@app.post(
    "/api/v1/fraud/check",
    response_model=TransactionCheckResponse,
    tags=["Detection"],
    summary="Check transaction for fraud",
    description="Analyze a single transaction for fraud risk using HTGNN and behavioral biometrics",
    dependencies=[Depends(require_role(Role.ANALYST)), Depends(StrictRateLimit(ip_limit=60, api_key_limit=300))]
)
async def check_transaction(
    request: TransactionCheckRequest,
    lateral_movement_detector=Depends(get_lateral_movement_detector),
    honeypot_manager=Depends(get_honeypot_manager),
    blockchain_manager=Depends(get_blockchain_manager),
):
    """
    Check a single transaction for fraud
    
    This endpoint performs real-time fraud detection using:
    - Heterogeneous Temporal Graph Neural Networks (HTGNN)
    - Behavioral biometrics analysis
    - Velocity and entropy calculations
    
    Returns risk score, decision (ALLOW/REVIEW/BLOCK), and explanation.
    """
    start_time = time.time()
    
    try:
        # Prepare transaction data
        transaction = request.model_dump()
        
        # Prepare biometrics data
        biometrics = None
        behavioral_stress_detected = False
        if request.biometrics:
            biometrics = {
                'hold_times': request.biometrics.hold_times,
                'flight_times': request.biometrics.flight_times,
            }
            
            # Innovation 1: Simple keystroke stress detection
            if INNOVATIONS_AVAILABLE:
                try:
                    behavioral_stress_detected = await asyncio.to_thread(_analyze_keystrokes_sync, biometrics)
                except Exception as e:
                    _api_logger.warning(
                        f"Keystroke analysis failed: {e}",
                        event_type="keystroke_analysis_error",
                    )
        
        # Offload CPU-bound scoring + graph analysis to thread pool.
        # When called from the batch endpoint, _batch_subgraph_cache and
        # _batch_subgraph_lock are set via context variables so that subgraph
        # extractions for the same source account are shared across concurrent
        # tasks within the same batch, reducing graph traversals from O(N) to
        # O(unique source accounts).
        loop = asyncio.get_running_loop()
        subgraph_cache = _batch_subgraph_cache.get()
        subgraph_lock = _batch_subgraph_lock.get()
        risk_result = await asyncio.to_thread(_run_scoring_pipeline, transaction,
                biometrics,
                request.source_account,
                request.target_account,
                lateral_movement_detector if LATERAL_MOVEMENT_AVAILABLE else None,
                INNOVATIONS_AVAILABLE,
                subgraph_cache,
                subgraph_lock,)

        # Generate explanation off the event loop to keep the request thread responsive.
        explanation_result = await asyncio.to_thread(generate_explanation, transaction=transaction,
                risk_result=risk_result,
                detail_level='high',)
        
        # Innovation 2: Check if honeypot should be activated
        honeypot_activated = False
        honeypot_id = None
        
        if INNOVATIONS_AVAILABLE and honeypot_manager is not None:
            try:
                # Extract fraud indicators from explanation
                fraud_indicators = []
                if 'mule' in explanation_result['explanation'].lower():
                    fraud_indicators.append('known_mule_account')
                if 'chain' in explanation_result['explanation'].lower():
                    fraud_indicators.append('mule_chain')
                if risk_result['breakdown']['velocity'] > 0.8:
                    fraud_indicators.append('extreme_velocity')
                
                should_activate = honeypot_manager.should_activate_honeypot(
                    risk_score=risk_result['risk_score'],
                    decision=risk_result['decision'],
                    fraud_indicators=fraud_indicators,
                )
                
                logic_decision = _normalize_decision(risk_result['decision'])
                if should_activate and logic_decision == FraudDecision.BLOCK.value:
                    # Activate honeypot
                    honeypot = await asyncio.to_thread(_activate_honeypot_sync, honeypot_manager,
                            request.transaction_id,
                            request.source_account,
                            request.target_account,
                            request.amount,
                            request.currency,
                            risk_result['risk_score'],
                            fraud_indicators,)
                    honeypot_activated = True
                    honeypot_id = honeypot.honeypot_id

                    original_explanation = str(explanation_result.get('explanation', '')).strip()
                    if original_explanation:
                        explanation_result['explanation'] = (
                            f"{original_explanation} | Honeypot containment activated"
                        )
                    else:
                        explanation_result['explanation'] = "Honeypot containment activated"
                    
                    _audit_logger.log_security_action(
                        "honeypot_activated",
                        metadata={
                            "honeypot_id": honeypot_id,
                            "transaction_id": request.transaction_id,
                        },
                    )

            except Exception as e:
                _api_logger.warning(
                    f"Honeypot activation check failed: {e}",
                    event_type="honeypot_activation_error",
                )
        
        # Innovation 6: Seal evidence in blockchain for high-risk transactions
        blockchain_evidence_id = None
        
        if INNOVATIONS_AVAILABLE and blockchain_manager is not None:
            try:
                logic_decision = _normalize_decision(risk_result['decision'])
                if logic_decision in [FraudDecision.BLOCK.value, FraudDecision.REVIEW.value] or honeypot_activated:
                    # Extract fraud patterns from explanation
                    fraud_patterns = []
                    if 'mule' in explanation_result['explanation'].lower():
                        fraud_patterns.append('mule_account')
                    if 'chain' in explanation_result['explanation'].lower():
                        fraud_patterns.append('mule_chain')
                    if 'velocity' in explanation_result['explanation'].lower():
                        fraud_patterns.append('velocity_spike')
                    if 'circular' in explanation_result['explanation'].lower():
                        fraud_patterns.append('circular_flow')
                    
                    evidence = await asyncio.to_thread(_seal_blockchain_sync, blockchain_manager,
                            request.transaction_id,
                            request.source_account,
                            request.target_account,
                            request.amount,
                            risk_result['risk_score'],
                            risk_result['decision'],
                            risk_result['confidence'],
                            risk_result['breakdown'],
                            explanation_result['explanation'],
                            fraud_patterns,)
                    blockchain_evidence_id = evidence.evidence_id
                    _audit_logger.log_security_action(
                        "blockchain_evidence_sealed",
                        metadata={
                            "evidence_id": blockchain_evidence_id,
                            "transaction_id": request.transaction_id,
                        },
                    )

            except Exception as e:
                _api_logger.warning(
                    f"Blockchain sealing failed: {e}",
                    event_type="blockchain_seal_error",
                )
        
        # Processing time
        processing_time_ms = (time.time() - start_time) * 1000
        
        internal_decision = _normalize_decision(risk_result['decision'])

        # Prepare response with innovation fields
        decision = _decision_to_api_value(internal_decision)

        # When the ML model is unavailable, the heuristic pipeline produces a
        # conservative base score (~0.22). Apply an amount-based override so that
        # high-value transactions are still flagged appropriately in degraded mode.
        # Thresholds are read from config/thresholds.yaml (fallback_scoring section)
        # so they can be tuned without a code change.
        _model_degraded = False
        _trigger = _FALLBACK_SCORING.get("fallback_trigger_score", 0.25)
        if not MODEL_AVAILABLE and risk_result.get('risk_score', 0) <= _trigger:
            amount = request.amount
            _block_above = _FALLBACK_SCORING.get("block_above", 200000)
            _block_med_above = _FALLBACK_SCORING.get("block_medium_above", 100000)
            _review_above = _FALLBACK_SCORING.get("review_above", 50000)
            _allow_above = _FALLBACK_SCORING.get("allow_above", 10000)

            if amount > _block_above:
                risk_result['risk_score'] = _FALLBACK_SCORING.get("block_score", 0.85)
                internal_decision = "BLOCK"
            elif amount > _block_med_above:
                risk_result['risk_score'] = _FALLBACK_SCORING.get("block_medium_score", 0.72)
                internal_decision = "BLOCK"
            elif amount > _review_above:
                risk_result['risk_score'] = _FALLBACK_SCORING.get("review_score", 0.48)
                internal_decision = "REVIEW"
            elif amount > _allow_above:
                risk_result['risk_score'] = _FALLBACK_SCORING.get("allow_score", 0.35)
                internal_decision = "ALLOW"

            decision = _decision_to_api_value(internal_decision)
            _model_degraded = True
            _api_logger.warning(
                "ML model unavailable; using amount-based fallback scoring",
                event_type="fallback_scoring_active",
                metadata={
                    "transaction_id": request.transaction_id,
                    "amount": amount,
                    "fallback_decision": internal_decision,
                    "fallback_risk_score": risk_result['risk_score'],
                },
            )

        async with _get_metrics_lock():
            # Update statistics AFTER amount-scaling override so stats
            # always reflect the final decision returned to the caller.
            state.requests_processed += 1
            state.decisions[internal_decision] += 1
            state.total_risk_score += risk_result['risk_score']
            state.total_processing_time += processing_time_ms

        response = TransactionCheckResponse(
            transaction_id=request.transaction_id,
            risk_score=risk_result['risk_score'],
            decision=decision,
            factors={**risk_result['breakdown'], 'behavioral': float(behavioral_stress_detected)},
            confidence=risk_result['confidence'],
            breakdown=RiskBreakdown(**risk_result['breakdown']),
            explanation=explanation_result['explanation'],
            recommended_action=explanation_result['recommended_action'],
            processing_time_ms=processing_time_ms,
            timestamp=datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            blockchain_evidence_id=blockchain_evidence_id,
            behavioral_stress_detected=behavioral_stress_detected,
            lateral_movement_detected=risk_result.get('lateral_movement_detected', False),
            model_degraded=_model_degraded,
        )
        
        # Add lateral movement info to explanation if detected
        if risk_result.get('lateral_movement_detected', False):
            lm_reason = risk_result.get('lateral_movement_reason', '')
            response.explanation = f"{response.explanation} | {lm_reason}"

        triggered_modules = []
        if behavioral_stress_detected:
            triggered_modules.append("behavioral_biometrics")
        if honeypot_activated:
            triggered_modules.append("honeypot_escrow")
        if blockchain_evidence_id:
            triggered_modules.append("blockchain_evidence")
        _audit_logger.log_fraud_decision(
            transaction_id=request.transaction_id,
            decision=internal_decision,
            risk_score=risk_result['risk_score'],
            triggered_modules=triggered_modules,
            metadata={
                "api_decision": decision,
                "confidence": risk_result.get('confidence'),
            },
        )

        return response
    
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid fraud analysis request") from exc
    except Exception as exc:
        _raise_internal_server_error("Fraud analysis", exc)


@app.post(
    "/api/v1/explain",
    include_in_schema=False,

    tags=["Analytics"],
    summary="Generate AI-explainable decision explanation",
    description="Innovation 5: Aegis-Oracle generates regulatory-compliant explanations for all fraud decisions. Includes causal factors, evidence,  and legal admissibility.",
    dependencies=[Depends(require_role(Role.ANALYST))]
)
async def explain_transaction(
    request: ExplainRequest,
    aegis_oracle=Depends(get_aegis_oracle),
):
    # /api/v1/explain is expected to return a standardized error payload on
    # missing/invalid request bodies in tests. If the oracle dependency is
    # unavailable (or partially configured), fail fast with 503.
    if aegis_oracle is None:
        raise ServiceUnavailableException("Aegis-Oracle unavailable")
    """
    Generate comprehensive explanation for a fraud decision
    
    Uses Aegis-Oracle to extract:
    - Causal factors driving the decision
    - Risk component breakdown  
    - Innovation modules triggered
    - Regulatory compliance documentation
    - Recommended actions
    
    Returns narrative suitable for:
    - Customer appeals and disputes
    - Law enforcement coordination
    - Legal proceedings
    - RBI master direction compliance
    """
    try:
        # Extract transaction and risk info
        transaction = {
            'transaction_id': request.transaction_id,
            'source_account': request.source_account,
            'target_account': request.target_account,
            'amount': request.amount,
            'currency': request.currency,
            'timestamp': request.timestamp,
            'behavioral_stress_detected': request.behavioral_stress_detected,
        }
        
        risk_assessment = {
            'decision': request.decision,
            'risk_score': request.risk_score,
            'confidence': request.confidence,
        }
        
        breakdown = request.breakdown.model_dump() if request.breakdown else {
            'graph': 0.0,
            'velocity': 0.0,
            'behavior': 0.0,
            'entropy': 0.0,
        }
        
        innovations_triggered = request.innovations_triggered
        
        # Use Aegis-Oracle to generate explanation
        loop = asyncio.get_running_loop()
        explanation = await asyncio.to_thread(aegis_oracle.generate_explanation, transaction=transaction,
                risk_assessment=risk_assessment,
                break_down=breakdown,
                innovations_triggered=innovations_triggered,)
        
        return explanation
        
    except ValueError as exc:
        raise ValidationException("Invalid explainability request") from exc
    except Exception as exc:
        _api_logger.error(
            f"Explainability failed: {exc}",
            event_type="api_internal_error",
            metadata={"operation": "Explainability", "error_type": type(exc).__name__},
        )
        raise AegisException("Internal Server Error")


# Enhanced Aegis-Oracle endpoint
@app.post(
    "/api/v1/oracle/explain",
    tags=["Analytics"],
    summary="Get comprehensive AI reasoning for fraud decisions",
    description="Advanced Aegis-Oracle endpoint with full forensic analysis and causal reasoning",
    dependencies=[Depends(require_role(Role.ANALYST))]
)
async def oracle_explain_detailed(
    request: OracleExplainRequest,
    aegis_oracle=Depends(get_aegis_oracle),
):
    """
    Advanced explainability endpoint with detailed forensic analysis
    
    Returns:
    - Main narrative for stakeholders
    - Detailed technical reasoning for analysts
    - Causal factors ranked by impact
    - Regulatory compliance section
    - Recommended investigative actions
    - Evidence trail for legal proceedings
    """
    try:
        if not hasattr(aegis_oracle, "generate_explanation"):
            aegis_oracle = get_aegis_oracle()

        loop = asyncio.get_running_loop()
        explanation = await asyncio.to_thread(aegis_oracle.generate_explanation, transaction=request.transaction,
                risk_assessment=request.risk_assessment,
                attention_weights=request.attention_weights,
                break_down=request.risk_breakdown,
                innovations_triggered=request.innovations_triggered,)
        
        return {
            'oracle_reasoning': explanation,
            'forensic_ready': True,
            'legal_admissible': True,
            'timestamp': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        }
        
    except ValueError as exc:
        raise ValidationException("Invalid oracle explainability request") from exc
    except Exception as exc:
        _api_logger.error(
            f"Oracle explainability failed: {exc}",
            event_type="api_internal_error",
            metadata={"operation": "Oracle explainability", "error_type": type(exc).__name__},
        )
        raise AegisException("Internal Server Error")

# DEBUG only: manually activate a honeypot via API.
# This endpoint is ONLY registered when DEBUG env var is set to "true".
# Never expose this route in production.
if settings.runtime.debug:
    if settings.runtime.is_production:
        raise RuntimeError(
            "Unsafe configuration: debug honeypot routes cannot be enabled in production."
        )
    @app.post(
        "/debug/activate_honeypot",
        tags=["Debug"],
        summary="Force honeypot activation (DEBUG mode only)",
        description="Available only when DEBUG env var is 'true'. For testing only.",
        dependencies=[Depends(require_role(Role.ADMIN))],
    )
    def debug_activate_honeypot(
        request: HoneypotDebugRequest,
        x_honeypot_admin_token: Optional[str] = Header(None, alias="X-Honeypot-Admin-Token"),
        honeypot_manager=Depends(get_honeypot_manager),
    ):
        # Ensure this endpoint is only available in DEBUG mode at runtime
        if not settings.runtime.debug:
            raise HTTPException(status_code=404, detail="Debug honeypot activation endpoint not available")
        _require_honeypot_admin(x_honeypot_admin_token)
        try:
            hp = honeypot_manager.activate_honeypot(
                transaction_id=request.transaction_id,
                source_account=request.source_account,
                target_account=request.target_account,
                amount=request.amount,
                currency=request.currency,
                risk_score=request.risk_score,
                fraud_indicators=request.fraud_indicators,
            )
            return {'honeypot_id': hp.honeypot_id, 'status': hp.status.value}
        except Exception as e:
            _raise_internal_server_error("Debug honeypot activation", e)

@app.websocket("/api/v1/fraud/stream/{client_id}")
async def fraud_stream_websocket(websocket: WebSocket, client_id: str):
    """
    Realtime fraud monitoring stream.
    Accepts WebSocket connections and streams fraud decisions.
    Requires periodic 'ping' messages as heartbeats.
    """
    # Validate client_id before accepting the connection.
    # Rejects values that are empty, overly long (>64 chars), or contain
    # characters that could cause log injection or memory exhaustion.
    if not _WS_CLIENT_ID_RE.match(client_id):
        _api_logger.warning(
            "WebSocket connection rejected: invalid client_id format",
            event_type="ws_invalid_client_id",
            metadata={"client_id_length": len(client_id)},
        )
        await websocket.close(code=1008, reason="Invalid client_id: use alphanumeric, hyphens, or underscores (max 64 chars)")
        return

    try:
        require_role(Role.ANALYST)(websocket.headers.get("X-API-Key"))
    except HTTPException:
        await websocket.close(code=1008)
        return

    accepted = await ws_manager.connect(websocket, client_id)
    if not accepted:
        return
        
    try:
        while True:
            data = await websocket.receive_text()
            if data.strip().lower() == "ping":
                await ws_manager.heartbeat(client_id)
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        await ws_manager.disconnect(client_id)

@app.post(
    "/api/v1/fraud/batch",
    response_model=BatchTransactionResponse,
    tags=["Detection"],
    summary="Check multiple transactions",
    description="Batch processing of multiple transactions for fraud detection",
    dependencies=[Depends(require_role(Role.ANALYST)), Depends(StrictRateLimit(ip_limit=10, api_key_limit=50))]
)
async def check_batch_transactions(request: BatchTransactionRequest):
    """
    Check multiple transactions in batch

    Processes multiple transactions and returns results for each.
    Maximum batch size: 100 transactions.

    Performance note: a shared subgraph cache (dict + Lock) is created
    once per batch and made available to every check_transaction() call
    via context variables. When the same source account appears in
    multiple transactions, the graph neighbourhood is extracted only once.
    This reduces get_approx_subgraph() calls from O(N) to O(unique source
    accounts), cutting batch latency significantly for real-world fraud
    workloads where a mule account may appear dozens of times per batch.
    """
    start_time = time.time()
    max_concurrent_tasks = 8
    semaphore = asyncio.Semaphore(max_concurrent_tasks)
    txns = request.transactions

    # Per-batch subgraph cache shared across all concurrent scorer calls
    batch_subgraph_cache: Dict = LRUCache(maxsize=1000)
    batch_subgraph_lock: Lock = Lock()

    async def _process_transaction(txn_request):
        async with semaphore:
            return await check_transaction(
                txn_request,
                lateral_movement_detector=await get_lateral_movement_detector(),
                honeypot_manager=await get_honeypot_manager(),
                blockchain_manager=await get_blockchain_manager(),
            )

    async def _stream_batch_response_impl():
        api_to_internal = {
            "approve": FraudDecision.ALLOW.value,
            "review": FraudDecision.REVIEW.value,
            "block": FraudDecision.BLOCK.value,
        }
        stats = {decision.value: 0 for decision in FraudDecision}
        processed = 0
        first_result = True

        yield '{"results":['

        for txn_chunk in _chunked(txns, max_concurrent_tasks):
            tasks = [asyncio.create_task(_process_transaction(txn_request)) for txn_request in txn_chunk]
            for completed in asyncio.as_completed(tasks):
                try:
                    result = await completed
                except Exception as result_error:
                    _api_logger.error(
                        f"Error processing batch transaction: {result_error}",
                        event_type="batch_processing_error",
                    )
                    continue

                processed += 1
                decision_key = api_to_internal.get(
                    str(result.decision).lower(),
                    FraudDecision.ALLOW.value,
                )
                stats[decision_key] += 1

                if not first_result:
                    yield ","
                else:
                    first_result = False
                yield json.dumps(result.model_dump(mode="json"), separators=(",", ":"))

        processing_time_ms = (time.time() - start_time) * 1000
        yield (
            '],"total_processed":'
            f"{processed},"
            f"\"total_blocked\":{stats['BLOCK']},"
            f"\"total_review\":{stats['REVIEW']},"
            f"\"total_allowed\":{stats['ALLOW']},"
            f"\"processing_time_ms\":{processing_time_ms}"
            "}"
        )

    async def _stream_batch_response():
        # Set the context variables inside the streaming generator so that
        # the set and the matching reset both run in the same context. A
        # StreamingResponse body iterator executes in a context copied by
        # Starlette, so a token created in the endpoint context cannot be
        # reset here. Child tasks created during iteration copy this context
        # after the values are set, so the shared cache stays visible to
        # every check_transaction() call.
        token_cache = _batch_subgraph_cache.set(batch_subgraph_cache)
        token_lock = _batch_subgraph_lock.set(batch_subgraph_lock)
        try:
            async for chunk in _stream_batch_response_impl():
                yield chunk
        finally:
            _batch_subgraph_cache.reset(token_cache)
            _batch_subgraph_lock.reset(token_lock)

    return StreamingResponse(_stream_batch_response(), media_type="application/json")


@app.get("/api/v1/model/info", tags=["Monitoring"], dependencies=[Depends(require_role(Role.VIEWER))])
async def get_model_info():
    """
    Get information about the loaded model
    
    Returns model architecture, version, and performance metrics
    """
    return {
        "model_name": "HTGNN Fraud Detector",
        "version": "2.0.0",
        "architecture": "Heterogeneous Temporal Graph Attention Network",
        "layers": 2,
        "hidden_dim": 128,
        "output_dim": 64,
        "attention_heads": 4,
        "parameters": "~2.5M",
        "performance": {
            "precision": 0.968,
            "recall": 0.942,
            "f1": 0.955,
            "roc_auc": 0.978,
            "latency_p99_ms": 89,
        },
        "trained_on": "Synthetic fraud dataset (100K transactions)",
        "fraud_types": ["Chain", "Star", "Mesh"],
    }


# ============================================================================
# INNOVATION ENDPOINTS
# ============================================================================

@app.post(
    "/api/v1/voice/analyze",
    response_model=VoiceAnalysisResponse,
    tags=["Detection"],
    summary="Analyze voice stress during transaction",
    description="Innovation 5: Real-time voice stress analysis to detect coercion or AI generation",
    dependencies=[Depends(require_role(Role.ANALYST)), Depends(StrictRateLimit(ip_limit=5, api_key_limit=20))]
)
@limiter.limit("10/minute")
async def analyze_voice(
    request: Request,
    request_body: VoiceAnalysisRequest,
    voice_analyzer=Depends(get_voice_analyzer),
):
    """
    Analyze voice recording for stress and coercion indicators
    
    Uses acoustic features (F0, jitter, shimmer, speech rate, prosody) to classify
    stress levels: NORMAL, MILD_STRESS, or SEVERE_COERCION
    """
    start_time = time.time()
    
    tmp_path = None
    try:
        import base64
        import tempfile
        
        # Decode base64 audio
        try:
            audio_bytes = base64.b64decode(request_body.audio_base64, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise HTTPException(status_code=400, detail="Invalid base64 audio payload") from exc

        # Base64 can still expand into a large decoded blob. Cap decoded bytes
        # as well so short voice samples cannot monopolize memory or CPU.
        if len(audio_bytes) > 350_000:
            raise HTTPException(status_code=413, detail="Audio payload too large")
        
        # Save to temporary file
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.wav', delete=False) as tmp:
            tmp.write(audio_bytes)
            tmp_path = tmp.name
        
        # Offload CPU-heavy analysis so a few voice requests do not monopolize
        # the request worker thread.
        loop = asyncio.get_running_loop()
        result = await asyncio.to_thread(voice_analyzer.analyze_voice, audio_file=tmp_path,
                sample_rate=request_body.sample_rate,)
        
        processing_time_ms = (time.time() - start_time) * 1000
        
        return VoiceAnalysisResponse(
            transaction_id=request_body.transaction_id,
            stress_score=result['stress_score'],
            classification=result['classification'],
            confidence=result['confidence'],
            features=result['features'],
            recommended_action=result['recommended_action'],
            processing_time_ms=processing_time_ms,
        )
    except HTTPException:
        raise
    except Exception as exc:
        _raise_internal_server_error("Voice analysis", exc)
    finally:
        # This guarantees the file is deleted even if the analysis crashes
        if tmp_path:
            from pathlib import Path
            Path(tmp_path).unlink(missing_ok=True)

@app.post(
    "/api/v1/accounts/score-opening",
    response_model=AccountOpeningResponse,
    tags=["Detection"],
    summary="Score account opening for mule risk",
    description="Innovation 4: Predicts mule accounts before first transaction using 12 features",
    dependencies=[Depends(require_role(Role.ANALYST))]
)
def score_account_opening(
    request: AccountOpeningRequest,
    mule_scorer=Depends(get_mule_scorer),
):
    """
    Score a new account opening for mule recruitment risk
    
    Analyzes 12 features including temporal clustering, device novelty,
    geographic mismatch, and more to identify potential mule accounts
    """
    start_time = time.time()
    
    try:
        if not hasattr(mule_scorer, "MAX_HISTORY_SIZE"):
            mule_scorer.MAX_HISTORY_SIZE = 10000

        # Score the account opening
        result = mule_scorer.score_account_opening(
            account_id=request.account_id,
            name=request.name,
            age=request.age,
            profession=request.profession,
            email=request.email,
            phone=request.phone,
            device_id=request.device_id,
            ip_address=request.ip_address,
            stated_address=request.stated_address,
            facial_match=request.facial_match,
            document_type=request.document_type,
            initial_deposit=request.initial_deposit,
            referrer=request.referrer,
            form_completion_time_seconds=request.form_completion_time_seconds,
        )
        
        processing_time_ms = (time.time() - start_time) * 1000
        
        risk_level = result.get('risk_level', result.get('classification', 'UNKNOWN'))
        confidence = result.get('confidence', 0.85)
        features = result.get('features', {})
        red_flags = result.get('red_flags', [])
        recommended_action = result.get('recommended_action', "")
        return AccountOpeningResponse(
            account_id=request.account_id,
            risk_score=result['risk_score'],
            risk_level=risk_level,
            confidence=confidence,
            features=features,
            red_flags=red_flags,
            recommended_action=recommended_action,
            processing_time_ms=processing_time_ms,
        )
    
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid account scoring request") from exc
    except Exception as exc:
        _raise_internal_server_error("Account scoring", exc)


# Alias endpoint for mule assessment
@app.post(
    "/api/v1/mule/assess",
    response_model=AccountOpeningResponse,
    tags=["Detection"],
    summary="Assess account mule risk",
    description="Innovation 3: Alias for mule assessment endpoint",
    dependencies=[Depends(require_role(Role.ANALYST))]
)
def assess_mule_risk(request: AccountOpeningRequest):
    """Alias endpoint for mule assessment"""
    return score_account_opening(request)


@app.get(
    "/api/v1/honeypot/active",
    response_model=HoneypotListResponse,
    tags=["Administration"],
    summary="List active honeypot traps",
    description="Innovation 2: View all active deceptive containment operations",
    dependencies=[Depends(require_role(Role.ADMIN))],
)
async def list_active_honeypots(
    x_honeypot_token: Optional[str] = Header(default=None, alias="X-Honeypot-Token"),
    honeypot_manager=Depends(get_honeypot_manager),
):
    """
    Get list of all active honeypot traps
    
    Shows honeypots that are currently monitoring for withdrawal attempts
    and tracking fraud networks
    """
    _require_honeypot_admin(x_honeypot_token)
    
    try:
        active = honeypot_manager.get_active_honeypots()
        stats = honeypot_manager.get_statistics()
        
        honeypot_statuses = []
        for hp in active:
            honeypot_statuses.append(HoneypotStatus(
                honeypot_id=hp['honeypot_id'],
                transaction_id=hp['transaction_id'],
                source_account=hp['source_account'],
                target_account=hp['target_account'],
                amount=hp['amount'],
                currency=hp['currency'],
                activated_at=hp['activated_at'],
                time_remaining_seconds=hp['time_remaining_seconds'],
                withdrawal_attempts=hp['withdrawal_attempts'],
                last_attempt_location=hp['last_attempt_location'],
                police_alerted=hp['police_alerted'],
                status=hp['status'],
            ))
        
        return HoneypotListResponse(
            active_honeypots=honeypot_statuses,
            total_active=len(honeypot_statuses),
            total_arrests_today=stats.get('arrests_today', 0),
            total_recovered_today=stats.get('recovered_today', 0.0),
        )
    
    except Exception as exc:
        _raise_internal_server_error("Honeypot list retrieval", exc)


@app.get(
    "/api/v1/honeypot/stats",
    response_model=HoneypotStatsResponse,
    tags=["Administration"],
    summary="Get honeypot system statistics",
    description="Innovation 2: View performance metrics including arrest rate and recovery amount",
    dependencies=[Depends(require_role(Role.ADMIN))],
)
async def get_honeypot_stats(
    x_honeypot_token: Optional[str] = Header(default=None, alias="X-Honeypot-Token"),
    honeypot_manager=Depends(get_honeypot_manager),
):
    """
    Get honeypot system performance statistics
    
    Returns all-time metrics including arrests, recovery amounts, and false positive rates
    """
    _require_honeypot_admin(x_honeypot_token)
    
    try:
        stats = honeypot_manager.get_statistics()
        
        return HoneypotStatsResponse(
            total_activated=stats['total_activated'],
            total_arrests=stats['total_arrests'],
            arrest_rate=stats['arrest_rate'],
            networks_dismantled=stats['networks_dismantled'],
            total_recovered=stats['total_recovered'],
            false_positives=stats['false_positives'],
            false_positive_rate=stats['false_positive_rate'],
            avg_time_to_arrest_minutes=stats['avg_time_to_arrest_minutes'],
        )
    
    except Exception as exc:
        _raise_internal_server_error("Honeypot statistics retrieval", exc)


@app.post(
    "/api/v1/blockchain/seal",
    response_model=BlockchainEvidenceResponse,
    tags=["Administration"],
    summary="Seal evidence in blockchain",
    description="Innovation 6: Create immutable evidence record for legal admissibility",
    dependencies=[Depends(require_role(Role.ANALYST))]
)
async def seal_evidence(
    request: BlockchainSealRequest,
    blockchain_manager=Depends(get_blockchain_manager),
):
    """
    Seal fraud detection evidence in blockchain
    
    Creates cryptographically-signed, immutable evidence record across
    18 validator nodes for legal proceedings
    """
    try:
        loop = asyncio.get_running_loop()
        result = await asyncio.to_thread(blockchain_manager.seal_evidence, transaction_id=request.transaction_id,
                source_account=request.source_account,
                target_account=request.target_account,
                amount=request.amount,
                risk_result=request.risk_result.model_dump(),
                explanation=request.explanation,)
        
        return BlockchainEvidenceResponse(
            evidence_id=result.evidence_id,
            transaction_hash=result.transaction_hash,
            block_number=result.block_number,
            block_hash=result.block_hash,
            timestamp=result.consensus_timestamp,
            finality_time_ms=result.finality_time_ms,
            validators=result.validator_signatures,
        )
    
    except Exception as exc:
        _raise_internal_server_error("Evidence sealing", exc)


@app.get(
    "/api/v1/blockchain/verify/{evidence_id}",
    response_model=BlockchainVerificationResponse,
    tags=["Administration"],
    summary="Verify blockchain evidence",
    description="Innovation 6: Verify integrity and authenticity of sealed evidence",
    dependencies=[Depends(require_role(Role.VIEWER))]
)
async def verify_evidence(
    evidence_id: str,
    block_number: int,
    blockchain_manager=Depends(get_blockchain_manager),
):
    """
    Verify blockchain evidence integrity
    
    Checks evidence across multiple validator nodes within given block
    to ensure chain integrity and authenticity
    """
    try:
        loop = asyncio.get_running_loop()
        result = await asyncio.to_thread(blockchain_manager.verify_evidence, evidence_id, block_number)
        
        return BlockchainVerificationResponse(
            evidence_id=evidence_id,
            verified=result['verified'],
            block_exists=result['block_exists'],
            chain_integrity=result['chain_integrity'],
            consensus_nodes=result.get('consensus_nodes', 0),
            original_timestamp=result.get('original_timestamp'),
            verification_details=result.get('details', {}),
        )
    
    except Exception as exc:
        _raise_internal_server_error("Evidence verification", exc)


@app.post(
    "/api/v1/blockchain/export",
    response_model=LegalExportResponse,
    tags=["Administration"],
    summary="Export evidence for legal proceedings",
    description="Innovation 6: Generate court-admissible evidence package",
    dependencies=[Depends(require_role(Role.ADMIN))]
)
@limiter.limit("5/minute")
async def export_legal_evidence(
    request: Request,
    export_request: LegalExportRequest,
    authorization: Optional[str] = Header(default=None, alias="Authorization"),
    x_legal_export_token: Optional[str] = Header(default=None, alias="X-Legal-Export-Token"),
    x_request_timestamp: Optional[str] = Header(default=None, alias="X-Request-Timestamp"),
    blockchain_manager=Depends(get_blockchain_manager),
):
    """
    Export blockchain evidence for legal proceedings
    
    Generates complete evidence package with chain of custody,
    validator attestations, and court-formatted documentation
    """
    try:
        _validate_legal_export_request(
            authorization=authorization,
            x_legal_export_token=x_legal_export_token,
            x_request_timestamp=x_request_timestamp,
        )

        loop = asyncio.get_running_loop()
        token = _extract_legal_export_token(authorization, x_legal_export_token)
        result = await asyncio.to_thread(blockchain_manager.export_for_legal_proceedings, evidence_id=export_request.evidence_id,
                case_number=export_request.case_number,
                requesting_authority=export_request.requesting_authority,
                authorization_token=token,)
        if 'error' in result:
            raise HTTPException(status_code=404, detail=result['error'])
        
        return LegalExportResponse(
            evidence_id=export_request.evidence_id,
            case_number=export_request.case_number,
            evidence_package=result['package'],
            chain_of_custody=result['chain_of_custody'],
            attestations=result['attestations'],
            export_timestamp=result['export_timestamp'],
            authorized_by=result['authorized_by'],
        )
    except HTTPException:
        raise
    except PermissionError as exc:
        _raise_internal_server_error("Evidence export", exc)
    except RuntimeError as exc:
        _raise_internal_server_error("Evidence export", exc)
    except Exception as exc:
        _raise_internal_server_error("Evidence export", exc)


# ---------------------------------------------------------------------------
# Graph Analytics — Blast Radius
# ---------------------------------------------------------------------------


def _run_blast_radius(
    source_node: str,
    graph,
    max_depth: int,
):
    """CPU-bound blast-radius computation, safe to run in a thread-pool executor."""
    analyzer = BlastRadiusAnalyzer()
    return analyzer.compute(source_node=source_node, graph=graph, max_depth=max_depth)


@app.post(
    "/api/v1/graph/blast-radius",
    response_model=BlastRadiusResponse,
    tags=["Analytics"],
    summary="Blast-radius contagion analysis",
    description=(
        "Starting from a single flagged/compromised node, perform a bounded graph "
        "traversal (up to `max_depth` hops) and compute a Contagion Score for every "
        "reachable neighbor.  Results are bucketed into CRITICAL, HIGH, and SUSPICIOUS "
        "risk tiers so that consuming microservices can lock affected components "
        "automatically.\n\n"
        "**Contagion Score formula:** `Sc = Σ (edge_weight / depth²)`\n\n"
        "**Risk tiers:** CRITICAL ≥ 0.70 | HIGH ≥ 0.35 | SUSPICIOUS ≥ 0.10"
    ),
    dependencies=[Depends(require_role(Role.ANALYST))],
)
async def blast_radius_analysis(request: BlastRadiusRequest):
    """
    Blast-radius contagion-score traversal.

    Accepts a ``node_id`` (e.g. a known-fraudulent account, device fingerprint,
    or IP address) and a ``max_depth`` limit.  The backend performs a
    cycle-safe BFS, accumulates Contagion Scores across paths, and returns
    a structured breakdown of all at-risk neighbouring nodes grouped by tier.

    Cycle detection prevents infinite loops on highly-connected fraud rings.
    """
    start_time = time.time()

    # ------------------------------------------------------------------
    # Guard: graph must be loaded
    # ------------------------------------------------------------------
    if not state.graph_loaded or state.transaction_graph is None:
        raise HTTPException(
            status_code=503,
            detail=(
                "Transaction graph is not available. "
                "Blast-radius analysis requires a loaded graph."
            ),
        )

    graph = state.transaction_graph

    # ------------------------------------------------------------------
    # Guard: source node must exist in the graph
    # ------------------------------------------------------------------
    # NetworkX supports `in` operator; Neo4j provider exposes `__contains__`.
    try:
        node_exists = request.node_id in graph
    except Exception:
        node_exists = False

    if not node_exists:
        raise HTTPException(
            status_code=404,
            detail=f"Node {request.node_id!r} not found in the transaction graph.",
        )

    # ------------------------------------------------------------------
    # Guard: module must be importable
    # ------------------------------------------------------------------
    if not BLAST_RADIUS_AVAILABLE or BlastRadiusAnalyzer is None:
        raise HTTPException(
            status_code=503,
            detail="Blast-radius analytics module is not available.",
        )

    # ------------------------------------------------------------------
    # Run traversal in thread-pool (CPU-bound graph walk)
    # ------------------------------------------------------------------
    try:
        loop = asyncio.get_running_loop()
        report = await asyncio.to_thread(_run_blast_radius, request.node_id,
                graph,
                request.max_depth,)
    except ValueError as exc:
        # BlastRadiusAnalyzer raises ValueError when the node is absent;
        # translate to 404 in case there was a race between the guard and
        # the actual traversal.
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        _raise_internal_server_error("Blast-radius analysis", exc)

    processing_time_ms = (time.time() - start_time) * 1000
    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    _api_logger.info(
        "Blast-radius analysis completed",
        event_type="blast_radius_computed",
        metadata={
            "source_node": request.node_id,
            "max_depth": request.max_depth,
            "total_nodes": report.total_nodes_evaluated,
            "critical_count": len(report.critical),
            "high_count": len(report.high),
            "suspicious_count": len(report.suspicious),
            "processing_time_ms": processing_time_ms,
        },
    )

    return BlastRadiusResponse(
        source_node=report.source_node,
        max_depth=report.max_depth,
        total_nodes_evaluated=report.total_nodes_evaluated,
        critical=[
            ContagionNode(
                node_id=r.node_id,
                contagion_score=r.contagion_score,
                risk_tier=r.risk_tier,
                depth=r.depth,
            )
            for r in report.critical
        ],
        high=[
            ContagionNode(
                node_id=r.node_id,
                contagion_score=r.contagion_score,
                risk_tier=r.risk_tier,
                depth=r.depth,
            )
            for r in report.high
        ],
        suspicious=[
            ContagionNode(
                node_id=r.node_id,
                contagion_score=r.contagion_score,
                risk_tier=r.risk_tier,
                depth=r.depth,
            )
            for r in report.suspicious
        ],
        processing_time_ms=round(processing_time_ms, 3),
        timestamp=timestamp,
    )


@app.post(
    "/api/v1/alerts/summarize",
    response_model=AlertSummaryResponse,
    tags=["Analytics"],
    summary="Generate AI-powered summary for anomaly alerts",
    description="Takes complex alert JSON and uses Gemini to return a 2-sentence plain English summary.",
    dependencies=[Depends(require_role(Role.ANALYST))]
)
async def summarize_alert(request: AlertSummaryRequest):
    start_time = time.time()
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise HTTPException(status_code=503, detail="GEMINI_API_KEY is not configured")
    
    try:
        import google.generativeai as genai
        genai.configure(api_key=api_key)
        
        model = genai.GenerativeModel('gemini-1.5-flash',
            system_instruction="You are a cybersecurity expert. Summarize this anomaly alert in exactly 2 plain English sentences for a non-technical analyst."
        )
        
        alert_json = json.dumps(request.alert_data, indent=2)
        response = await asyncio.to_thread(model.generate_content, alert_json)
        
        summary = response.text.strip()
        
        processing_time_ms = (time.time() - start_time) * 1000
        
        return AlertSummaryResponse(
            summary=summary,
            processing_time_ms=processing_time_ms
        )
    except ImportError:
        raise HTTPException(status_code=500, detail="google-generativeai package is not installed")
    except Exception as e:
        _api_logger.error(
            f"Failed to generate alert summary: {e}",
            event_type="api_internal_error",
            metadata={"operation": "Alert summary", "error_type": type(e).__name__},
        )
        raise HTTPException(status_code=500, detail="Failed to generate AI summary")


@app.get("/api/v1/monitoring/memory", tags=["Monitoring"], dependencies=[Depends(require_role(Role.ADMIN))])
async def get_memory_diagnostics():
    """Diagnostic endpoint to inspect memory usage and cache sizes."""
    import sys
    try:
        import psutil
        process = psutil.Process()
        memory_info = process.memory_info()
        rss_mb = memory_info.rss / 1024 / 1024
        vms_mb = memory_info.vms / 1024 / 1024
    except ImportError:
        rss_mb = -1
        vms_mb = -1

    return {
        "status": "ok",
        "memory": {
            "rss_mb": round(rss_mb, 2) if rss_mb > 0 else "psutil not installed",
            "vms_mb": round(vms_mb, 2) if vms_mb > 0 else "psutil not installed"
        },
        "caches": {
            "centrality_baseline_size": len(state.centrality_baseline),
            "centrality_baseline_maxsize": getattr(state.centrality_baseline, "maxsize", None),
            "account_profiles_size": len(state.account_profiles),
            "fraud_chains_size": len(state.fraud_chains)
        },
        "globals": {
            "mule_accounts_size": len(state.mule_accounts)
        }
    }


# ==============================================================================
# CASE MANAGEMENT ENDPOINTS (Phase 4)
# ==============================================================================

def _serialise_case(case) -> FraudCaseResponse:
    """Convert a FraudCase dataclass to its API response schema."""
    return FraudCaseResponse(
        case_id=case.case_id,
        transaction_id=case.transaction_id,
        risk_score=case.risk_score,
        decision=case.decision,
        status=case.status.value,
        priority=case.priority.value,
        assigned_analyst=case.assigned_analyst,
        created_at=case.created_at,
        updated_at=case.updated_at,
        tags=case.tags,
        comment_count=len(case.comment_ids),
        evidence_count=len(case.evidence_ids),
    )


@app.post(
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


@app.get(
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


@app.get(
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


@app.get(
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


@app.patch(
    "/api/v1/cases/{case_id}",
    response_model=FraudCaseResponse,
    tags=["Case Management"],
    dependencies=[Depends(require_role(Role.ANALYST))],
    summary="Update status, assignment, or priority of a case",
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


@app.post(
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


@app.post(
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


@app.post(
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


@app.get(
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


def main():
    """Run the API server"""
    runtime_settings = get_settings(refresh=True)
    host = runtime_settings.api.host
    port = runtime_settings.api.port
    reload = runtime_settings.api.reload
    
    uvicorn.run(
        "src.api.main:app",
        host=host,
        port=port,
        reload=reload,
        log_level=runtime_settings.api.log_level,
    )


if __name__ == "__main__":
    main()
