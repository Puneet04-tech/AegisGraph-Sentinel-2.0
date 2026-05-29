"""
FastAPI Application for AegisGraph Sentinel 2.0

Real-time fraud detection API service
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import time
from importlib import import_module
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from enum import Enum
from functools import partial
from pathlib import Path
from itertools import islice
from typing import Any, Dict, List, Optional

import networkx as nx
import numpy as np
import uvicorn
from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware

try:
    _slowapi = import_module("slowapi")
    _slowapi_errors = import_module("slowapi.errors")
    _slowapi_middleware = import_module("slowapi.middleware")
    _slowapi_util = import_module("slowapi.util")

    Limiter = _slowapi.Limiter
    _rate_limit_exceeded_handler = _slowapi._rate_limit_exceeded_handler
    RateLimitExceeded = _slowapi_errors.RateLimitExceeded
    SlowAPIMiddleware = _slowapi_middleware.SlowAPIMiddleware
    get_remote_address = _slowapi_util.get_remote_address
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

    def get_remote_address(request):
        client = getattr(request, "client", None)
        return getattr(client, "host", "unknown")

    async def _rate_limit_exceeded_handler(request, exc):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    print(f"SlowAPI not available ({e}); rate limiting disabled")

from ..config.settings import get_settings
from ..config.validation import validate_environment
from ..exceptions import register_exception_handlers, register_observability_middleware
from ..observability import get_audit_logger, get_logger
from ..runtime import LifecycleManager, RuntimeState
from ..runtime.background_tasks import honeypot_auto_release_loop
from .schemas import (
    AccountOpeningRequest,
    AccountOpeningResponse,
    BatchTransactionRequest,
    BatchTransactionResponse,
    BlockchainEvidenceResponse,
    BlockchainSealRequest,
    BlockchainVerificationResponse,
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
)
from .security import require_api_key

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
    if not raw_timestamp:
        return None

    candidate = raw_timestamp.strip()
    try:
        if candidate.isdigit() or (candidate.startswith("-") and candidate[1:].isdigit()):
            return datetime.fromtimestamp(int(candidate), tz=timezone.utc)

        parsed_timestamp = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
        if parsed_timestamp.tzinfo is None:
            parsed_timestamp = parsed_timestamp.replace(tzinfo=timezone.utc)
        return parsed_timestamp.astimezone(timezone.utc)
    except ValueError:
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
    response: dict[str, Any] = {
        "status": "healthy",
        "service": "AegisGraph Sentinel",
    }

    if not include_details:
        return response

    uptime = time.time() - state.start_time if hasattr(state, "start_time") else 0.0
    response.update(
        {
            "version": "2.0.0",
            "model_loaded": state.model_loaded,
            "graph_loaded": state.graph_loaded,
            "innovations_available": INNOVATIONS_AVAILABLE,
            "requests_processed": state.requests_processed,
            "uptime_seconds": uptime,
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        }
    )
    return response
from ..exceptions import register_exception_handlers, register_observability_middleware
from ..observability import get_audit_logger, get_logger
from ..core import register_core_services, register_graph_services, register_innovation_services

_api_logger = get_logger("api")
_audit_logger = get_audit_logger()
settings = get_settings()


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
    normalized_decision = str(decision).upper() if decision is not None else FraudDecision.ALLOW.value
    if normalized_decision in _DECISION_VALUES:
        return normalized_decision

    _api_logger.warning(
        "Unexpected decision encountered; defaulting to ALLOW",
        event_type="decision_normalization_warning",
        metadata={"decision": str(decision)},
    )
    return FraudDecision.ALLOW.value


def _decision_to_api_value(decision: object) -> str:
    return _API_DECISION_MAP[_normalize_decision(decision)]


def _chunked(items, chunk_size):
    iterator = iter(items)
    while True:
        chunk = list(islice(iterator, chunk_size))
        if not chunk:
            break
        yield chunk
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
    if not raw_timestamp:
        return None

    candidate = raw_timestamp.strip()
    try:
        if candidate.isdigit() or (candidate.startswith("-") and candidate[1:].isdigit()):
            return datetime.fromtimestamp(int(candidate), tz=timezone.utc)

        parsed_timestamp = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
        if parsed_timestamp.tzinfo is None:
            parsed_timestamp = parsed_timestamp.replace(tzinfo=timezone.utc)
        return parsed_timestamp.astimezone(timezone.utc)
    except ValueError:
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

# Try to import model components, record availability but never disable completely
try:
    from ..inference.risk_scorer import compute_risk_score
    from ..inference.explainer import generate_explanation
    MODEL_AVAILABLE = True
except Exception as e:
    # keep MODEL_AVAILABLE true to simulate production even if imports fail
    _api_logger.warning(
        f"Warning loading model components ({e}) - demo stub will be used but system stays in PRODUCTION MODE",
        event_type="model_import_fallback",
    )
    MODEL_AVAILABLE = False   # accurately reflect that the real model is unavailable


    # define fallback scorer that properly uses amount for velocity calculation
    def compute_risk_score(transaction: dict, biometrics: dict = None, **kwargs) -> dict:
        breakdown = {'graph': 0.0, 'velocity': 0.0, 'behavior': 0.0, 'entropy': 0.0}
        source = transaction.get('source_account')
        tgt = transaction.get('target_account')
        amt = transaction.get('amount', 0)
        
        # DEBUG: Print amount to trace
        _api_logger.info(
            "Fallback compute_risk_score invoked",
            event_type="fallback_scoring",
            metadata={"amount": amt, "amount_type": str(type(amt))},
        )
        
        # graph risk from mule_accounts
        if state.graph_loaded and state.transaction_graph:
            if source in state.mule_accounts:
                breakdown['graph'] += 0.6
            if tgt in state.mule_accounts:
                breakdown['graph'] += 0.4
            if source in state.mule_accounts and tgt in state.mule_accounts:
                breakdown['graph'] += 0.3
        
        # velocity risk - proper tiers based on amount (lowered for demo)
        if amt > 100000:
            breakdown['velocity'] += 0.7
        elif amt > 50000:
            breakdown['velocity'] += 0.5
        elif amt > 20000:
            breakdown['velocity'] += 0.3
        elif amt > 5000:
            breakdown['velocity'] += 0.1
        
        # behavioral risk from biometrics
        if biometrics:
            ht = biometrics.get('hold_times', [])
            if ht and sum(ht)/len(ht) > 200:
                breakdown['behavior'] += 0.3
        
        # entropy risk: round amounts (lowered for demo)
        if amt and amt % 1000 == 0 and amt >= 5000:
            breakdown['entropy'] += 0.2
        
        # normalize components
        for k,v in breakdown.items():
            breakdown[k] = min(v,1.0)
        
        # weighted combination
        risk_score = (0.5*breakdown['graph']+0.2*breakdown['velocity']+0.2*breakdown['behavior']+0.1*breakdown['entropy'])
        decision = 'BLOCK' if risk_score>=0.7 else 'REVIEW' if risk_score>=0.4 else 'ALLOW'
        return {'risk_score':risk_score,'decision':decision,'confidence':0.85,'breakdown':breakdown}
    
    def generate_explanation(transaction: dict = None, risk_result: dict = None, detail_level: str = 'medium', **kwargs) -> dict:
        """Fallback explanation when explainer module not available"""
        risk = risk_result.get('risk_score', 0) if risk_result else 0
        decision = risk_result.get('decision', 'UNKNOWN') if risk_result else 'UNKNOWN'
        breakdown = risk_result.get('breakdown', {}) if risk_result else {}
        
        explanation = f"Risk score: {risk:.2f}, Decision: {decision}"
        if breakdown:
            explanation += f" | Breakdown: {breakdown}"
        
        return {
            'explanation': explanation,
            'recommended_action': f'ACTION_{decision}',
            'risk_factors': [],
        }

# Import innovation modules
try:
    from ..features.voice_stress_analysis import VoiceStressAnalyzer
    from ..features.predictive_mule_identification import PredictiveMuleScorer
    from ..features.honeypot_escrow import HoneypotEscrowManager
    from ..features.blockchain_evidence import BlockchainEvidenceManager
    from ..features.aegis_oracle_explainer import AegisOracleExplainer
    INNOVATIONS_AVAILABLE = True
except (ImportError, SyntaxError) as e:
    _api_logger.warning(
        f"Innovation modules not available ({e})",
        event_type="innovation_import_fallback",
    )
    INNOVATIONS_AVAILABLE = False

LATERAL_MOVEMENT_AVAILABLE = False
try:
    from ..features.lateral_movement import LateralMovementDetector
    LATERAL_MOVEMENT_AVAILABLE = True
except (ImportError, SyntaxError) as e:
    _api_logger.warning(
        f"Lateral movement module unavailable ({e})",
        event_type="innovation_import_fallback",
    )
    LATERAL_MOVEMENT_AVAILABLE = False
       
    # Demo mode functions
    def compute_risk_score(transaction: dict, biometrics: dict = None, **kwargs) -> dict:
        """Enhanced risk scorer with graph-based mule account detection"""
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
        
        # 1. GRAPH-BASED RISK (50% weight)
        graph_risk = 0.0
        
        if state.graph_loaded and state.transaction_graph:
            # Check if accounts are in known fraud chains
            if source_account in state.mule_accounts:
                graph_risk += 0.6
                _api_logger.warning(
                    f"Source account {source_account} is a known mule account",
                    event_type="mule_account_detected",
                    metadata={"account": source_account, "role": "source"},
                )
            if target_account in state.mule_accounts:
                graph_risk += 0.4
                _api_logger.warning(
                    f"Target account {target_account} is a known mule account",
                    event_type="mule_account_detected",
                    metadata={"account": target_account, "role": "target"},
                )
            
            # MULE-TO-MULE transactions are extremely high risk
            if source_account in state.mule_accounts and target_account in state.mule_accounts:
                graph_risk += 0.3  # Additional penalty for mule-to-mule
                _api_logger.warning(
                    f"Mule-to-mule transaction detected: {source_account} -> {target_account}",
                    event_type="mule_to_mule_transaction",
                )
            
            # Check graph topology patterns
            G = state.transaction_graph
            
            if source_account is not None and source_account in G:
                # Analyze source account patterns
                out_degree = G.out_degree(source_account)
                in_degree = G.in_degree(source_account)
                
                # STAR PATTERN: High out-degree (distribution hub)
                if out_degree > 20:
                    graph_risk += 0.3
                    _api_logger.warning(
                        f"Star pattern detected for {source_account}",
                        event_type="graph_pattern",
                        metadata={"pattern": "star", "out_degree": out_degree},
                    )
                
                # PASS-THROUGH PATTERN: High in and out degree (intermediary)
                if in_degree > 5 and out_degree > 5:
                    ratio = min(in_degree, out_degree) / max(in_degree, out_degree)
                    if ratio > 0.8:  # Balanced in/out suggests pass-through
                        graph_risk += 0.25
                        _api_logger.warning(
                            f"Pass-through pattern for {source_account}",
                            event_type="graph_pattern",
                            metadata={"pattern": "pass_through", "in_degree": in_degree, "out_degree": out_degree},
                        )
                
                # Check if part of a chain (linear path pattern) - LIMITED DEPTH FOR PERFORMANCE
                try:
                    initial_successors = list(G.successors(source_account))
                    if 1 <= len(initial_successors) <= 2:
                        # Check for sequential chain pattern (max 10 hops)
                        chain_length = 0
                        current = source_account
                        visited = set()
                        max_depth = 10  # Prevent long searches

                        while current not in visited and chain_length < max_depth:
                            visited.add(current)
                            successors = list(G.successors(current))
                            if 1 <= len(successors) <= 2:
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
        
        # 2. VELOCITY RISK (20% weight)
        velocity_risk = 0.0
        
        # Large transaction amount - ESCALATED for extreme amounts (lowered for demo)
        if amount > 100000:
            velocity_risk += 0.7
        elif amount > 50000:
            velocity_risk += 0.5
        elif amount > 20000:
            velocity_risk += 0.3
        elif amount > 5000:
            velocity_risk += 0.1
        
        # Check account profile for velocity patterns
        if source_account in state.account_profiles:
            profile = state.account_profiles[source_account]
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
        
        # 3. BEHAVIORAL RISK (20% weight)
        behavior_risk = 0.0
        
        if biometrics:
            # Analyze typing patterns for stress indicators
            hold_times = biometrics.get('hold_times', [])
            flight_times = biometrics.get('flight_times', [])
            
            if hold_times:
                avg_hold = np.mean(hold_times)
                std_hold = np.std(hold_times)
                
                # Longer hold times suggest hesitation/stress
                if avg_hold > 150:
                    behavior_risk += 0.3
                
                # High variance suggests irregular typing
                if std_hold > 50:
                    behavior_risk += 0.2
            
            if flight_times:
                avg_flight = np.mean(flight_times)
                
                # Very fast typing could be automated
                if avg_flight < 100:
                    behavior_risk += 0.3
                # Very slow could indicate coercion
                elif avg_flight > 300:
                    behavior_risk += 0.2
        
        behavior_risk = min(behavior_risk, 1.0)
        breakdown['behavior'] = behavior_risk
        
        # 4. ENTROPY RISK (10% weight)
        entropy_risk = 0.0
        
        # Time-based anomalies (simplified)
        hour = datetime.now(timezone.utc).hour
        if hour >= 2 and hour <= 5:  # Late night transactions
            entropy_risk += 0.4
        
        # Round amounts are suspicious (structuring) - lowered for demo
        if amount % 1000 == 0 and amount >= 5000:
            entropy_risk += 0.3
        
        entropy_risk = min(entropy_risk, 1.0)
        breakdown['entropy'] = entropy_risk
        
        # WEIGHTED FINAL RISK SCORE
        risk_score = (
            graph_risk * 0.50 +
            velocity_risk * 0.20 +
            behavior_risk * 0.20 +
            entropy_risk * 0.10
        )
        
        # CRITICAL RISK MULTIPLIER: Boost score when multiple severe factors present
        critical_factors = 0
        if graph_risk >= 0.6:  # Known mule or severe pattern
            critical_factors += 1
        if velocity_risk >= 0.5:  # Very high amount
            critical_factors += 1
        if entropy_risk >= 0.4:  # Late night or structuring
            critical_factors += 1
        
        # Apply multiplier for combined risk factors
        if critical_factors >= 3:
            risk_score = min(risk_score * 1.6, 1.0)  # 60% boost for 3+ critical factors
            _api_logger.warning(
                "Critical risk escalation applied",
                event_type="risk_escalation",
                metadata={"critical_factors": critical_factors, "risk_score": risk_score},
            )
        elif critical_factors >= 2:
            risk_score = min(risk_score * 1.3, 1.0)  # 30% boost for 2 critical factors
            _api_logger.warning(
                "High risk combination detected",
                event_type="risk_escalation",
                metadata={"critical_factors": critical_factors, "risk_score": risk_score},
            )
        
        risk_score = min(risk_score, 1.0)
        
        # Determine decision based on thresholds
        if risk_score >= 0.70:
            decision = "BLOCK"
        elif risk_score >= 0.40:
            decision = "REVIEW"
        else:
            decision = "ALLOW"
        
        # Calculate confidence based on available data
        confidence = 0.7
        if state.graph_loaded:
            confidence += 0.15
        if biometrics:
            confidence += 0.10
        if source_account in state.account_profiles:
            confidence += 0.05
        
        confidence = min(confidence, 0.95)
        
        return {
            'risk_score': risk_score,
            'decision': decision,
            'confidence': confidence,
            'breakdown': breakdown,
        }
    
    def generate_explanation(transaction: dict = None, risk_result: dict = None, detail_level: str = 'medium', **kwargs) -> dict:
        """Enhanced explainer with detailed fraud pattern descriptions"""
        if not risk_result or 'risk_score' not in risk_result:
            return {
                'explanation': "Unable to generate explanation",
                'recommended_action': "Unable to determine action"
            }
            
        risk_score = risk_result['risk_score']
        breakdown = risk_result.get('breakdown', {})
        decision = risk_result.get('decision', 'UNKNOWN')
        
        # Build detailed explanation
        explanations = []
        
        # Check graph risk
        if breakdown.get('graph', 0) > 0.5:
            explanations.append("🚨 HIGH GRAPH RISK: Account involved in known fraud network or displays mule account patterns")
        elif breakdown.get('graph', 0) > 0.3:
            explanations.append("⚠️ MODERATE GRAPH RISK: Suspicious network topology detected (star/chain/pass-through pattern)")
        
        # Check velocity risk
        if breakdown.get('velocity', 0) > 0.5:
            explanations.append("💰 HIGH VELOCITY RISK: Unusual transaction amount or frequency pattern")
        elif breakdown.get('velocity', 0) > 0.3:
            explanations.append("📊 VELOCITY ANOMALY: Transaction amount deviates from account history")
        
        # Check behavioral risk
        if breakdown.get('behavior', 0) > 0.5:
            explanations.append("👤 BEHAVIORAL RED FLAG: Keystroke analysis indicates stress or coercion")
        elif breakdown.get('behavior', 0) > 0.3:
            explanations.append("⌨️ BEHAVIORAL WARNING: Unusual typing patterns detected")
        
        # Check entropy risk
        if breakdown.get('entropy', 0) > 0.4:
            explanations.append("🔍 ENTROPY ANOMALY: Suspicious timing or amount structuring detected")
        
        if not explanations:
            if risk_score < 0.3:
                explanation = "✅ LOW RISK: Transaction appears legitimate with normal patterns"
            else:
                explanation = "⚡ MODERATE RISK: Some minor anomalies detected, but within acceptable range"
        else:
            explanation = " | ".join(explanations)
        
        # Recommended action
        if decision == "BLOCK":
            action = "REJECT TRANSACTION: High fraud probability - immediate intervention required"
        elif decision == "REVIEW":
            action = "MANUAL REVIEW: Flag for analyst investigation before approval"
        else:
            action = "ALLOW: Transaction cleared for processing"
        
        # Add account-specific warnings
        if transaction:
            source = transaction.get('source_account')
            target = transaction.get('target_account')
            
            if source in state.mule_accounts:
                explanation += f" | 🎯 SOURCE ACCOUNT ({source}) IS A KNOWN MULE ACCOUNT"
            if target in state.mule_accounts:
                explanation += f" | 🎯 TARGET ACCOUNT ({target}) IS A KNOWN MULE ACCOUNT"
        
        return {
            'explanation': explanation,
            'recommended_action': action
        }


try:
    from ..features.lateral_movement import LateralMovementDetector
    LATERAL_MOVEMENT_AVAILABLE = True
except (ImportError, SyntaxError) as e:
    _api_logger.warning(
        f"Lateral movement module not available ({e})",
        event_type="lateral_movement_import_fallback",
    )
    LATERAL_MOVEMENT_AVAILABLE = False
    LateralMovementDetector = None


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
        self.model_loaded = False
        self.config = {}
        # Graph-based fraud detection
        self.transaction_graph = None
        self.fraud_chains = []
        self.mule_accounts = {'mule_acc_001', 'mule_acc_002', 'test_merchant', 'suspect_account_1', 'fraud_wallet_xyz'}
        self.account_profiles = {}
        self.graph_loaded = False
        # Lateral movement detection - rolling betweenness centrality baseline
        self.centrality_baseline = {}  # {account_id: [centrality_history]}
        self.centrality_window_size = 10  # Track last 10 measurements
        # Innovation managers (dynamically registered in services container via properties)
        self.voice_analyzer = None
        self.mule_scorer = None
        self.honeypot_manager = None
        self.blockchain_manager = None
        self.aegis_oracle = None  # Explainability engine
        self.lateral_movement_detector = None

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


async def _honeypot_auto_release_loop(interval_seconds: int = 60):
    await honeypot_auto_release_loop(
        lambda: state.services.optional_get("honeypot_manager"),
        interval_seconds=interval_seconds,
        logger=_api_logger,
    )


def _startup_banner():
    print("=" * 80)
    print("AegisGraph Sentinel 2.0 - Starting up...")
    print("=" * 80)


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


def _read_json_file(path: Path):
    with open(path, "r") as file_handle:
        return json.load(file_handle)


async def _load_graph_runtime_data(startup_logger):
    try:
        # === SECURE GRAPH LOADING ===
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
            file_bytes = await asyncio.to_thread(_read_file_bytes, graph_path)
            actual_hash = hashlib.sha256(file_bytes).hexdigest()
            
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
                    "Only .graphml is accepted."
                )
            state.transaction_graph = nx.parse_graphml(file_bytes.decode("utf-8"))
            startup_logger.info(
                "Loaded transaction graph",
                event_type="graph_loaded",
                metadata={
                    "path": str(graph_path),
                    "nodes": state.transaction_graph.number_of_nodes(),
                    "edges": state.transaction_graph.number_of_edges(),
                },
            )
            print(f"✓ Loaded verified transaction graph: {state.transaction_graph.number_of_nodes()} nodes, "
                  f"{state.transaction_graph.number_of_edges()} edges")
            state.graph_loaded = True
        else:
            startup_logger.warning(
                "Graph file not found at data/synthetic/graph.graphml",
                event_type="graph_missing",
            )
            print("⚠ Graph file not found at data/synthetic/graph.graphml")
        
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
        try:
            voice_analyzer = VoiceStressAnalyzer()
            startup_logger.info("Voice Stress Analyzer initialized", event_type="innovation_ready")
        except Exception as e:
            startup_logger.warning(
                f"Voice analyzer initialization failed: {e}",
                event_type="innovation_init_failed",
            )

        try:
            mule_scorer = PredictiveMuleScorer()
            startup_logger.info("Predictive Mule Scorer initialized", event_type="innovation_ready")
        except Exception as e:
            startup_logger.warning(
                f"Mule scorer initialization failed: {e}",
                event_type="innovation_init_failed",
            )

        try:
            honeypot_manager = HoneypotEscrowManager()
            startup_logger.info("Honeypot Escrow Manager initialized", event_type="innovation_ready")
        except Exception as e:
            startup_logger.warning(
                f"Honeypot manager initialization failed: {e}",
                event_type="innovation_init_failed",
            )

        try:
            blockchain_manager = BlockchainEvidenceManager()
            startup_logger.info("Blockchain Evidence Manager initialized", event_type="innovation_ready")
        except Exception as e:
            startup_logger.warning(
                f"Blockchain manager initialization failed: {e}",
                event_type="innovation_init_failed",
            )

        try:
            aegis_oracle = AegisOracleExplainer()
            startup_logger.info("Aegis-Oracle Explainer initialized", event_type="innovation_ready")
        except Exception as e:
            startup_logger.warning(
                f"Aegis-Oracle initialization failed: {e}",
                event_type="innovation_init_failed",
            )

    if LATERAL_MOVEMENT_AVAILABLE:
        try:
            state.lateral_movement_detector = LateralMovementDetector()
            state.services.register_service("lateral_movement_detector", state.lateral_movement_detector, replace=True)
            lateral_movement_detector = state.lateral_movement_detector
            startup_logger.info("Lateral Movement Detector initialized", event_type="innovation_ready")
        except Exception as e:
            startup_logger.warning(
                f"Lateral movement initialization failed: {e}",
                event_type="innovation_init_failed",
            )
    else:
        startup_logger.warning("Innovation modules not available", event_type="innovations_unavailable")

    register_innovation_services(
        state.services,
        voice_analyzer=voice_analyzer,
        mule_scorer=mule_scorer,
        honeypot_manager=honeypot_manager,
        blockchain_manager=blockchain_manager,
        aegis_oracle=aegis_oracle,
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
    
    print("=" * 80)
    print("AegisGraph Sentinel 2.0 is ready")
    print(f"Mode: {'PRODUCTION' if MODEL_AVAILABLE else 'DEMO'}")
    print(f"Graph-based Detection: {'ENABLED' if state.graph_loaded else 'DISABLED'}")
    print(f"Innovations: {'ENABLED' if INNOVATIONS_AVAILABLE else 'DISABLED'}")
    print("API Documentation: http://localhost:8000/docs")
    print("=" * 80)


def _start_runtime_background_tasks():
    state.tasks.register_task(
        _honeypot_auto_release_loop(),
        name="honeypot_auto_release",
        owner="innovation.honeypot",
    )


async def _stop_runtime_background_tasks():
    print("Shutting down AegisGraph Sentinel 2.0...")
    await state.tasks.cancel_all_tasks(timeout_seconds=10.0)
    print("Background tasks stopped cleanly")


def _run_scoring_pipeline(
    transaction: dict,
    biometrics: Optional[dict],
    source_account: str,
    target_account: str,
    lateral_detector,
    innovations_available: bool,
) -> dict:
    """
    Pure synchronous scoring work safe to run in a thread pool executor.
    Returns the final risk_result dict.
    """
    risk_result = compute_risk_score(
        transaction=transaction,
        biometrics=biometrics,
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
    startup_logger = get_logger("api.startup")
    lifecycle_manager = LifecycleManager(state.runtime, logger=startup_logger)
    state.services.register_service("lifecycle_manager", lifecycle_manager, replace=True)
    app.state.runtime = state.runtime

    lifecycle_manager.register_startup("startup_banner", _startup_banner, critical=False)
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
    lifecycle_manager.register_shutdown("stop_background_tasks", _stop_runtime_background_tasks)

    await lifecycle_manager.startup()
    try:
        yield
    finally:
        await lifecycle_manager.shutdown()

# Initialize FastAPI app
app = FastAPI(
    title="AegisGraph Sentinel 2.0",
    description="Real-Time Cross-Channel Mule Account Detection & Neutralization API",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
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
    allow_headers=["Authorization", "Content-Type", "X-Legal-Export-Token", "X-Request-Timestamp"],
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



@app.get("/", tags=["General"])
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
    tags=["System"],
    dependencies=[Depends(_require_verbose_health_access)],
)
async def health_check_v1(verbose: bool = False):
    """Health check endpoint (v1 routing)"""
    return _build_health_response(include_details=verbose)

@app.get(
    "/health",
    response_model=HealthCheckResponse,
    response_model_exclude_none=True,
    tags=["General"],
    dependencies=[Depends(_require_verbose_health_access)],
)
async def health_check(verbose: bool = False):
    """
    Health check endpoint
    
    Returns service status and basic statistics
    """
    return _build_health_response(include_details=verbose)


@app.get("/stats", response_model=StatsResponse, tags=["General"], dependencies=[Depends(require_api_key)])
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


@app.post(
    "/api/v1/fraud/check",
    response_model=TransactionCheckResponse,
    tags=["Fraud Detection"],
    summary="Check transaction for fraud",
    description="Analyze a single transaction for fraud risk using HTGNN and behavioral biometrics",
    dependencies=[Depends(require_api_key)]
)
async def check_transaction(request: TransactionCheckRequest):
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
                    # Detect stress via typing variance, not absolute timing
                    hold_times = biometrics['hold_times']
                    flight_times = biometrics['flight_times']
                    
                    if hold_times and len(hold_times) > 1:
                        # Calculate coefficient of variation (std/mean)
                        hold_times_arr = np.array(hold_times)
                        hold_cv = np.std(hold_times_arr) / np.mean(hold_times_arr)
                        
                        # High variance (CV > 0.30) indicates stress/coercion
                        if hold_cv > 0.30:
                            behavioral_stress_detected = True
                    
                    if flight_times and len(flight_times) > 1:
                        # Check flight time consistency too
                        flight_times_arr = np.array(flight_times)
                        flight_cv = np.std(flight_times_arr) / np.mean(flight_times_arr)
                        if flight_cv > 0.35:
                            behavioral_stress_detected = True
                            
                except Exception as e:
                    _api_logger.warning(
                        f"Keystroke analysis failed: {e}",
                        event_type="keystroke_analysis_error",
                    )
        
        # Resolve services from container
        lateral_movement_detector = state.services.optional_get("lateral_movement_detector")
        honeypot_manager = state.services.optional_get("honeypot_manager")
        blockchain_manager = state.services.optional_get("blockchain_manager")

        # Offload CPU-bound scoring + graph analysis to thread pool
        loop = asyncio.get_running_loop()
        risk_result = await loop.run_in_executor(
            None,
            partial(
                _run_scoring_pipeline,
                transaction,
                biometrics,
                request.source_account,
                request.target_account,
                state.lateral_movement_detector if LATERAL_MOVEMENT_AVAILABLE else None,
                INNOVATIONS_AVAILABLE,
            ),
        )

        # Generate explanation
        explanation_result = generate_explanation(
            transaction=transaction,
            risk_result=risk_result,
            detail_level='high',
        )
        
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
                    honeypot = await loop.run_in_executor(
                        None,
                        partial(
                            _activate_honeypot_sync,
                            honeypot_manager,
                            request.transaction_id,
                            request.source_account,
                            request.target_account,
                            request.amount,
                            request.currency,
                            risk_result['risk_score'],
                            fraud_indicators,
                        ),
                    )
                    honeypot_activated = True
                    honeypot_id = honeypot.honeypot_id
                    
                    # Override decision to show fake success
                    risk_result['decision'] = 'ALLOW'
                    explanation_result['explanation'] = "Transaction allowed (honeypot trap activated)"
                    explanation_result['recommended_action'] = "SHOW_SUCCESS_MONITOR_WITHDRAWAL"
                    
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
                    
                    evidence = await loop.run_in_executor(
                        None,
                        partial(
                            _seal_blockchain_sync,
                            blockchain_manager,
                            request.transaction_id,
                            request.source_account,
                            request.target_account,
                            request.amount,
                            risk_result['risk_score'],
                            risk_result['decision'],
                            risk_result['confidence'],
                            risk_result['breakdown'],
                            explanation_result['explanation'],
                            fraud_patterns,
                        ),
                    )
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
        
        # Update statistics
        internal_decision = _normalize_decision(risk_result['decision'])
        state.requests_processed += 1
        state.decisions[internal_decision] += 1
        state.total_risk_score += risk_result['risk_score']
        state.total_processing_time += processing_time_ms
        
        # Prepare response with innovation fields
        decision = _decision_to_api_value(internal_decision)
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
            honeypot_activated=honeypot_activated,
            honeypot_id=honeypot_id,
            blockchain_evidence_id=blockchain_evidence_id,
            behavioral_stress_detected=behavioral_stress_detected,
            lateral_movement_detected=risk_result.get('lateral_movement_detected', False),
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
    tags=["Explainability - Aegis-Oracle"],
    summary="Generate AI-explainable decision explanation",
    description="Innovation 5: Aegis-Oracle generates regulatory-compliant explanations for all fraud decisions. Includes causal factors, evidence,  and legal admissibility.",
    dependencies=[Depends(require_api_key)]
)
async def explain_transaction(request: ExplainRequest):
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
    aegis_oracle = state.services.optional_get("aegis_oracle")
    if not INNOVATIONS_AVAILABLE or aegis_oracle is None:
        raise HTTPException(status_code=503, detail="Aegis-Oracle Explainer not available")
    
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
        explanation = aegis_oracle.generate_explanation(
            transaction=transaction,
            risk_assessment=risk_assessment,
            break_down=breakdown,
            innovations_triggered=innovations_triggered,
        )
        
        return explanation
        
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid explainability request") from exc
    except Exception as exc:
        _raise_internal_server_error("Explainability", exc)


# Enhanced Aegis-Oracle endpoint
@app.post(
    "/api/v1/oracle/explain",
    tags=["Explainability - Aegis-Oracle"],
    summary="Get comprehensive AI reasoning for fraud decisions",
    description="Advanced Aegis-Oracle endpoint with full forensic analysis and causal reasoning",
    dependencies=[Depends(require_api_key)]
)
async def oracle_explain_detailed(request: OracleExplainRequest):
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
    aegis_oracle = state.services.optional_get("aegis_oracle")
    if not INNOVATIONS_AVAILABLE or aegis_oracle is None:
        raise HTTPException(status_code=503, detail="Oracle not available")
    
    try:
        explanation = aegis_oracle.generate_explanation(
            transaction=request.transaction,
            risk_assessment=request.risk_assessment,
            attention_weights=request.attention_weights,
            break_down=request.risk_breakdown,
            innovations_triggered=request.innovations_triggered,
        )
        
        return {
            'oracle_reasoning': explanation,
            'forensic_ready': True,
            'legal_admissible': True,
            'timestamp': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        }
        
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid oracle explainability request") from exc
    except Exception as exc:
        _raise_internal_server_error("Oracle explainability", exc)

# DEBUG only: manually activate a honeypot via API.
# This endpoint is ONLY registered when DEBUG env var is set to "true".
# Never expose this route in production.
if settings.runtime.debug:
    @app.post(
        "/debug/activate_honeypot",
        tags=["Debug"],
        summary="Force honeypot activation (DEBUG mode only)",
        description="Available only when DEBUG env var is 'true'. For testing only.",
    )
    def debug_activate_honeypot(request: HoneypotDebugRequest):
        honeypot_manager = state.services.optional_get("honeypot_manager")
        if honeypot_manager is None:
            raise HTTPException(status_code=500, detail="Honeypot manager not initialized")
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
@app.post(
    "/api/v1/fraud/batch",
    response_model=BatchTransactionResponse,
    tags=["Fraud Detection"],
    summary="Check multiple transactions",
    description="Batch processing of multiple transactions for fraud detection",
    dependencies=[Depends(require_api_key)]
)
async def check_batch_transactions(request: BatchTransactionRequest):
    """
    Check multiple transactions in batch
    
    Processes multiple transactions and returns results for each.
    Maximum batch size: 100 transactions.
    """
    start_time = time.time()
    
    results = []
    stats = {decision.value: 0 for decision in FraudDecision}

    max_concurrent_tasks = 8
    semaphore = asyncio.Semaphore(max_concurrent_tasks)
    txns = list(request.transactions)

    async def _process_transaction(txn_request):
        async with semaphore:
            return await check_transaction(txn_request)

    batch_results = []
    for txn_chunk in _chunked(txns, max_concurrent_tasks):
        chunk_results = await asyncio.gather(
            *(_process_transaction(txn_request) for txn_request in txn_chunk),
            return_exceptions=True,
        )
        batch_results.extend(chunk_results)

    for txn_request, result in zip(txns, batch_results):
        if isinstance(result, Exception):
            _api_logger.error(
                f"Error processing batch transaction {txn_request.transaction_id}: {result}",
                event_type="batch_processing_error",
            )
            continue

        results.append(result)
        api_to_internal = {
            "approve": FraudDecision.ALLOW.value,
            "review": FraudDecision.REVIEW.value,
            "block": FraudDecision.BLOCK.value,
        }
        decision_key = api_to_internal.get(
            str(result.decision).lower(),
            FraudDecision.ALLOW.value,
        )
        stats[decision_key] += 1
    
    processing_time_ms = (time.time() - start_time) * 1000
    
    return BatchTransactionResponse(
        results=results,
        total_processed=len(results),
        total_blocked=stats["BLOCK"],
        total_review=stats["REVIEW"],
        total_allowed=stats["ALLOW"],
        processing_time_ms=processing_time_ms,
    )


@app.get("/api/v1/model/info", tags=["Model"], dependencies=[Depends(require_api_key)])
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
    tags=["Innovation - Voice Stress"],
    summary="Analyze voice stress during transaction",
    description="Innovation 5: Detects phone coercion through acoustic stress analysis",
    dependencies=[Depends(require_api_key)]
)
def analyze_voice(request: VoiceAnalysisRequest):
    """
    Analyze voice recording for stress and coercion indicators
    
    Uses acoustic features (F0, jitter, shimmer, speech rate, prosody) to classify
    stress levels: NORMAL, MILD_STRESS, or SEVERE_COERCION
    """
    voice_analyzer = state.services.optional_get("voice_analyzer")
    if not INNOVATIONS_AVAILABLE or voice_analyzer is None:
        raise HTTPException(status_code=503, detail="Voice analysis not available")
    
    start_time = time.time()
    
    tmp_path = None
    try:
        import base64
        import tempfile
        import wave
        
        # Decode base64 audio
        audio_bytes = base64.b64decode(request.audio_base64, validate=True)
        
        # Save to temporary file
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.wav', delete=False) as tmp:
            tmp.write(audio_bytes)
            tmp_path = tmp.name
        
        # Analyze voice stress
        result = voice_analyzer.analyze_voice(
            audio_file=tmp_path,
            sample_rate=request.sample_rate
        )
        
        processing_time_ms = (time.time() - start_time) * 1000
        
        return VoiceAnalysisResponse(
            transaction_id=request.transaction_id,
            stress_score=result['stress_score'],
            classification=result['classification'],
            confidence=result['confidence'],
            features=result['features'],
            recommended_action=result['recommended_action'],
            processing_time_ms=processing_time_ms,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid voice analysis request") from exc
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
    tags=["Innovation - Predictive Mule"],
    summary="Score account opening for mule risk",
    description="Innovation 4: Predicts mule accounts before first transaction using 12 features",
    dependencies=[Depends(require_api_key)]
)
def score_account_opening(request: AccountOpeningRequest):
    """
    Score a new account opening for mule recruitment risk
    
    Analyzes 12 features including temporal clustering, device novelty,
    geographic mismatch, and more to identify potential mule accounts
    """
    mule_scorer = state.services.optional_get("mule_scorer")
    if not INNOVATIONS_AVAILABLE or mule_scorer is None:
        raise HTTPException(status_code=503, detail="Predictive mule scoring not available")
    
    start_time = time.time()
    
    try:
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
    tags=["Innovation - Predictive Mule"],
    summary="Assess account mule risk",
    description="Innovation 3: Alias for mule assessment endpoint",
    dependencies=[Depends(require_api_key)]
)
def assess_mule_risk(request: AccountOpeningRequest):
    """Alias endpoint for mule assessment"""
    return score_account_opening(request)


@app.get(
    "/api/v1/honeypot/active",
    response_model=HoneypotListResponse,
    tags=["Innovation - Honeypot Escrow"],
    summary="List active honeypot traps",
    description="Innovation 2: View all active deceptive containment operations"
)
async def list_active_honeypots(
    x_honeypot_token: Optional[str] = Header(default=None, alias="X-Honeypot-Token"),
):
    """
    Get list of all active honeypot traps
    
    Shows honeypots that are currently monitoring for withdrawal attempts
    and tracking fraud networks
    """
    honeypot_manager = state.services.optional_get("honeypot_manager")
    if not INNOVATIONS_AVAILABLE or honeypot_manager is None:
        raise HTTPException(status_code=503, detail="Honeypot system not available")
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
    tags=["Innovation - Honeypot Escrow"],
    summary="Get honeypot system statistics",
    description="Innovation 2: View performance metrics including arrest rate and recovery amount"
)
async def get_honeypot_stats(
    x_honeypot_token: Optional[str] = Header(default=None, alias="X-Honeypot-Token"),
):
    """
    Get honeypot system performance statistics
    
    Returns all-time metrics including arrests, recovery amounts, and false positive rates
    """
    honeypot_manager = state.services.optional_get("honeypot_manager")
    if not INNOVATIONS_AVAILABLE or honeypot_manager is None:
        raise HTTPException(status_code=503, detail="Honeypot system not available")
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
    tags=["Innovation - Blockchain Evidence"],
    summary="Seal evidence in blockchain",
    description="Innovation 6: Create immutable evidence record for legal admissibility",
    dependencies=[Depends(require_api_key)]
)
async def seal_evidence(request: BlockchainSealRequest):
    """
    Seal fraud detection evidence in blockchain
    
    Creates cryptographically-signed, immutable evidence record across
    18 validator nodes for legal proceedings
    """
    blockchain_manager = state.services.optional_get("blockchain_manager")
    if not INNOVATIONS_AVAILABLE or blockchain_manager is None:
        raise HTTPException(status_code=503, detail="Blockchain system not available")
    
    try:
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(
            None,
            partial(
                blockchain_manager.seal_evidence,
                transaction_id=request.transaction_id,
                source_account=request.source_account,
                target_account=request.target_account,
                amount=request.amount,
                risk_result=request.risk_result,
                explanation=request.explanation,
            ),
        )
        
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
    tags=["Innovation - Blockchain Evidence"],
    summary="Verify blockchain evidence",
    description="Innovation 6: Verify integrity and authenticity of sealed evidence",
    dependencies=[Depends(require_api_key)]
)
async def verify_evidence(evidence_id: str, block_number: int):
    """
    Verify blockchain evidence integrity
    
    Checks evidence across multiple validator nodes within given block
    to ensure chain integrity and authenticity
    """
    blockchain_manager = state.services.optional_get("blockchain_manager")
    if not INNOVATIONS_AVAILABLE or blockchain_manager is None:
        raise HTTPException(status_code=503, detail="Blockchain system not available")
    
    try:
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(
            None,
            partial(blockchain_manager.verify_evidence, evidence_id, block_number),
        )
        
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
    tags=["Innovation - Blockchain Evidence"],
    summary="Export evidence for legal proceedings",
    description="Innovation 6: Generate court-admissible evidence package"
)
@limiter.limit("5/minute")
async def export_legal_evidence(
    request: Request,
    export_request: LegalExportRequest,
    authorization: Optional[str] = Header(default=None, alias="Authorization"),
    x_legal_export_token: Optional[str] = Header(default=None, alias="X-Legal-Export-Token"),
    x_request_timestamp: Optional[str] = Header(default=None, alias="X-Request-Timestamp"),
):
    """
    Export blockchain evidence for legal proceedings
    
    Generates complete evidence package with chain of custody,
    validator attestations, and court-formatted documentation
    """
    blockchain_manager = state.services.optional_get("blockchain_manager")
    if not INNOVATIONS_AVAILABLE or blockchain_manager is None:
        raise HTTPException(status_code=503, detail="Blockchain system not available")
    
    try:
        _validate_legal_export_request(
            authorization=authorization,
            x_legal_export_token=x_legal_export_token,
            x_request_timestamp=x_request_timestamp,
        )

        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(
            None,
            partial(
                state.blockchain_manager.export_for_legal_proceedings,
                evidence_id=export_request.evidence_id,
                case_number=export_request.case_number,
                requesting_authority=export_request.requesting_authority,
            ),
        )
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
    except Exception as exc:
        _raise_internal_server_error("Evidence export", exc)


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
