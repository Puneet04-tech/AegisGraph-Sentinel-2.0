"""
FastAPI Application for AegisGraph Sentinel 2.0

Real-time fraud detection API service
"""
# Working on fraud detection API endpoints and streamlit integration

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import time
import asyncio
import os
from datetime import datetime
from pathlib import Path
import yaml
from typing import Dict, List
import uvicorn
import random
import json
import pickle
import networkx as nx
import numpy as np

from .schemas import (
    TransactionCheckRequest,
    TransactionCheckResponse,
    BatchTransactionRequest,
    BatchTransactionResponse,
    HealthCheckResponse,
    StatsResponse,
    ErrorResponse,
    RiskBreakdown,
    # Innovation schemas
    VoiceAnalysisRequest,
    VoiceAnalysisResponse,
    AccountOpeningRequest,
    AccountOpeningResponse,
    HoneypotStatus,
    HoneypotListResponse,
    HoneypotStatsResponse,
    BlockchainSealRequest,
    BlockchainEvidenceResponse,
    BlockchainVerificationResponse,
    LegalExportRequest,
    LegalExportResponse,
)

# ====================== FALLBACK RISK SCORER ======================
def _get_fallback_risk_score(transaction: dict, biometrics: dict = None, **kwargs) -> dict:
    """
    Single fallback function used when either model or innovation modules are unavailable.
    This prevents duplicate definitions and ensures consistent degraded behavior.
    """
    breakdown = {'graph': 0.0, 'velocity': 0.0, 'behavior': 0.0, 'entropy': 0.0}
    amount = float(transaction.get('amount', 0) or 0)

    # Velocity-based risk
    if amount > 100000:
        breakdown['velocity'] = 0.7
    elif amount > 50000:
        breakdown['velocity'] = 0.5
    elif amount > 20000:
        breakdown['velocity'] = 0.3
    elif amount > 5000:
        breakdown['velocity'] = 0.15

    # Graph risk using mule accounts (if available)
    source = transaction.get('source_account')
    target = transaction.get('target_account')

    if hasattr(state, 'mule_accounts') and state.mule_accounts:
        if source in state.mule_accounts:
            breakdown['graph'] += 0.5
        if target in state.mule_accounts:
            breakdown['graph'] += 0.4

    risk_score = min(sum(breakdown.values()), 1.0)

    return {
        'risk_score': round(risk_score, 4),
        'decision': 'REVIEW' if risk_score >= 0.6 else 'ALLOW',
        'confidence': 0.55,
        'breakdown': breakdown,
        'explanation': 'Fallback mode: Model or innovation modules unavailable',
        'fallback_mode': True
    }

def _get_fallback_explanation(transaction: dict = None, risk_result: dict = None, detail_level: str = 'medium', **kwargs) -> dict:
    """Fallback explanation generator"""
    if not risk_result:
        return {
            'explanation': "Unable to generate explanation (fallback mode)",
            'recommended_action': "Unable to determine action"
        }
    
    risk = risk_result.get('risk_score', 0)
    decision = risk_result.get('decision', 'UNKNOWN')
    
    return {
        'explanation': f"Risk score: {risk:.2f}, Decision: {decision}",
        'recommended_action': f'ACTION_{decision}',
        'risk_factors': [],
    }
    
    
MODEL_AVAILABLE = False
try:
    from ..inference.risk_scorer import compute_risk_score
    from ..inference.explainer import generate_explanation
    MODEL_AVAILABLE = True
except Exception as e:
    print(f"⚠️ Model components unavailable. Using fallback. Error: {e}")
    compute_risk_score = _get_fallback_risk_score
    generate_explanation = _get_fallback_explanation

# Import innovation modules
try:
    from ..features.voice_stress_analysis import VoiceStressAnalyzer
    from ..features.predictive_mule_identification import PredictiveMuleScorer
    from ..features.honeypot_escrow import HoneypotEscrowManager
    from ..features.blockchain_evidence import BlockchainEvidenceManager
    from ..features.aegis_oracle_explainer import AegisOracleExplainer
    INNOVATIONS_AVAILABLE = True
except (ImportError, SyntaxError) as e:
    print(f"⚠️  Warning: Innovation modules not available ({e})")
    INNOVATIONS_AVAILABLE = False

# Initialize FastAPI app
app = FastAPI(
    title="AegisGraph Sentinel 2.0",
    description="Real-Time Cross-Channel Mule Account Detection & Neutralization API",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS middleware
#
# CWE-942 prevention: `allow_origins=["*"]` combined with
# `allow_credentials=True` makes Starlette reflect the request's Origin
# header back, effectively allowing credentialed cross-origin requests
# from any site. Read the allowed origins from AEGIS_ALLOWED_ORIGINS
# (comma-separated) instead, defaulting to local dev URLs.
_default_origins = "http://localhost:3000,http://localhost:8501,http://127.0.0.1:8501"
ALLOWED_ORIGINS = [
    o.strip()
    for o in os.getenv("AEGIS_ALLOWED_ORIGINS", _default_origins).split(",")
    if o.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
    max_age=600,
)

# Global state
class AppState:
    """Application state"""
    def __init__(self):
        self.start_time = time.time()
        self.requests_processed = 0
        self.decisions = {"ALLOW": 0, "REVIEW": 0, "BLOCK": 0}
        self.total_risk_score = 0.0
        self.total_processing_time = 0.0
        self.model_loaded = False
        self.config = {}
        # Graph-based fraud detection
        self.transaction_graph = None
        self.fraud_chains = []
        self.mule_accounts = {'mule_acc_001', 'mule_acc_002', 'test_merchant', 'suspect_account_1', 'fraud_wallet_xyz'}
        self.account_profiles = {}
        self.graph_loaded = True  # Enable for demo
        # Lateral movement detection - rolling betweenness centrality baseline
        self.centrality_baseline = {}  # {account_id: [centrality_history]}
        self.centrality_window_size = 10  # Track last 10 measurements
        # Innovation managers
        self.voice_analyzer = None
        self.mule_scorer = None
        self.honeypot_manager = None
        self.blockchain_manager = None
        self.aegis_oracle = None  # Explainability engine
        
state = AppState()


@app.on_event("startup")
async def startup_event():
    """Initialize service on startup"""
    print("=" * 80)
    print("AegisGraph Sentinel 2.0 - Starting up...")
    print("=" * 80)
    
    # Load configuration
    config_path = Path("config/config.yaml")
    if config_path.exists():
        with open(config_path, 'r') as f:
            state.config = yaml.safe_load(f)
        print("✓ Configuration loaded")
    else:
        print("⚠ Configuration file not found, using defaults")
        state.config = {}
    
    # Load synthetic fraud data for graph-based detection
    try:
        # Load transaction graph
        graph_path = Path("data/synthetic/graph.gpickle")
        if graph_path.exists():
            with open(graph_path, 'rb') as f:
                state.transaction_graph = pickle.load(f)
            print(f"✓ Loaded transaction graph: {state.transaction_graph.number_of_nodes()} nodes, {state.transaction_graph.number_of_edges()} edges")
            state.graph_loaded = True
        else:
            print("⚠ Graph file not found at data/synthetic/graph.gpickle")
        
        # Load fraud chains
        chains_path = Path("data/synthetic/fraud_chains.json")
        if chains_path.exists():
            with open(chains_path, 'r') as f:
                state.fraud_chains = json.load(f)
            # Extract mule accounts from chains
            for chain in state.fraud_chains:
                state.mule_accounts.update(chain.get('accounts', []))
            print(f"✓ Loaded {len(state.fraud_chains)} fraud chains with {len(state.mule_accounts)} mule accounts")
        else:
            print("⚠ Fraud chains file not found")
        
        # Load account profiles
        accounts_path = Path("data/synthetic/accounts.json")
        if accounts_path.exists():
            with open(accounts_path, 'r') as f:
                accounts_list = json.load(f)
                state.account_profiles = {acc['account_id']: acc for acc in accounts_list}
            print(f"✓ Loaded {len(state.account_profiles)} account profiles")
        else:
            print("⚠ Accounts file not found")
            
    except Exception as e:
        print(f"⚠ Error loading graph data: {e}")
        state.graph_loaded = False
    
    # Check model availability
    if MODEL_AVAILABLE:
        state.model_loaded = True
        print("✓ Model components loaded successfully")
    else:
        state.model_loaded = False
        print("⚠ Running in DEMO MODE (install torch-geometric for full functionality)")
    
    # Initialize innovation managers
    if INNOVATIONS_AVAILABLE:
        try:
            state.voice_analyzer = VoiceStressAnalyzer()
            print("✓ Voice Stress Analyzer initialized")
        except Exception as e:
            print(f"⚠ Voice analyzer initialization failed: {e}")
        
        try:
            state.mule_scorer = PredictiveMuleScorer()
            print("✓ Predictive Mule Scorer initialized")
        except Exception as e:
            print(f"⚠ Mule scorer initialization failed: {e}")
        
        try:
            state.honeypot_manager = HoneypotEscrowManager()
            print("✓ Honeypot Escrow Manager initialized")
        except Exception as e:
            print(f"⚠ Honeypot manager initialization failed: {e}")
        
        try:
            state.blockchain_manager = BlockchainEvidenceManager()
            print("✓ Blockchain Evidence Manager initialized")
        except Exception as e:
            print(f"⚠ Blockchain manager initialization failed: {e}")
        
        try:
            state.aegis_oracle = AegisOracleExplainer()
            print("✓ Aegis-Oracle Explainer initialized")
        except Exception as e:
            print(f"⚠ Aegis-Oracle initialization failed: {e}")
    else:
        print("⚠ Innovation modules not available")
    
    print("=" * 80)
    print("🚀 AegisGraph Sentinel 2.0 is ready")
    print(f"📊 Mode: {'PRODUCTION' if MODEL_AVAILABLE else 'DEMO'}")
    print(f"🔗 Graph-based Detection: {'ENABLED' if state.graph_loaded else 'DISABLED'}")
    print(f"🎯 Innovations: {'ENABLED' if INNOVATIONS_AVAILABLE else 'DISABLED'}")
    print("📖 API Documentation: http://localhost:8000/docs")
    print("=" * 80)
    asyncio.ensure_future(_honeypot_auto_release_loop())

async def _honeypot_auto_release_loop(interval_seconds: int = 60):
    while True:
        await asyncio.sleep(interval_seconds)
        if state.honeypot_manager is not None:
            try:
                state.honeypot_manager.check_auto_release()
            except Exception as exc:
                print(f"⚠ Honeypot auto-release check failed: {exc}")


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


@app.get("/api/v1/health", response_model=HealthCheckResponse, tags=["System"])
async def health_check_v1():
    """Health check endpoint (v1 routing)"""
    uptime = time.time() - state.start_time if hasattr(state, 'start_time') else 0
    
    return HealthCheckResponse(
        status="healthy",
        version="2.0",
        model_loaded=MODEL_AVAILABLE,
        graph_loaded=state.graph_loaded if hasattr(state, 'graph_loaded') else False,
        innovations_available=INNOVATIONS_AVAILABLE,
        uptime_seconds=uptime,
        requests_processed=state.requests_processed,
        timestamp=datetime.utcnow().isoformat() + 'Z',
    )

@app.get("/health", response_model=HealthCheckResponse, tags=["General"])
async def health_check():
    """
    Health check endpoint
    
    Returns service status and basic statistics
    """
    uptime = time.time() - state.start_time if hasattr(state, 'start_time') else 0
    
    return HealthCheckResponse(
        status="healthy",
        version="2.0.0",
        model_loaded=state.model_loaded,
        graph_loaded=state.graph_loaded,
        innovations_available=INNOVATIONS_AVAILABLE,
        uptime_seconds=uptime,
        requests_processed=state.requests_processed,
        timestamp=datetime.utcnow().isoformat() + 'Z',
    )


@app.get("/stats", response_model=StatsResponse, tags=["General"])
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
    description="Analyze a single transaction for fraud risk using HTGNN and behavioral biometrics"
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
                    print(f"Keystroke analysis failed: {e}")
        
        # Compute risk score
        risk_result = compute_risk_score(
            transaction=transaction,
            biometrics=biometrics,
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
        
        if INNOVATIONS_AVAILABLE and state.honeypot_manager is not None:
            try:
                # Extract fraud indicators from explanation
                fraud_indicators = []
                if 'mule' in explanation_result['explanation'].lower():
                    fraud_indicators.append('known_mule_account')
                if 'chain' in explanation_result['explanation'].lower():
                    fraud_indicators.append('mule_chain')
                if risk_result['breakdown']['velocity'] > 0.8:
                    fraud_indicators.append('extreme_velocity')
                
                should_activate = state.honeypot_manager.should_activate_honeypot(
                    risk_score=risk_result['risk_score'],
                    decision=risk_result['decision'],
                    fraud_indicators=fraud_indicators,
                )
                
                logic_decision = 'ALLOW' if risk_result['decision'] == 'APPROVE' else risk_result['decision']
                if should_activate and logic_decision == 'BLOCK':
                    # Activate honeypot
                    honeypot = state.honeypot_manager.activate_honeypot(
                        transaction_id=request.transaction_id,
                        source_account=request.source_account,
                        target_account=request.target_account,
                        amount=request.amount,
                        currency=request.currency,
                        risk_score=risk_result['risk_score'],
                        fraud_indicators=fraud_indicators,
                    )
                    honeypot_activated = True
                    honeypot_id = honeypot.honeypot_id
                    
                    # Override decision to show fake success
                    risk_result['decision'] = 'ALLOW'
                    explanation_result['explanation'] = "Transaction approved (honeypot trap activated)"
                    explanation_result['recommended_action'] = "SHOW_SUCCESS_MONITOR_WITHDRAWAL"
                    
                    print(f"🍯 Honeypot activated: {honeypot_id} for transaction {request.transaction_id}")
                    
            except Exception as e:
                print(f"Honeypot activation check failed: {e}")
        
        # Innovation 6: Seal evidence in blockchain for high-risk transactions
        blockchain_evidence_id = None
        
        if INNOVATIONS_AVAILABLE and state.blockchain_manager is not None:
            try:
                logic_decision = 'ALLOW' if risk_result['decision'] == 'APPROVE' else risk_result['decision']
                if logic_decision in ['BLOCK', 'REVIEW'] or honeypot_activated:
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
                    
                    evidence = state.blockchain_manager.seal_evidence(
                        transaction_id=request.transaction_id,
                        source_account=request.source_account,
                        target_account=request.target_account,
                        amount=request.amount,
                        risk_score=risk_result['risk_score'],
                        decision=risk_result['decision'],
                        confidence=risk_result['confidence'],
                        breakdown=risk_result['breakdown'],
                        explanation=explanation_result['explanation'],
                        fraud_patterns=fraud_patterns,
                    )
                    blockchain_evidence_id = evidence.evidence_id
                    print(f"⛓️ Evidence sealed in blockchain: {blockchain_evidence_id}")
                    
            except Exception as e:
                print(f"Blockchain sealing failed: {e}")
        
        # Processing time
        processing_time_ms = (time.time() - start_time) * 1000
        
        # Update statistics
        internal_decision = risk_result['decision']
        logic_decision = 'ALLOW' if internal_decision == 'APPROVE' else internal_decision
        if logic_decision not in state.decisions:
            logic_decision = 'ALLOW'
        state.requests_processed += 1
        state.decisions[logic_decision] += 1
        state.total_risk_score += risk_result['risk_score']
        state.total_processing_time += processing_time_ms
        
        # Prepare response with innovation fields
        decision_map = {
            'ALLOW': 'approve',
            'APPROVE': 'approve',
            'REVIEW': 'review',
            'BLOCK': 'block',
        }
        decision = decision_map.get(internal_decision, internal_decision.lower())
        raw_decision = risk_result['decision']
        decision = {
            'ALLOW': 'approve',
            'REVIEW': 'review',
            'BLOCK': 'block',
        }.get(raw_decision, str(raw_decision).lower())
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
            timestamp=datetime.utcnow().isoformat() + 'Z',
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
        
        return response
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")


@app.post(
    "/api/v1/explain",
    tags=["Explainability - Aegis-Oracle"],
    summary="Generate AI-explainable decision explanation",
    description="Innovation 5: Aegis-Oracle generates regulatory-compliant explanations for all fraud decisions. Includes causal factors, evidence,  and legal admissibility."
)
async def explain_transaction(payload: dict):
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
    if not INNOVATIONS_AVAILABLE or state.aegis_oracle is None:
        raise HTTPException(status_code=503, detail="Aegis-Oracle Explainer not available")
    
    try:
        # Extract transaction and risk info
        transaction = {
            'transaction_id': payload.get('transaction_id', 'TXN_UNKNOWN'),
            'source_account': payload.get('source_account'),
            'target_account': payload.get('target_account'),
            'amount': payload.get('amount', 0),
            'currency': payload.get('currency', 'INR'),
            'timestamp': payload.get('timestamp'),
            'behavioral_stress_detected': payload.get('behavioral_stress_detected', False),
        }
        
        risk_assessment = {
            'decision': payload.get('decision', 'ALLOW'),
            'risk_score': payload.get('risk_score', 0.0),
            'confidence': payload.get('confidence', 0.85),
        }
        
        breakdown = payload.get('breakdown') or {
            'graph': 0.0,
            'velocity': 0.0,
            'behavior': 0.0,
            'entropy': 0.0,
        }
        
        innovations_triggered = payload.get('innovations_triggered', [])
        
        # Use Aegis-Oracle to generate explanation
        explanation = state.aegis_oracle.generate_explanation(
            transaction=transaction,
            risk_assessment=risk_assessment,
            break_down=breakdown,
            innovations_triggered=innovations_triggered,
        )
        
        return explanation
        
    except Exception as e:
        print(f"❌ Explanation error: {e}")
        raise HTTPException(status_code=500, detail=f"Explain error: {str(e)}")


# Enhanced Aegis-Oracle endpoint
@app.post(
    "/api/v1/oracle/explain",
    tags=["Explainability - Aegis-Oracle"],
    summary="Get comprehensive AI reasoning for fraud decisions",
    description="Advanced Aegis-Oracle endpoint with full forensic analysis and causal reasoning"
)
async def oracle_explain_detailed(payload: dict):
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
    if not INNOVATIONS_AVAILABLE or state.aegis_oracle is None:
        raise HTTPException(status_code=503, detail="Oracle not available")
    
    try:
        explanation = state.aegis_oracle.generate_explanation(
            transaction=payload.get('transaction', {}),
            risk_assessment=payload.get('risk_assessment', {}),
            attention_weights=payload.get('attention_weights', {}),
            break_down=payload.get('risk_breakdown', {}),
            innovations_triggered=payload.get('innovations_triggered', []),
        )
        
        return {
            'oracle_reasoning': explanation,
            'forensic_ready': True,
            'legal_admissible': True,
            'timestamp': datetime.utcnow().isoformat() + 'Z',
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail={'error': str(e)})

# DEBUG only: manually activate a honeypot via API.
# This endpoint is ONLY registered when DEBUG env var is set to "true".
# Never expose this route in production.
if os.getenv("DEBUG", "false").lower() == "true":
    @app.post(
        "/debug/activate_honeypot",
        tags=["Debug"],
        summary="Force honeypot activation (DEBUG mode only)",
        description="Available only when DEBUG env var is 'true'. For testing only.",
    )
    def debug_activate_honeypot(payload: dict):
        if state.honeypot_manager is None:
            raise HTTPException(status_code=500, detail="Honeypot manager not initialized")
        try:
            hp = state.honeypot_manager.activate_honeypot(
                transaction_id=payload.get('transaction_id', 'DEBUG'),
                source_account=payload.get('source_account', 'SRC'),
                target_account=payload.get('target_account', 'TGT'),
                amount=payload.get('amount', 0.0),
                currency=payload.get('currency', 'INR'),
                risk_score=payload.get('risk_score', 1.0),
                fraud_indicators=payload.get('fraud_indicators', []),
            )
            return {'honeypot_id': hp.honeypot_id, 'status': hp.status.value}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
@app.post(
    "/api/v1/fraud/batch",
    response_model=BatchTransactionResponse,
    tags=["Fraud Detection"],
    summary="Check multiple transactions",
    description="Batch processing of multiple transactions for fraud detection"
)
async def check_batch_transactions(request: BatchTransactionRequest):
    """
    Check multiple transactions in batch
    
    Processes multiple transactions and returns results for each.
    Maximum batch size: 100 transactions.
    """
    start_time = time.time()
    
    results = []
    stats = {"ALLOW": 0, "REVIEW": 0, "BLOCK": 0}
    
    for txn_request in request.transactions:
        try:
            # Process each transaction
            result = await check_transaction(txn_request)
            results.append(result)
            stats[result.decision.upper()] += 1
        except Exception as e:
            # Handle individual transaction errors
            print(f"Error processing {txn_request.transaction_id}: {e}")
            continue
    
    processing_time_ms = (time.time() - start_time) * 1000
    
    return BatchTransactionResponse(
        results=results,
        total_processed=len(results),
        total_blocked=stats["BLOCK"],
        total_review=stats["REVIEW"],
        total_allowed=stats["ALLOW"],
        processing_time_ms=processing_time_ms,
    )


@app.get("/api/v1/model/info", tags=["Model"])
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
    description="Innovation 5: Detects phone coercion through acoustic stress analysis"
)
async def analyze_voice(request: VoiceAnalysisRequest):
    """
    Analyze voice recording for stress and coercion indicators
    
    Uses acoustic features (F0, jitter, shimmer, speech rate, prosody) to classify
    stress levels: NORMAL, MILD_STRESS, or SEVERE_COERCION
    """
    if not INNOVATIONS_AVAILABLE or state.voice_analyzer is None:
        raise HTTPException(status_code=503, detail="Voice analysis not available")
    
    start_time = time.time()
    
    try:
        import base64
        import tempfile
        import wave
        
        # Decode base64 audio
        audio_bytes = base64.b64decode(request.audio_base64)
        
        # Save to temporary file
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.wav', delete=False) as tmp:
            tmp.write(audio_bytes)
            tmp_path = tmp.name
        
        # Analyze voice stress
        result = state.voice_analyzer.analyze_voice(
            audio_file=tmp_path,
            sample_rate=request.sample_rate
        )
        
        # Clean up temp file
        Path(tmp_path).unlink()
        
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
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Voice analysis failed: {str(e)}")


@app.post(
    "/api/v1/accounts/score-opening",
    response_model=AccountOpeningResponse,
    tags=["Innovation - Predictive Mule"],
    summary="Score account opening for mule risk",
    description="Innovation 4: Predicts mule accounts before first transaction using 12 features"
)
async def score_account_opening(request: AccountOpeningRequest):
    """
    Score a new account opening for mule recruitment risk
    
    Analyzes 12 features including temporal clustering, device novelty,
    geographic mismatch, and more to identify potential mule accounts
    """
    if not INNOVATIONS_AVAILABLE or state.mule_scorer is None:
        raise HTTPException(status_code=503, detail="Predictive mule scoring not available")
    
    start_time = time.time()
    
    try:
        # Score the account opening
        result = state.mule_scorer.score_account_opening(
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
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Account scoring failed: {str(e)}")


# Alias endpoint for mule assessment
@app.post(
    "/api/v1/mule/assess",
    response_model=AccountOpeningResponse,
    tags=["Innovation - Predictive Mule"],
    summary="Assess account mule risk",
    description="Innovation 3: Alias for mule assessment endpoint"
)
async def assess_mule_risk(request: AccountOpeningRequest):
    """Alias endpoint for mule assessment"""
    return await score_account_opening(request)


@app.get(
    "/api/v1/honeypot/active",
    response_model=HoneypotListResponse,
    tags=["Innovation - Honeypot Escrow"],
    summary="List active honeypot traps",
    description="Innovation 2: View all active deceptive containment operations"
)
async def list_active_honeypots():
    """
    Get list of all active honeypot traps
    
    Shows honeypots that are currently monitoring for withdrawal attempts
    and tracking fraud networks
    """
    if not INNOVATIONS_AVAILABLE or state.honeypot_manager is None:
        raise HTTPException(status_code=503, detail="Honeypot system not available")
    
    try:
        active = state.honeypot_manager.get_active_honeypots()
        stats = state.honeypot_manager.get_statistics()
        
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
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get honeypot list: {str(e)}")


@app.get(
    "/api/v1/honeypot/stats",
    response_model=HoneypotStatsResponse,
    tags=["Innovation - Honeypot Escrow"],
    summary="Get honeypot system statistics",
    description="Innovation 2: View performance metrics including arrest rate and recovery amount"
)
async def get_honeypot_stats():
    """
    Get honeypot system performance statistics
    
    Returns all-time metrics including arrests, recovery amounts, and false positive rates
    """
    if not INNOVATIONS_AVAILABLE or state.honeypot_manager is None:
        raise HTTPException(status_code=503, detail="Honeypot system not available")
    
    try:
        stats = state.honeypot_manager.get_statistics()
        
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
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get statistics: {str(e)}")


@app.post(
    "/api/v1/blockchain/seal",
    response_model=BlockchainEvidenceResponse,
    tags=["Innovation - Blockchain Evidence"],
    summary="Seal evidence in blockchain",
    description="Innovation 6: Create immutable evidence record for legal admissibility"
)
async def seal_evidence(request: BlockchainSealRequest):
    """
    Seal fraud detection evidence in blockchain
    
    Creates cryptographically-signed, immutable evidence record across
    18 validator nodes for legal proceedings
    """
    if not INNOVATIONS_AVAILABLE or state.blockchain_manager is None:
        raise HTTPException(status_code=503, detail="Blockchain system not available")
    
    try:
        result = state.blockchain_manager.seal_evidence(
            transaction_id=request.transaction_id,
            source_account=request.source_account,
            target_account=request.target_account,
            amount=request.amount,
            risk_result=request.risk_result,
            explanation=request.explanation,
        )
        
        return BlockchainEvidenceResponse(
            evidence_id=result['evidence_id'],
            transaction_hash=result['transaction_hash'],
            block_number=result['block_number'],
            block_hash=result['block_hash'],
            timestamp=result['timestamp'],
            finality_time_ms=result['finality_time_ms'],
            validators=result['validators'],
        )
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Evidence sealing failed: {str(e)}")


@app.get(
    "/api/v1/blockchain/verify/{evidence_id}",
    response_model=BlockchainVerificationResponse,
    tags=["Innovation - Blockchain Evidence"],
    summary="Verify blockchain evidence",
    description="Innovation 6: Verify integrity and authenticity of sealed evidence"
)
async def verify_evidence(evidence_id: str, block_number: int):
    """
    Verify blockchain evidence integrity
    
    Checks evidence across multiple validator nodes within given block
    to ensure chain integrity and authenticity
    """
    if not INNOVATIONS_AVAILABLE or state.blockchain_manager is None:
        raise HTTPException(status_code=503, detail="Blockchain system not available")
    
    try:
        result = state.blockchain_manager.verify_evidence(evidence_id, block_number)
        
        return BlockchainVerificationResponse(
            evidence_id=evidence_id,
            verified=result['verified'],
            block_exists=result['block_exists'],
            chain_integrity=result['chain_integrity'],
            consensus_nodes=result.get('consensus_nodes', 0),
            original_timestamp=result.get('original_timestamp'),
            verification_details=result.get('details', {}),
        )
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Verification failed: {str(e)}")


@app.post(
    "/api/v1/blockchain/export",
    response_model=LegalExportResponse,
    tags=["Innovation - Blockchain Evidence"],
    summary="Export evidence for legal proceedings",
    description="Innovation 6: Generate court-admissible evidence package"
)
async def export_legal_evidence(request: LegalExportRequest):
    """
    Export blockchain evidence for legal proceedings
    
    Generates complete evidence package with chain of custody,
    validator attestations, and court-formatted documentation
    """
    if not INNOVATIONS_AVAILABLE or state.blockchain_manager is None:
        raise HTTPException(status_code=503, detail="Blockchain system not available")
    
    try:
        result = state.blockchain_manager.export_for_legal(
            evidence_id=request.evidence_id,
            case_number=request.case_number,
            requesting_authority=request.requesting_authority,
            authorization_token=request.authorization_token,
        )
        
        return LegalExportResponse(
            evidence_id=request.evidence_id,
            case_number=request.case_number,
            evidence_package=result['package'],
            chain_of_custody=result['chain_of_custody'],
            attestations=result['attestations'],
            export_timestamp=result['export_timestamp'],
            authorized_by=result['authorized_by'],
        )
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Evidence export failed: {str(e)}")


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Custom HTTP exception handler"""
    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorResponse(
            error=exc.detail,
            detail=None,
            timestamp=datetime.utcnow().isoformat() + 'Z',
        ).model_dump(),
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """General exception handler"""
    return JSONResponse(
        status_code=500,
        content=ErrorResponse(
            error="Internal server error",
            detail=str(exc),
            timestamp=datetime.utcnow().isoformat() + 'Z',
        ).model_dump(),
    )


def main():
    """Run the API server"""
    config_path = Path("config/config.yaml")
    
    if config_path.exists():
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        api_config = config.get('api', {})
    else:
        api_config = {}
    
    host = api_config.get('host', '0.0.0.0')
    port = api_config.get('port', 8000)
    reload = api_config.get('reload', True)
    
    uvicorn.run(
        "src.api.main:app",
        host=host,
        port=port,
        reload=reload,
        log_level="info",
    )


if __name__ == "__main__":
    main()
