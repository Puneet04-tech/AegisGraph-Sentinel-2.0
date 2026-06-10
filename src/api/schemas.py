"""
Pydantic schemas for API request/response validation
"""
# Schema validation for all fraud detection endpoints

from pydantic import BaseModel, Field, field_validator, model_validator, AliasChoices, ConfigDict
from typing import Optional, List, Dict, Union, Any, Literal
from src.api.validators import (
    TransactionValidator,
    ValidationError,
    VALID_CURRENCY_CODES,
    VALID_MODES,
)


class BiometricsData(BaseModel):
    """Keystroke biometrics data"""
    hold_times: List[float] = Field(default_factory=list, description="Key hold times in milliseconds")
    flight_times: List[float] = Field(default_factory=list, description="Key flight times in milliseconds")
    keystroke_events: Optional[List[Dict]] = Field(default=None, description="Raw keystroke events")
    mouse_movements: Optional[List[Dict]] = Field(default=None, description="Raw mouse movement events")
    
    @field_validator('hold_times', 'flight_times')
    @classmethod
    def validate_biometric_values(cls, v):
        """Validate biometric array constraints."""
        if len(v) > 1000:
            raise ValueError("Biometric arrays cannot exceed 1000 elements")
        if any(x < 0 or x > 10000 for x in v):
            raise ValueError("Biometric values must be between 0 and 10000 milliseconds")
        return v


class TransactionCheckRequest(BaseModel):
    """Request schema for transaction fraud check"""
    model_config = ConfigDict(
        json_schema_extra = {
            "example": {
                "transaction_id": "TXN123456789",
                "source_account": "ACC987654321",
                "target_account": "ACC123456789",
                "amount": 50000.00,
                "currency": "INR",
                "mode": "UPI",
                "timestamp": "2026-02-26T14:30:00Z",
                "device_id": "DEV123",
                "biometrics": {
                    "hold_times": [120, 135, 128, 142, 118],
                    "flight_times": [200, 185, 210, 195]
                },
                "ip_address": "103.x.x.x",
                "location": "Mumbai, India"
            }
        }
    )
    
    transaction_id: str = Field(description="Unique transaction identifier")
    source_account: str = Field(
        validation_alias=AliasChoices('source_account', 'from_account'),
        description="Source account ID",
    )
    target_account: str = Field(
        validation_alias=AliasChoices('target_account', 'to_account'),
        description="Target account ID",
    )
    amount: float = Field(gt=0, description="Transaction amount")
    currency: str = Field(default="INR", description="Currency code")
    mode: str = Field(default="UPI", description="Transaction mode (UPI, IMPS, NEFT, etc.)")
    timestamp: Union[str, float] = Field(description="Transaction timestamp (ISO 8601 UTC format or epoch seconds)")
    device_id: Optional[str] = Field(default=None, description="Device identifier")
    biometrics: Optional[BiometricsData] = Field(default=None, description="Behavioral biometrics")
    ip_address: Optional[str] = Field(default=None, description="IP address")
    location: Optional[str] = Field(default=None, description="Transaction location")
    @field_validator('timestamp')
    @classmethod
    def validate_timestamp(cls, v):
        """Validate and normalize timestamp to ISO 8601 UTC format.

        Accepted inputs include Unix epoch seconds and timezone-aware ISO 8601
        strings (Z or explicit UTC offsets).
        """
        try:
            v = TransactionValidator.normalize_timestamp(v)
            TransactionValidator.validate_timestamp(v)
        except ValidationError as e:
            raise ValueError(e.suggestion) from e
        return v
    
    @field_validator('source_account')
    @classmethod
    def validate_source_account(cls, v):
        """Validate source account format."""
        try:
            TransactionValidator.validate_account_id(v, "source_account")
        except ValidationError as e:
            raise ValueError(e.suggestion) from e
        return v
    
    @field_validator('target_account')
    @classmethod
    def validate_target_account(cls, v):
        """Validate target account format."""
        try:
            TransactionValidator.validate_account_id(v, "target_account")
        except ValidationError as e:
            raise ValueError(e.suggestion) from e
        return v
    
    @field_validator('currency')
    @classmethod
    def validate_currency(cls, v):
        """Validate currency code."""
        try:
            TransactionValidator.validate_currency_code(v)
        except ValidationError as e:
            raise ValueError(e.suggestion) from e
        return v
    
    @field_validator('mode')
    @classmethod
    def validate_mode(cls, v):
        """Validate transaction mode."""
        try:
            TransactionValidator.validate_mode(v)
        except ValidationError as e:
            raise ValueError(e.suggestion) from e
        return v
    
    @model_validator(mode='after')
    def validate_cross_fields(self):
        """Validate cross-field constraints."""
        try:
            TransactionValidator.validate_cross_fields(
                self.source_account, self.target_account
            )
        except ValidationError as e:
            raise ValueError(e.suggestion) from e
        return self
    


class RiskBreakdown(BaseModel):
    """Risk score breakdown by component"""
    graph: float = Field(ge=0, le=1, description="Graph-based risk")
    velocity: float = Field(ge=0, le=1, description="Velocity-based risk")
    behavior: float = Field(ge=0, le=1, description="Behavioral risk")
    entropy: float = Field(ge=0, le=1, description="Entropy-based risk")


class TransactionCheckResponse(BaseModel):
    """Response schema for transaction fraud check"""
    model_config = ConfigDict(
        json_schema_extra = {
                "example": {
                    "transaction_id": "TXN123456789",
                    "risk_score": 0.92,
                    "decision": "BLOCK",
                    "confidence": 0.97,
                    "breakdown": {
                        "graph": 0.89,
                        "velocity": 0.95,
                        "behavior": 0.88,
                        "entropy": 0.93
                    },
                    "explanation": "High-risk mule chain pattern detected...",
                    "recommended_action": "BLOCK_AND_ALERT_LAW_ENFORCEMENT",
                    "processing_time_ms": 142.5,
                    "timestamp": "2026-02-26T14:30:00.142Z",
                    "blockchain_evidence_id": "EVID_XYZ789",
                    "behavioral_stress_detected": True,
                    "lateral_movement_detected": False
                }
            }
    )
    transaction_id: str
    risk_score: float = Field(ge=0, le=1, description="Overall risk score")
    decision: str = Field(description="Decision: ALLOW, REVIEW, or BLOCK")
    factors: Dict[str, float] = Field(default_factory=dict, description="Legacy factor map")
    confidence: float = Field(ge=0, le=1, description="Confidence in decision")
    breakdown: RiskBreakdown = Field(description="Risk score breakdown")
    explanation: str = Field(description="Human-readable explanation")
    recommended_action: str = Field(description="Recommended action")
    processing_time_ms: float = Field(description="Processing time in milliseconds")
    timestamp: str = Field(description="Response timestamp")
    
    # Innovation fields (real-time integration)
    # Note: Honeypot activation state is intentionally excluded from client responses
    # to prevent information disclosure about defensive mechanisms.
    # Internal logging captures honeypot activity for monitoring/audit.
    blockchain_evidence_id: Optional[str] = Field(default=None, description="Blockchain evidence ID (Innovation 6)")
    behavioral_stress_detected: bool = Field(default=False, description="Keystroke stress detected (Innovation 1)")
    lateral_movement_detected: bool = Field(default=False, description="Lateral movement pattern detected (MITRE ATT&CK TA0008)")
    model_degraded: bool = Field(
        default=False,
        description=(
            "True when the ML model was unavailable and the response was produced "
            "by the amount-based fallback heuristic instead of the GNN pipeline. "
            "Downstream consumers should treat degraded-mode decisions with lower "
            "confidence and flag them in audit trails accordingly."
        ),
    )
    


class BatchTransactionRequest(BaseModel):
    """Request schema for batch transaction checking"""
    model_config = ConfigDict(
        json_schema_extra = {
            "example": {
                "transactions": [
                    {
                        "transaction_id": "TXN123456789",
                        "source_account": "ACC987654321",
                        "target_account": "ACC123456789",
                        "amount": 50000.00,
                        "currency": "INR",
                        "mode": "UPI",
                        "timestamp": "2026-02-26T14:30:00Z"
                    }
                ]
            }
        }
    )
    transactions: List[TransactionCheckRequest] = Field(description="List of transactions to check")
    
    @field_validator('transactions')
    @classmethod
    def validate_batch_size(cls, v):
        if len(v) > 100:
            raise ValueError("Batch size cannot exceed 100 transactions")
        return v


class BatchTransactionResponse(BaseModel):
    """Response schema for batch transaction checking"""
    model_config = ConfigDict(
        json_schema_extra = {
            "example": {
                "results": [],
                "total_processed": 1,
                "total_blocked": 0,
                "total_review": 0,
                "total_allowed": 1,
                "processing_time_ms": 45.2
            }
        }
    )
    results: List[TransactionCheckResponse]
    total_processed: int
    total_blocked: int
    total_review: int
    total_allowed: int
    processing_time_ms: float


class HealthCheckResponse(BaseModel):
    """Health check response"""
    model_config = ConfigDict(
        json_schema_extra = {
            "example": {
                "status": "operational",
                "service": "AegisGraph Sentinel 2.0",
                "version": "2.0.0",
                "model_loaded": True,
                "graph_loaded": True,
                "innovations_available": True,
                "uptime_seconds": 3600.5,
                "requests_processed": 1500,
                "timestamp": "2026-06-06T12:00:00Z"
            }
        }
    )
    status: str = Field(description="Service status")
    service: str = Field(default="AegisGraph Sentinel", description="Service name")
    version: Optional[str] = Field(default=None, description="API version")
    model_loaded: Optional[bool] = Field(default=None, description="Whether model is loaded")
    graph_loaded: Optional[bool] = Field(default=None, description="Whether transaction graph is loaded")
    innovations_available: Optional[bool] = Field(default=None, description="Whether innovations are available")
    uptime_seconds: Optional[float] = Field(default=None, description="Service uptime in seconds")
    requests_processed: Optional[int] = Field(default=None, description="Total requests processed")
    timestamp: Optional[str] = Field(default=None, description="Response timestamp")
    services_health: Optional[Dict[str, Dict[str, Any]]] = Field(default=None, description="Detailed health stats for registered services")


class ModelInfo(BaseModel):
    """Model information"""
    model_config = ConfigDict(
        json_schema_extra = {
            "example": {
                "model_name": "HTGNN-Fraud-Detector",
                "version": "v1.2",
                "architecture": "Heterogeneous Temporal Graph Attention Network",
                "parameters": 5000000,
                "trained_on": "2026-01-15T00:00:00Z",
                "performance_metrics": {
                    "precision": 0.968,
                    "recall": 0.942,
                    "f1_score": 0.955
                }
            }
        }
    )
    model_name: str
    version: str
    architecture: str
    parameters: int
    trained_on: str
    performance_metrics: Dict[str, float]


class StatsResponse(BaseModel):
    """Statistics response"""
    model_config = ConfigDict(
        json_schema_extra = {
            "example": {
                "total_requests": 1500,
                "decisions": {
                    "ALLOW": 1400,
                    "REVIEW": 80,
                    "BLOCK": 20
                },
                "avg_risk_score": 0.15,
                "avg_processing_time_ms": 112.5,
                "uptime_seconds": 3600.5,
                "total_checks": 1500,
                "flagged_transactions": 100,
                "average_response_time": 112.5
            }
        }
    )
    total_requests: int
    decisions: Dict[str, int]
    avg_risk_score: float
    avg_processing_time_ms: float
    uptime_seconds: float
    total_checks: int = 0
    flagged_transactions: int = 0
    average_response_time: float = 0.0


class ErrorResponse(BaseModel):
    """Error response schema"""
    model_config = ConfigDict(
        json_schema_extra = {
            "example": {
                "error": "Authentication Failed",
                "detail": "Invalid API Key provided",
                "timestamp": "2026-06-06T12:00:00Z"
            }
        }
    )
    error: str = Field(description="Error message")
    detail: Optional[str] = Field(default=None, description="Detailed error information")
    timestamp: str = Field(description="Error timestamp")


# ============================================================================
# INNOVATION SCHEMAS
# ============================================================================

# Innovation 5: Voice Stress Analysis
class VoiceAnalysisRequest(BaseModel):
    """Request for voice stress analysis"""
    transaction_id: str = Field(description="Transaction ID for correlation")
    # Keep this small so the API accepts only short voice clips and rejects
    # large uploads before they can consume excessive memory or CPU.
    audio_base64: str = Field(max_length=500_000, description="Base64-encoded audio WAV file (max 30 seconds)")
    sample_rate: int = Field(default=16000, description="Audio sample rate in Hz")
    
    @field_validator('sample_rate')
    @classmethod
    def validate_sample_rate(cls, v):
        if v not in [8000, 16000, 44100, 48000]:
            raise ValueError("Sample rate must be 8000, 16000, 44100, or 48000 Hz")
        return v


class VoiceAnalysisResponse(BaseModel):
    """Response for voice stress analysis"""
    model_config = ConfigDict(
        json_schema_extra = {
            "example": {
                "transaction_id": "TXN123",
                "stress_score": 78.5,
                "classification": "SEVERE_COERCION",
                "confidence": 0.92,
                "features": {
                    "f0_mean": 235.4,
                    "jitter": 1.2,
                    "shimmer": 0.08,
                    "speech_rate": 3.8,
                    "prosody_entropy": 0.42
                },
                "recommended_action": "CALLBACK_REQUIRED",
                "processing_time_ms": 245.3
            }
        }
    )
    
    transaction_id: str
    stress_score: float = Field(ge=0, le=100, description="Voice stress score (0-100)")
    classification: str = Field(description="NORMAL, MILD_STRESS, or SEVERE_COERCION")
    confidence: float = Field(ge=0, le=1, description="Confidence in classification")
    features: Dict[str, float] = Field(description="Acoustic features extracted")
    recommended_action: str = Field(description="Recommended action based on stress level")
    processing_time_ms: float = Field(description="Processing time in milliseconds")
    


# Innovation 4: Predictive Mule Identification
class AccountOpeningRequest(BaseModel):
    """Request for account opening risk assessment"""
    account_id: str = Field(description="Account identifier")
    name: str = Field(description="Account holder name")
    age: int = Field(ge=18, le=100, description="Account holder age")
    profession: str = Field(description="Profession or occupation")
    email: str = Field(description="Email address")
    phone: str = Field(description="Phone number")
    device_id: str = Field(description="Device identifier")
    ip_address: str = Field(description="IP address during registration")
    stated_address: str = Field(description="Stated home address")
    facial_match: float = Field(ge=0, le=1, description="Facial recognition match score")
    document_type: str = Field(description="KYC document type (Aadhaar, PAN, etc.)")
    initial_deposit: float = Field(ge=0, description="Initial deposit amount")
    referrer: Optional[str] = Field(default=None, description="Referrer ID or source")
    form_completion_time_seconds: Optional[int] = Field(default=None, description="Time to complete form")


class AccountOpeningResponse(BaseModel):
    """Response for account opening risk assessment"""
    model_config = ConfigDict(
        json_schema_extra = {
            "example": {
                "account_id": "ACC_NEW_123",
                "risk_score": 87.3,
                "risk_level": "HIGH_MULE_RISK",
                "confidence": 0.86,
                "features": {
                    "temporal_clustering": 85.0,
                    "document_quality": 72.0,
                    "device_novelty": 90.0
                },
                "red_flags": [
                    "New device (<7 days)",
                    "Temporary email domain",
                    "Fast form completion (3 min)"
                ],
                "recommended_action": "ENHANCED_MONITORING",
                "processing_time_ms": 89.2
            }
        }
    ) 
    
    account_id: str
    risk_score: float = Field(ge=0, le=100, description="Mule risk score (0-100)")
    risk_level: str = Field(description="CRITICAL_MULE_RISK, HIGH_MULE_RISK, MODERATE, or LOW")
    confidence: float = Field(ge=0, le=1, description="Confidence in assessment")
    features: Dict[str, float] = Field(description="Feature scores breakdown")
    red_flags: List[str] = Field(description="List of identified red flags")
    recommended_action: str = Field(description="Recommended action")
    processing_time_ms: float = Field(description="Processing time in milliseconds")
    

# Innovation 2: Honeypot Escrow
class HoneypotStatus(BaseModel):
    """Status of a honeypot trap"""
    honeypot_id: str
    transaction_id: str
    source_account: str
    target_account: str
    amount: float
    currency: str
    activated_at: str
    time_remaining_seconds: int = Field(description="Time until auto-release")
    withdrawal_attempts: int = Field(description="Number of withdrawal attempts")
    last_attempt_location: Optional[str] = Field(default=None)
    police_alerted: bool = Field(description="Whether police have been alerted")
    status: str = Field(description="ACTIVE, ARRESTED, RELEASED, or ESCAPED")


class HoneypotListResponse(BaseModel):
    """Response listing active honeypots"""
    active_honeypots: List[HoneypotStatus]
    total_active: int
    total_arrests_today: int
    total_recovered_today: float


class HoneypotStatsResponse(BaseModel):
    """Statistics for honeypot system"""
    total_activated: int = Field(description="All-time honeypots activated")
    total_arrests: int = Field(description="All-time arrests")
    arrest_rate: float = Field(ge=0, le=1, description="Arrest success rate")
    networks_dismantled: int = Field(description="Fraud networks dismantled")
    total_recovered: float = Field(description="Total amount recovered")
    false_positives: int = Field(description="False positive activations")
    false_positive_rate: float = Field(ge=0, le=1, description="False positive rate")
    avg_time_to_arrest_minutes: float = Field(description="Average time from activation to arrest")


# Innovation 6: Blockchain Evidence Chain
class BlockchainRiskBreakdown(BaseModel):
    """Strict risk breakdown accepted for blockchain evidence sealing."""

    model_config = ConfigDict(extra="forbid")

    graph: float = Field(ge=0, le=1, description="Graph-based risk")
    velocity: float = Field(ge=0, le=1, description="Velocity-based risk")
    behavior: float = Field(ge=0, le=1, description="Behavioral risk")
    entropy: float = Field(ge=0, le=1, description="Entropy-based risk")


class BlockchainRiskResult(BaseModel):
    """Canonical risk result sealed onto the blockchain."""

    model_config = ConfigDict(extra="forbid")

    risk_score: float = Field(ge=0, le=1, description="Overall risk score")
    decision: Literal["ALLOW", "REVIEW", "BLOCK"] = Field(
        description="Decision: ALLOW, REVIEW, or BLOCK"
    )
    confidence: float = Field(ge=0, le=1, description="Confidence in the decision")
    breakdown: BlockchainRiskBreakdown = Field(description="Strict risk breakdown")


class BlockchainSealRequest(BaseModel):
    """Request to seal evidence in blockchain"""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "example": {
                "transaction_id": "TXN123456789",
                "source_account": "ACC987654321",
                "target_account": "ACC123456789",
                "amount": 50000.0,
                "risk_result": {
                    "risk_score": 0.92,
                    "decision": "BLOCK",
                    "confidence": 0.97,
                    "breakdown": {
                        "graph": 0.89,
                        "velocity": 0.95,
                        "behavior": 0.88,
                        "entropy": 0.93,
                    },
                },
                "explanation": "High-risk mule chain pattern detected...",
            }
        },
    )

    transaction_id: str
    source_account: str
    target_account: str
    amount: float = Field(gt=0, description="Transaction amount")
    risk_result: BlockchainRiskResult = Field(description="Complete risk assessment result")
    explanation: str = Field(max_length=5000, description="Decision explanation")


class BlockchainEvidenceResponse(BaseModel):
    """Response from blockchain evidence sealing"""
    model_config = ConfigDict(
        json_schema_extra = {
            "example": {
                "evidence_id": "EVID_001",
                "transaction_hash": "0x7a3f...",
                "block_number": 12487,
                "block_hash": "0x9b2c...",
                "timestamp": "2026-02-26T14:30:00.142Z",
                "finality_time_ms": 87.3,
                "validators": ["INDIAN_BANK_1", "VIT_CHENNAI_2", "RBI_1"]
            }
        }
    )
    
    evidence_id: str = Field(description="Unique evidence identifier")
    transaction_hash: str = Field(description="Transaction hash (no PII)")
    block_number: int = Field(description="Block number in chain")
    block_hash: str = Field(description="Block hash for integrity")
    timestamp: str = Field(description="Timestamp of sealing")
    finality_time_ms: float = Field(description="Time to achieve consensus")
    validators: List[str] = Field(description="Validator nodes that confirmed")



class BlockchainVerificationResponse(BaseModel):
    """Response from blockchain evidence verification"""
    evidence_id: str
    verified: bool = Field(description="Whether evidence is valid")
    block_exists: bool = Field(description="Block exists in chain")
    chain_integrity: bool = Field(description="Chain integrity intact")
    consensus_nodes: int = Field(description="Nodes that confirmed")
    original_timestamp: Optional[str] = Field(default=None, description="Original seal timestamp")
    verification_details: Dict = Field(description="Detailed verification info")


class LegalExportRequest(BaseModel):
    """Request for legal evidence export"""
    evidence_id: str
    case_number: str = Field(description="Legal case number")
    requesting_authority: str = Field(description="Law enforcement agency")


class LegalExportResponse(BaseModel):
    """Response with legal evidence package"""
    evidence_id: str
    case_number: str
    evidence_package: Dict = Field(description="Complete evidence package")
    chain_of_custody: List[Dict] = Field(description="Chain of custody records")
    attestations: List[Dict] = Field(description="Validator attestations")
    export_timestamp: str
    authorized_by: str


# ============================================================================
# EXPLAINABILITY SCHEMAS (Aegis-Oracle)
# ============================================================================

class ExplainRequest(BaseModel):
    """Request for AI-explainable decision explanation"""
    transaction_id: str = Field(default="TXN_UNKNOWN", description="Transaction identifier")
    source_account: Optional[str] = Field(default=None, description="Source account ID")
    target_account: Optional[str] = Field(default=None, description="Target account ID")
    amount: float = Field(default=0.0, description="Transaction amount")
    currency: str = Field(default="INR", description="Currency code")
    timestamp: Optional[str] = Field(default=None, description="Transaction timestamp")
    behavioral_stress_detected: bool = Field(default=False, description="Whether behavioral stress was detected")
    decision: str = Field(description="The decision made (ALLOW, REVIEW, BLOCK)")
    risk_score: float = Field(description="The calculated risk score")
    confidence: float = Field(default=0.85, description="Confidence in the decision")
    breakdown: Optional[RiskBreakdown] = Field(default=None, description="Risk component breakdown")
    innovations_triggered: List[str] = Field(default_factory=list, description="List of innovation modules triggered")


class OracleExplainRequest(BaseModel):
    """Detailed request for Aegis-Oracle forensic reasoning"""
    transaction: Dict = Field(description="Transaction details")
    risk_assessment: Dict = Field(description="Risk assessment results")
    attention_weights: Optional[Dict] = Field(default=None, description="Model attention weights")
    risk_breakdown: Optional[Dict] = Field(default=None, description="Detailed risk breakdown")
    innovations_triggered: List[str] = Field(default_factory=list, description="Innovation modules triggered")


class HoneypotDebugRequest(BaseModel):
    """Request to manually activate a honeypot (Debug only)"""
    transaction_id: str = Field(default="DEBUG", description="Transaction identifier")
    source_account: str = Field(default="SRC", description="Source account ID")
    target_account: str = Field(default="TGT", description="Target account ID")
    amount: float = Field(default=0.0, description="Transaction amount")
    currency: str = Field(default="INR", description="Currency code")
    risk_score: float = Field(default=1.0, description="Risk score for the transaction")
    fraud_indicators: List[str] = Field(default_factory=list, description="Identified fraud indicators")


# ============================================================================
# BLAST RADIUS ANALYTICS SCHEMAS
# ============================================================================


class BlastRadiusRequest(BaseModel):
    """
    Request for blast-radius contagion analysis.

    Given a verified-fraudulent or compromised node, the backend performs a
    bounded graph traversal and computes a Contagion Score for every reachable
    neighbor, returning results bucketed by risk tier.
    """

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "node_id": "ACC987654321",
                "max_depth": 3,
            }
        }
    )

    node_id: str = Field(
        description="ID of the flagged/compromised node to start from (e.g. account, device, IP)."
    )
    max_depth: int = Field(
        default=3,
        ge=1,
        le=5,
        description=(
            "Maximum hop count to traverse away from the source node. "
            "Accepted range: 1–5. Defaults to 3."
        ),
    )


class ContagionNode(BaseModel):
    """
    A single node reached during blast-radius traversal together with its
    computed Contagion Score and assigned risk tier.
    """

    node_id: str = Field(description="Unique identifier of the affected node.")
    contagion_score: float = Field(
        ge=0.0,
        description=(
            "Accumulated Contagion Score Sc = Σ weight_edge / depth². "
            "Higher values indicate stronger proximity to the fraud origin."
        ),
    )
    risk_tier: str = Field(
        description="Risk classification: CRITICAL (≥0.70), HIGH (≥0.35), or SUSPICIOUS (≥0.10)."
    )
    depth: int = Field(
        ge=1,
        description="Shortest-path hop distance from the source node.",
    )


class BlastRadiusResponse(BaseModel):
    """
    Structured blast-radius report categorising all reachable nodes by risk
    tier so that consuming microservices can lock or quarantine them
    automatically.
    """

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "source_node": "ACC987654321",
                "max_depth": 3,
                "total_nodes_evaluated": 12,
                "critical": [
                    {
                        "node_id": "ACC_RING_001",
                        "contagion_score": 0.85,
                        "risk_tier": "CRITICAL",
                        "depth": 1,
                    }
                ],
                "high": [
                    {
                        "node_id": "DEV_abc123",
                        "contagion_score": 0.50,
                        "risk_tier": "HIGH",
                        "depth": 2,
                    }
                ],
                "suspicious": [
                    {
                        "node_id": "IP_10_0_0_5",
                        "contagion_score": 0.18,
                        "risk_tier": "SUSPICIOUS",
                        "depth": 3,
                    }
                ],
                "processing_time_ms": 14.7,
                "timestamp": "2026-05-31T10:00:00.000Z",
            }
        }
    )

    source_node: str = Field(description="The origin node from which traversal started.")
    max_depth: int = Field(description="The max-depth limit used for this traversal.")
    total_nodes_evaluated: int = Field(
        ge=0,
        description="Total number of unique neighbor nodes scored (above 0.0).",
    )
    critical: List[ContagionNode] = Field(
        default_factory=list,
        description="Nodes with Contagion Score ≥ 0.70 — immediate lockdown recommended.",
    )
    high: List[ContagionNode] = Field(
        default_factory=list,
        description="Nodes with 0.35 ≤ Contagion Score < 0.70 — enhanced monitoring required.",
    )
    suspicious: List[ContagionNode] = Field(
        default_factory=list,
        description="Nodes with 0.10 ≤ Contagion Score < 0.35 — flag for investigation.",
    )
    processing_time_ms: float = Field(description="Wall-clock time taken to compute the blast radius.")
    timestamp: str = Field(description="ISO-8601 UTC timestamp of the response.")

# ============================================================================
# ALERT SUMMARIES (AI-Powered)
# ============================================================================

class AlertSummaryRequest(BaseModel):
    """Request schema for summarizing an anomaly alert"""
    alert_data: Dict[str, Any] = Field(description="The complex JSON data of the anomaly alert")


class AlertSummaryResponse(BaseModel):
    """Response schema for the AI-generated alert summary"""
    summary: str = Field(description="A plain English, 2-sentence explanation of the alert")
    processing_time_ms: float = Field(description="Time taken to generate the summary in ms")


# ============================================================================
# CASE MANAGEMENT SCHEMAS (Phase 4)
# ============================================================================

class CreateCaseRequest(BaseModel):
    """Request to open a new fraud investigation case."""
    transaction_id: str = Field(description="Transaction ID that triggered the alert")
    risk_score: float = Field(ge=0.0, le=1.0, description="Risk score from the fraud engine")
    decision: str = Field(description="Engine decision: ALLOW, REVIEW, or BLOCK")
    priority: Optional[str] = Field(default="MEDIUM", description="Case priority: LOW, MEDIUM, HIGH, CRITICAL")
    tags: Optional[List[str]] = Field(default_factory=list, description="Optional tags for categorisation")

    @field_validator("decision")
    @classmethod
    def validate_decision(cls, v: str) -> str:
        if v not in {"ALLOW", "REVIEW", "BLOCK"}:
            raise ValueError("decision must be ALLOW, REVIEW, or BLOCK")
        return v

    @field_validator("priority")
    @classmethod
    def validate_priority(cls, v: Optional[str]) -> Optional[str]:
        valid = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        if v and v.upper() not in valid:
            raise ValueError(f"priority must be one of: {valid}")
        return v.upper() if v else "MEDIUM"


class UpdateCaseRequest(BaseModel):
    """Partial update for an existing case (all fields optional)."""
    status: Optional[str] = Field(default=None, description="New status: OPEN, IN_PROGRESS, ESCALATED, RESOLVED, CLOSED")
    assigned_analyst: Optional[str] = Field(default=None, description="Analyst ID to assign the case to")
    priority: Optional[str] = Field(default=None, description="New priority: LOW, MEDIUM, HIGH, CRITICAL")

    @field_validator("status")
    @classmethod
    def validate_status(cls, v: Optional[str]) -> Optional[str]:
        valid = {"OPEN", "IN_PROGRESS", "ESCALATED", "RESOLVED", "CLOSED"}
        if v and v.upper() not in valid:
            raise ValueError(f"status must be one of: {valid}")
        return v.upper() if v else None

    @field_validator("priority")
    @classmethod
    def validate_update_priority(cls, v: Optional[str]) -> Optional[str]:
        valid = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        if v and v.upper() not in valid:
            raise ValueError(f"priority must be one of: {valid}")
        return v.upper() if v else None


class AddCommentRequest(BaseModel):
    """Request to add an investigation note to a case."""
    text: str = Field(min_length=1, max_length=5000, description="Investigation note text")


class AddEvidenceRequest(BaseModel):
    """Request to attach evidence to a case."""
    evidence_type: str = Field(description="Type: TRANSACTION_LINK, GRAPH_SNAPSHOT, NOTE, DOCUMENT")
    description: str = Field(min_length=1, max_length=2000, description="Description of the evidence")
    reference_id: Optional[str] = Field(default=None, description="Optional ID referencing the source (e.g. transaction_id)")

    @field_validator("evidence_type")
    @classmethod
    def validate_evidence_type(cls, v: str) -> str:
        valid = {"TRANSACTION_LINK", "GRAPH_SNAPSHOT", "NOTE", "DOCUMENT"}
        if v.upper() not in valid:
            raise ValueError(f"evidence_type must be one of: {valid}")
        return v.upper()


class CaseCommentResponse(BaseModel):
    """Serialised investigation comment."""
    comment_id: str
    case_id: str
    analyst_id: str
    text: str
    created_at: str


class CaseEvidenceResponse(BaseModel):
    """Serialised case evidence record."""
    evidence_id: str
    case_id: str
    analyst_id: str
    evidence_type: str
    description: str
    reference_id: Optional[str]
    created_at: str


class CaseAuditEventResponse(BaseModel):
    """A single immutable audit event from the case timeline."""
    event_id: str
    case_id: str
    analyst_id: str
    action: str
    old_value: Optional[str]
    new_value: Optional[str]
    timestamp: str


class FraudCaseResponse(BaseModel):
    """Full fraud case detail response."""
    case_id: str
    transaction_id: str
    risk_score: float
    decision: str
    status: str
    priority: str
    assigned_analyst: Optional[str]
    created_at: str
    updated_at: str
    tags: List[str]
    comment_count: int
    evidence_count: int


class CaseListResponse(BaseModel):
    """Paginated list of fraud cases."""
    cases: List[FraudCaseResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


class CaseTimelineResponse(BaseModel):
    """Immutable audit trail for a case."""
    case_id: str
    events: List[CaseAuditEventResponse]
    total_events: int


class CaseDashboardResponse(BaseModel):
    """Aggregated case management dashboard statistics."""
    total_cases: int
    open_cases: int
    in_progress_cases: int
    escalated_cases: int
    by_status: Dict[str, int]
    by_priority: Dict[str, int]


# ============================================================================
# ENTITY RESOLUTION SCHEMAS (Phase 9)
# ============================================================================

class EntityLinkRequest(BaseModel):
    """Request to link two entities in the knowledge graph."""
    source_entity_id: Optional[str] = Field(default=None, description="Source entity ID (optional if source_value provided)")
    source_entity_type: str = Field(default="ACCOUNT", description="Source entity type: ACCOUNT, DEVICE, IP_ADDRESS, PHONE_NUMBER, EMAIL, WALLET, etc.")
    source_value: Optional[str] = Field(default=None, description="Source entity value (used if source_entity_id not provided)")
    target_entity_id: Optional[str] = Field(default=None, description="Target entity ID (optional if target_value provided)")
    target_entity_type: str = Field(default="ACCOUNT", description="Target entity type: ACCOUNT, DEVICE, IP_ADDRESS, PHONE_NUMBER, EMAIL, WALLET, etc.")
    target_value: Optional[str] = Field(default=None, description="Target entity value (used if target_entity_id not provided)")
    relationship_type: str = Field(default="SHARED_DEVICE", description="Relationship type: SHARED_DEVICE, SHARED_IP, SHARED_PHONE, SHARED_EMAIL, WALLET_OWNER, etc.")
    confidence_score: float = Field(default=0.5, ge=0.0, le=1.0, description="Relationship confidence score")
    evidence: Optional[List[str]] = Field(default_factory=list, description="Evidence supporting the relationship")

    @field_validator("source_entity_type", "target_entity_type")
    @classmethod
    def validate_entity_type(cls, v: str) -> str:
        valid_types = {"ACCOUNT", "DEVICE", "IP_ADDRESS", "PHONE_NUMBER", "EMAIL", "WALLET", "BANK_ACCOUNT", "CARD", "TRANSACTION", "LOCATION"}
        if v.upper() not in valid_types:
            raise ValueError(f"entity_type must be one of: {valid_types}")
        return v.upper()

    @field_validator("relationship_type")
    @classmethod
    def validate_relationship_type(cls, v: str) -> str:
        valid_types = {"SHARED_DEVICE", "SHARED_IP", "SHARED_PHONE", "SHARED_EMAIL", "WALLET_OWNER", "WALLET_BENEFICIARY", "TRANSFER_FROM", "TRANSFER_TO", "SAME_PERSON", "FAMILY_MEMBER", "BUSINESS_ASSOCIATE", "CASH_OUT", "MULE_ACCOUNT"}
        if v.upper() not in valid_types:
            raise ValueError(f"relationship_type must be one of: {valid_types}")
        return v.upper()


class EntityResponse(BaseModel):
    """Response containing entity information."""
    id: str
    entity_type: str
    value: str
    risk_score: float
    tags: List[str]
    created_at: str
    updated_at: str


class EntityRelationshipResponse(BaseModel):
    """Response containing relationship information."""
    source_id: str
    target_id: str
    relationship_type: str
    confidence_score: float
    evidence: List[str]
    created_at: str


class EntityLinkResponse(BaseModel):
    """Response from linking entities."""
    success: bool
    relationship: EntityRelationshipResponse
    source_entity: EntityResponse
    target_entity: EntityResponse
    is_new_relationship: bool
    is_new_source_entity: bool
    is_new_target_entity: bool
    processing_time_ms: float


class EntityNetworkResponse(BaseModel):
    """Response containing entity network information."""
    root_entity_id: str
    entities: List[Dict[str, Any]]
    relationships: List[Dict[str, Any]]
    depth: int
    total_entities: int
    total_relationships: int
    processing_time_ms: float


class FraudClusterResponse(BaseModel):
    """Response containing fraud cluster information."""
    cluster_id: str
    entity_ids: List[str]
    risk_score: float
    tags: List[str]
    created_at: str
    updated_at: str
    member_count: int


class HighRiskRingsResponse(BaseModel):
    """Response containing high-risk fraud rings."""
    rings: List[FraudClusterResponse]
    total_rings: int
    critical_count: int
    high_count: int
    processing_time_ms: float


class RiskPropagationNode(BaseModel):
    """A node affected by risk propagation."""
    node_id: str
    entity_type: str
    propagated_risk: float
    tier: str


class ContagionReportResponse(BaseModel):
    """Response containing risk contagion report."""
    source_entity_id: str
    source_entity_type: str
    source_risk_score: float
    source_contagion_score: float
    total_affected: int
    max_depth: int
    critical: List[RiskPropagationNode]
    high: List[RiskPropagationNode]
    medium: List[RiskPropagationNode]
    low: List[RiskPropagationNode]
    processing_time_ms: float


class ClusterDetailResponse(BaseModel):
    """Response containing detailed cluster information."""
    cluster: FraudClusterResponse
    entities: List[EntityResponse]
    relationships: List[EntityRelationshipResponse]
    processing_time_ms: float


class GraphStatsResponse(BaseModel):
    """Response containing knowledge graph statistics."""
    current_entities: int
    current_relationships: int
    current_clusters: int
    cache_utilization: float
    graph_density: float
    graph_connected_components: int
    processing_time_ms: float


# =============================================================================
# Predictive Intelligence Schemas
# =============================================================================

class SimulationScenarioRequest(BaseModel):
    """Request to create a simulation scenario."""
    simulation_type: str
    source_entity_ids: List[str] = []
    parameters: Dict[str, Any] = {}
    use_template: bool = True


class SimulationScenarioResponse(BaseModel):
    """Response containing simulation scenario."""
    scenario_id: str
    simulation_type: str
    source_entity_ids: List[str]
    parameters: Dict[str, Any]
    status: str
    created_at: str
    created_by: str


class SimulationResultResponse(BaseModel):
    """Response containing simulation result."""
    scenario_id: str
    predicted_outcomes: List[Dict[str, Any]]
    risk_score: float
    affected_entities: List[str]
    confidence: float
    processing_time_ms: float
    timestamp: str


class ForecastRequest(BaseModel):
    """Request to forecast risk."""
    entity_id: str
    current_risk: float
    forecast_period: str = "DAY_1"


class ForecastResultResponse(BaseModel):
    """Response containing forecast result."""
    entity_id: str
    forecast_period: str
    risk_score: float
    confidence: float
    factors: List[Dict[str, Any]]
    recommendations: List[str]
    timestamp: str


class RiskTrendResponse(BaseModel):
    """Response containing risk trend forecast."""
    entity_id: str
    current_risk: float
    predicted_risk: float
    risk_trend: str
    time_to_peak: Optional[str]
    confidence: float
    timestamp: str


class CampaignPredictionResponse(BaseModel):
    """Response containing campaign prediction."""
    campaign_id: str
    campaign_name: str
    predicted_status: str
    growth_rate: float
    affected_entities: List[str]
    peak_time: Optional[str]
    confidence: float
    timestamp: str


class AttackPathResponse(BaseModel):
    """Response containing attack path prediction."""
    source_entity_id: str
    predicted_path: List[str]
    probability: float
    estimated_damage: float
    confidence: float
    timestamp: str


class RecommendationResponse(BaseModel):
    """Response containing prevention recommendation."""
    recommendation_id: str
    entity_id: str
    recommendation_type: str
    priority: str
    description: str
    expected_impact: float
    timestamp: str


class PredictiveStatsResponse(BaseModel):
    """Response containing predictive intelligence statistics."""
    total_simulations: int
    total_forecasts: int
    total_campaigns: int
    total_recommendations: int
    current_scenarios: int
    current_campaigns: int
    processing_time_ms: float


# =============================================================================
# Multi-Agent SOC Schemas
# =============================================================================

class InvestigationRequestSchema(BaseModel):
    """Request to initiate an investigation."""
    entity_id: Optional[str] = None
    case_id: Optional[str] = None
    alert_ids: List[str] = []
    priority: str = "MEDIUM"
    context: Dict[str, Any] = {}


class InvestigationResponse(BaseModel):
    """Response containing investigation results."""
    investigation_id: str
    entity_id: str
    status: str
    risk_score: float
    findings: List[Dict[str, Any]]
    recommendations: List[str]
    timestamp: str


class ThreatAnalysisRequest(BaseModel):
    """Request for threat intelligence analysis."""
    threat_type: str
    indicators: List[Dict[str, Any]] = []
    affected_entities: List[str] = []


class ThreatAnalysisResponse(BaseModel):
    """Response containing threat intelligence report."""
    report_id: str
    threat_type: str
    severity: str
    confidence: float
    ttps: List[str]
    recommendations: List[str]
    timestamp: str


class ForensicAnalysisRequest(BaseModel):
    """Request for forensic analysis."""
    target_entity_id: str
    analysis_type: str
    evidence_types: List[str] = []


class ForensicAnalysisResponse(BaseModel):
    """Response containing forensic analysis."""
    analysis_id: str
    target_entity_id: str
    analysis_type: str
    conclusion: str
    confidence: float
    artifacts: List[Dict[str, Any]]
    timestamp: str


class FraudRingDetectionRequest(BaseModel):
    """Request to detect a fraud ring."""
    seed_entities: List[str]
    ring_type: str = "unknown"


class FraudRingResponse(BaseModel):
    """Response containing fraud ring analysis."""
    ring_id: str
    ring_name: Optional[str]
    member_count: int
    ring_score: float
    ring_type: str
    financial_impact: float
    confidence: float
    timestamp: str


class SOCReportRequest(BaseModel):
    """Request to generate a SOC report."""
    report_type: str
    period_start: Optional[str] = None
    period_end: Optional[str] = None


class SOCReportResponse(BaseModel):
    """Response containing SOC report."""
    report_id: str
    report_type: str
    period_start: str
    period_end: str
    metrics: Dict[str, float]
    threats_identified: List[Dict[str, Any]]
    recommendations: List[str]
    generated_by: str
    timestamp: str


class OrchestrationRequest(BaseModel):
    """Request to orchestrate a multi-agent workflow."""
    workflow_name: str
    tasks: List[Dict[str, Any]] = []
    priority: str = "MEDIUM"


class OrchestrationResponse(BaseModel):
    """Response containing orchestration plan."""
    plan_id: str
    title: str
    task_count: int
    estimated_duration_seconds: int
    status: str
    timestamp: str


class SOCDashboardResponse(BaseModel):
    """Response containing SOC dashboard data."""
    overview: Dict[str, Any]
    trends: Dict[str, Any]
    performance: Dict[str, Any]
    alerts_by_severity: Dict[str, int]
    timestamp: str


class SOCStatsResponse(BaseModel):
    """Response containing SOC statistics."""
    total_agents: int
    active_tasks: int
    completed_tasks: int
    investigations_stored: int
    threat_reports_stored: int
    fraud_rings_stored: int
    reports_stored: int


# =============================================================================
# Executive Governance Schemas
# =============================================================================

class DashboardRequest(BaseModel):
    """Request to generate executive dashboard."""
    title: str = "Executive Risk Dashboard"
    period: str = "daily"


class DashboardResponse(BaseModel):
    """Response containing executive dashboard."""
    dashboard_id: str
    title: str
    period: str
    risk_summary: Dict[str, Any]
    compliance_summary: Dict[str, Any]
    performance_summary: Dict[str, Any]
    key_metrics_count: int
    alerts_count: int
    timestamp: str


class BoardReportRequest(BaseModel):
    """Request to generate board report."""
    period_start: str
    period_end: str
    include_sections: List[str] = []


class BoardReportResponse(BaseModel):
    """Response containing board report."""
    report_id: str
    title: str
    period_start: str
    period_end: str
    summary: Dict[str, Any]
    metrics: List[Dict[str, Any]]
    findings_count: int
    recommendations_count: int
    status: str
    timestamp: str


class ComplianceGapAnalysisRequest(BaseModel):
    """Request for compliance gap analysis."""
    framework_name: str


class ComplianceGapAnalysisResponse(BaseModel):
    """Response containing gap analysis."""
    framework: str
    compliance_percentage: float
    gaps_identified: int
    gap_details: List[Dict[str, Any]]


class RiskScorecardRequest(BaseModel):
    """Request to generate risk scorecard."""
    period: str = "quarterly"


class RiskScorecardResponse(BaseModel):
    """Response containing risk scorecard."""
    scorecard_id: str
    period: str
    overall_risk_score: float
    risk_level: str
    risk_categories: Dict[str, float]
    risk_trend: str
    key_risks_count: int
    next_review: Optional[str]
    timestamp: str


class AuditFindingRequest(BaseModel):
    """Request to create audit finding."""
    title: str
    description: str
    severity: str
    category: str
    affected_controls: List[str] = []
    affected_entities: List[str] = []


class AuditFindingResponse(BaseModel):
    """Response containing audit finding."""
    finding_id: str
    title: str
    severity: str
    status: str
    risk_impact: float
    due_date: Optional[str]
    timestamp: str


class GovernanceReportRequest(BaseModel):
    """Request to generate governance report."""
    report_type: str
    period_start: Optional[str] = None
    period_end: Optional[str] = None


class GovernanceReportResponse(BaseModel):
    """Response containing governance report."""
    report_id: str
    report_type: str
    title: str
    period_start: str
    period_end: str
    summary: Dict[str, Any]
    status: str
    timestamp: str


class GovernanceStatsResponse(BaseModel):
    """Response containing governance statistics."""
    metrics_stored: int
    scorecards_stored: int
    frameworks_tracked: int
    findings_stored: int
    open_findings: int
    critical_findings: int
    dashboards_stored: int
    reports_stored: int


# =============================================================================
# Advanced Analytics & BI Schemas
# =============================================================================

class MetricDefinitionRequest(BaseModel):
    """Request to define a metric."""
    name: str
    description: str
    metric_type: str
    aggregation: str
    category: str
    unit: str
    formula: Optional[str] = None


class MetricValueRequest(BaseModel):
    """Request to record a metric value."""
    metric_id: str
    value: float
    dimensions: Dict[str, str] = {}


class KPIRequest(BaseModel):
    """Request to create a KPI."""
    name: str
    description: str
    metric_id: str
    target_value: float
    warning_threshold: float
    critical_threshold: float
    category: str
    owner: Optional[str] = None


class KPIResponse(BaseModel):
    """Response containing KPI data."""
    kpi_id: str
    name: str
    target_value: float
    current_value: Optional[float]
    change_percent: Optional[float]
    status: str
    category: str


class TrendAnalysisRequest(BaseModel):
    """Request to perform trend analysis."""
    metric_name: str
    data_points: List[float]
    period_start: str
    period_end: str


class TrendAnalysisResponse(BaseModel):
    """Response containing trend analysis."""
    analysis_id: str
    metric_name: str
    direction: str
    slope: float
    volatility: float
    anomaly_detected: bool
    forecast_values: List[float]
    timestamp: str


class CorrelationAnalysisRequest(BaseModel):
    """Request to perform correlation analysis."""
    variable_a: List[float]
    variable_b: List[float]
    variable_a_name: str
    variable_b_name: str


class CorrelationAnalysisResponse(BaseModel):
    """Response containing correlation analysis."""
    correlation_id: str
    variable_a: str
    variable_b: str
    correlation_coefficient: float
    p_value: float
    significance: str
    interpretation: str
    timestamp: str


class DashboardRequest(BaseModel):
    """Request to create BI dashboard."""
    name: str
    description: str
    chart_ids: List[str] = []
    kpi_ids: List[str] = []
    refresh_interval: int = 300


class DashboardResponse(BaseModel):
    """Response containing dashboard data."""
    dashboard_id: str
    name: str
    description: str
    chart_count: int
    kpi_count: int
    refresh_interval: int
    timestamp: str


class ChartDataRequest(BaseModel):
    """Request for chart data."""
    chart_id: str
    time_range: str = "30d"


class ReportGenerationRequest(BaseModel):
    """Request to generate a report."""
    report_type: str
    content_config: Dict[str, Any] = {}
    format: str = "PDF"


class ReportGenerationResponse(BaseModel):
    """Response containing generated report."""
    report_id: str
    report_type: str
    format: str
    generated_at: str
    page_count: int


class ScheduledReportRequest(BaseModel):
    """Request to create scheduled report."""
    name: str
    description: str
    schedule: str
    report_type: str
    content_config: Dict[str, Any] = {}
    recipients: List[str] = []
    format: str = "PDF"


class AnalyticsStatsResponse(BaseModel):
    """Response containing analytics statistics."""
    metric_definitions_stored: int
    kpis_stored: int
    trends_stored: int
    dashboards_stored: int
    reports_stored: int
    insights_stored: int
    unacknowledged_insights: int

# =============================================================================
# Threat Hunting & Security Analytics Schemas (Phase 34)
# =============================================================================

class ThreatHuntStartRequest(BaseModel):
    """Request to start a threat hunt."""
    model_config = ConfigDict(extra="forbid")

    name: str = Field(description="Name of the threat hunt")
    description: str = Field(description="Description of the threat hunt")
    query_criteria: Dict[str, Any] = Field(default_factory=dict, description="Custom criteria for finding threats")


class ThreatHuntStartResponse(BaseModel):
    """Response containing started hunt details."""
    model_config = ConfigDict(extra="allow")

    hunt_id: str
    name: str
    state: str
    created_at: str


class ThreatQueryRequest(BaseModel):
    """Request to query threats."""
    model_config = ConfigDict(extra="forbid")

    entity_id: str = Field(description="Entity identifier")
    entity_type: str = Field(default="user", description="Entity type")
    amount: float = Field(default=0.0)
    hour: int = Field(default=12)
    ip_address: str = Field(default="")
    device_id: str = Field(default="")
    device_status: str = Field(default="UNKNOWN")
    failed_attempts: int = Field(default=0)
    operation: str = Field(default="")
    recent_txn_count_1m: int = Field(default=0)
    events: List[Dict[str, Any]] = Field(default_factory=list)
    relationships: List[Dict[str, Any]] = Field(default_factory=list)


class ThreatQueryResponse(BaseModel):
    """Response containing threat query details."""
    model_config = ConfigDict(extra="allow")

    entity_id: str
    entity_type: str
    score: float
    severity: str
    breakdown: Dict[str, float]
    active_indicators: List[str]


class ThreatCorrelateRequest(BaseModel):
    """Request to correlate threats."""
    model_config = ConfigDict(extra="forbid")

    name: str = Field(description="Name of the correlation")
    entities: List[str] = Field(description="List of entity IDs")
    indicator_ids: List[str] = Field(description="List of threat indicator IDs")


class ThreatCorrelateResponse(BaseModel):
    """Response containing correlation details."""
    model_config = ConfigDict(extra="allow")

    correlation_id: str
    name: str
    correlation_score: float
    timestamp: str


# =============================================================================
# Zero Trust Security Schemas (Phase 31)
# =============================================================================

class ZeroTrustEvaluateRequest(BaseModel):
    """Request for zero trust evaluation."""
    model_config = ConfigDict(extra="forbid")
    
    user_id: str = Field(description="User identifier")
    device_id: Optional[str] = Field(default=None, description="Device identifier")
    session_id: Optional[str] = Field(default=None, description="Session identifier")
    ip_address: Optional[str] = Field(default=None, description="IP address")
    location: Optional[Dict[str, Any]] = Field(default=None, description="Location data")
    user_agent: Optional[str] = Field(default=None, description="User agent string")
    resource: Optional[str] = Field(default=None, description="Resource being accessed")
    action: Optional[str] = Field(default=None, description="Action being performed")
    authentication_method: Optional[str] = Field(default=None, description="Auth method")
    authentication_strength: float = Field(default=0.5, ge=0, le=1, description="Auth strength")
    device_info: Optional[Dict[str, Any]] = Field(default=None, description="Device info for registration")


class DeviceRegisterRequest(BaseModel):
    """Request to register a device."""
    model_config = ConfigDict(extra="forbid")
    
    user_id: str = Field(description="User identifier")
    device_type: str = Field(description="Device type (mobile, desktop, tablet)")
    os_version: Optional[str] = Field(default=None, description="OS version")
    browser: Optional[str] = Field(default=None, description="Browser name")
    browser_version: Optional[str] = Field(default=None, description="Browser version")
    screen_resolution: Optional[str] = Field(default=None, description="Screen resolution")
    timezone: Optional[str] = Field(default=None, description="Device timezone")
    language: Optional[str] = Field(default=None, description="Language")
    ip_address: Optional[str] = Field(default=None, description="IP address")
    mac_address: Optional[str] = Field(default=None, description="MAC address")
    serial_number: Optional[str] = Field(default=None, description="Device serial number")


class DeviceRegisterResponse(BaseModel):
    """Response for device registration."""
    model_config = ConfigDict(extra="allow")
    
    device_id: str
    fingerprint_id: str
    status: str
    trust_score: float
    first_seen: str
    last_seen: str
    verification_required: bool = False


class SessionAnalyzeRequest(BaseModel):
    """Request for session risk analysis."""
    model_config = ConfigDict(extra="forbid")
    
    user_id: str = Field(description="User identifier")
    session_id: Optional[str] = Field(default=None, description="Session identifier")
    device_id: Optional[str] = Field(default=None, description="Device identifier")
    ip_address: Optional[str] = Field(default=None, description="IP address")
    location: Optional[Dict[str, Any]] = Field(default=None, description="Location data")
    user_agent: Optional[str] = Field(default=None, description="User agent")
    resource: Optional[str] = Field(default=None, description="Resource being accessed")
    action: Optional[str] = Field(default=None, description="Action being performed")
    auth_method: Optional[str] = Field(default=None, description="Auth method")
    auth_strength: float = Field(default=0.5, ge=0, le=1)
    session_attributes: Optional[Dict[str, Any]] = Field(default=None, description="Session attributes")


class SessionAnalyzeResponse(BaseModel):
    """Response for session risk analysis."""
    model_config = ConfigDict(extra="allow")
    
    session_id: str
    user_id: str
    risk_level: str
    risk_score: float
    anomalies_detected: List[str]
    location_risk: float
    behavior_deviation: float
    velocity_anomaly: bool
    unusual_operations: List[str]
    recommended_actions: List[str]
    evaluated_at: str


class PolicyResponse(BaseModel):
    """Response for policy information."""
    model_config = ConfigDict(extra="allow")
    
    policy_id: str
    name: str
    description: str
    priority: int
    enabled: bool
    conditions: Dict[str, Any]
    actions: Dict[str, Any]
    created_at: str
    updated_at: str


# =============================================================================
# Autonomous SOAR Platform Schemas (Phase 35)
# =============================================================================

class IncidentCreateRequest(BaseModel):
    """Request to create a security incident."""
    model_config = ConfigDict(extra="forbid")

    title: str = Field(description="Incident title")
    description: str = Field(description="Incident description")
    severity: str = Field(description="Threat severity (LOW, MEDIUM, HIGH, CRITICAL)")
    source: str = Field(description="Source of the incident")
    entities: List[str] = Field(default_factory=list, description="Associated entity IDs")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")


class IncidentResponse(BaseModel):
    """Response containing incident details."""
    model_config = ConfigDict(extra="allow")

    incident_id: str
    title: str
    description: str
    severity: str
    status: str
    source: str
    created_at: str
    updated_at: str
    entities: List[str]
    assigned_analyst: Optional[str] = None
    tags: List[str]
    metadata: Dict[str, Any]


class PlaybookCreateRequest(BaseModel):
    """Request to register an automation playbook."""
    model_config = ConfigDict(extra="forbid")

    name: str = Field(description="Playbook name")
    description: str = Field(description="Playbook description")
    version: str = Field(description="Playbook version")
    tasks: List[Dict[str, Any]] = Field(description="List of task definitions")
    rules: Dict[str, Any] = Field(description="Triggers and conditions")


class PlaybookExecuteRequest(BaseModel):
    """Request to execute a playbook."""
    model_config = ConfigDict(extra="forbid")

    playbook_id: str = Field(description="Playbook ID")
    incident_id: str = Field(description="Incident ID")


class ResponseActionRequest(BaseModel):
    """Request to run a response action."""
    model_config = ConfigDict(extra="forbid")

    action_type: str = Field(description="Type of response action")
    target_id: str = Field(description="Target entity ID")
    additional_params: Optional[Dict[str, Any]] = Field(default_factory=dict)


class ResponseActionResponse(BaseModel):
    """Response containing response action results."""
    model_config = ConfigDict(extra="allow")

    action_id: str
    name: str
    action_type: str
    status: str
    target_id: str
    executed_by: str
    executed_at: str
    result: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None


class ContainmentRequest(BaseModel):
    """Request to trigger a containment action."""
    model_config = ConfigDict(extra="forbid")

    type: str = Field(description="Type of containment (NETWORK_ISOLATE, ACCOUNT_SUSPEND, API_BLOCK)")
    target_entity: str = Field(description="Target entity ID")
    duration_seconds: Optional[int] = Field(default=None, description="Optional auto-release duration")


class ContainmentResponse(BaseModel):
    """Response containing containment details."""
    model_config = ConfigDict(extra="allow")

    containment_id: str
    type: str
    status: str
    target_entity: str
    initiated_by: str
    timestamp: str
    duration_seconds: Optional[int] = None
    released_at: Optional[str] = None


class SOARDashboardResponse(BaseModel):
    """Response containing SOAR dashboard statistics."""
    model_config = ConfigDict(extra="allow")

    total_incidents: int
    status_distribution: Dict[str, int]
    severity_distribution: Dict[str, int]
    active_containments: int
    running_workflows: int
    total_audit_records: int


class SOARAuditResponse(BaseModel):
    """Response containing SOAR audit record details."""
    model_config = ConfigDict(extra="allow")

    record_id: str
    action: str
    user_id: str
    ip_address: str
    timestamp: str
    details: Dict[str, Any]
    status: str
