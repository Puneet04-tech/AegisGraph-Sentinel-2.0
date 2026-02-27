"""
Pydantic schemas for API request/response validation
"""

from pydantic import BaseModel, Field, field_validator
from typing import Optional, List, Dict
from datetime import datetime


class BiometricsData(BaseModel):
    """Keystroke biometrics data"""
    hold_times: List[float] = Field(description="Key hold times in milliseconds")
    flight_times: List[float] = Field(description="Key flight times in milliseconds")
    
    @field_validator('hold_times', 'flight_times')
    @classmethod
    def validate_positive(cls, v):
        if any(x < 0 for x in v):
            raise ValueError("Times must be non-negative")
        return v


class TransactionCheckRequest(BaseModel):
    """Request schema for transaction fraud check"""
    transaction_id: str = Field(description="Unique transaction identifier")
    source_account: str = Field(description="Source account ID")
    target_account: str = Field(description="Target account ID")
    amount: float = Field(gt=0, description="Transaction amount")
    currency: str = Field(default="INR", description="Currency code")
    mode: str = Field(description="Transaction mode (UPI, IMPS, NEFT, etc.)")
    timestamp: str = Field(description="Transaction timestamp (ISO format)")
    device_id: Optional[str] = Field(default=None, description="Device identifier")
    biometrics: Optional[BiometricsData] = Field(default=None, description="Behavioral biometrics")
    ip_address: Optional[str] = Field(default=None, description="IP address")
    location: Optional[str] = Field(default=None, description="Transaction location")
    
    class Config:
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


class RiskBreakdown(BaseModel):
    """Risk score breakdown by component"""
    graph: float = Field(ge=0, le=1, description="Graph-based risk")
    velocity: float = Field(ge=0, le=1, description="Velocity-based risk")
    behavior: float = Field(ge=0, le=1, description="Behavioral risk")
    entropy: float = Field(ge=0, le=1, description="Entropy-based risk")


class TransactionCheckResponse(BaseModel):
    """Response schema for transaction fraud check"""
    transaction_id: str
    risk_score: float = Field(ge=0, le=1, description="Overall risk score")
    decision: str = Field(description="Decision: ALLOW, REVIEW, or BLOCK")
    confidence: float = Field(ge=0, le=1, description="Confidence in decision")
    breakdown: RiskBreakdown = Field(description="Risk score breakdown")
    explanation: str = Field(description="Human-readable explanation")
    recommended_action: str = Field(description="Recommended action")
    processing_time_ms: float = Field(description="Processing time in milliseconds")
    timestamp: str = Field(description="Response timestamp")
    
    class Config:
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
                "timestamp": "2026-02-26T14:30:00.142Z"
            }
        }


class BatchTransactionRequest(BaseModel):
    """Request schema for batch transaction checking"""
    transactions: List[TransactionCheckRequest] = Field(description="List of transactions to check")
    
    @field_validator('transactions')
    @classmethod
    def validate_batch_size(cls, v):
        if len(v) > 100:
            raise ValueError("Batch size cannot exceed 100 transactions")
        return v


class BatchTransactionResponse(BaseModel):
    """Response schema for batch transaction checking"""
    results: List[TransactionCheckResponse]
    total_processed: int
    total_blocked: int
    total_review: int
    total_allowed: int
    processing_time_ms: float


class HealthCheckResponse(BaseModel):
    """Health check response"""
    status: str = Field(description="Service status")
    version: str = Field(description="API version")
    model_loaded: bool = Field(description="Whether model is loaded")
    graph_loaded: bool = Field(description="Whether transaction graph is loaded")
    uptime_seconds: float = Field(description="Service uptime in seconds")
    requests_processed: int = Field(description="Total requests processed")


class ModelInfo(BaseModel):
    """Model information"""
    model_name: str
    version: str
    architecture: str
    parameters: int
    trained_on: str
    performance_metrics: Dict[str, float]


class StatsResponse(BaseModel):
    """Statistics response"""
    total_requests: int
    decisions: Dict[str, int]
    avg_risk_score: float
    avg_processing_time_ms: float
    uptime_seconds: float


class ErrorResponse(BaseModel):
    """Error response schema"""
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
    audio_base64: str = Field(description="Base64-encoded audio WAV file (max 30 seconds)")
    sample_rate: int = Field(default=16000, description="Audio sample rate in Hz")
    
    @field_validator('sample_rate')
    @classmethod
    def validate_sample_rate(cls, v):
        if v not in [8000, 16000, 44100, 48000]:
            raise ValueError("Sample rate must be 8000, 16000, 44100, or 48000 Hz")
        return v


class VoiceAnalysisResponse(BaseModel):
    """Response for voice stress analysis"""
    transaction_id: str
    stress_score: float = Field(ge=0, le=100, description="Voice stress score (0-100)")
    classification: str = Field(description="NORMAL, MILD_STRESS, or SEVERE_COERCION")
    confidence: float = Field(ge=0, le=1, description="Confidence in classification")
    features: Dict[str, float] = Field(description="Acoustic features extracted")
    recommended_action: str = Field(description="Recommended action based on stress level")
    processing_time_ms: float = Field(description="Processing time in milliseconds")
    
    class Config:
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
    account_id: str
    risk_score: float = Field(ge=0, le=100, description="Mule risk score (0-100)")
    risk_level: str = Field(description="CRITICAL_MULE_RISK, HIGH_MULE_RISK, MODERATE, or LOW")
    confidence: float = Field(ge=0, le=1, description="Confidence in assessment")
    features: Dict[str, float] = Field(description="Feature scores breakdown")
    red_flags: List[str] = Field(description="List of identified red flags")
    recommended_action: str = Field(description="Recommended action")
    processing_time_ms: float = Field(description="Processing time in milliseconds")
    
    class Config:
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
class BlockchainSealRequest(BaseModel):
    """Request to seal evidence in blockchain"""
    transaction_id: str
    source_account: str
    target_account: str
    amount: float
    risk_result: Dict = Field(description="Complete risk assessment result")
    explanation: str = Field(description="Decision explanation")


class BlockchainEvidenceResponse(BaseModel):
    """Response from blockchain evidence sealing"""
    evidence_id: str = Field(description="Unique evidence identifier")
    transaction_hash: str = Field(description="Transaction hash (no PII)")
    block_number: int = Field(description="Block number in chain")
    block_hash: str = Field(description="Block hash for integrity")
    timestamp: str = Field(description="Timestamp of sealing")
    finality_time_ms: float = Field(description="Time to achieve consensus")
    validators: List[str] = Field(description="Validator nodes that confirmed")
    
    class Config:
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


class BlockchainVerificationResponse(BaseModel):
    """Response from blockchain evidence verification"""
    evidence_id: str
    verified: bool = Field(description="Whether evidence is valid")
    block_exists: bool = Field(description="Block exists in chain")
    chain_integrity: bool = Field(description="Chain integrity intact")
    consensus_nodes: int = Field(description="Nodes that confirmed")
    original_timestamp: str = Field(description="Original seal timestamp")
    verification_details: Dict = Field(description="Detailed verification info")


class LegalExportRequest(BaseModel):
    """Request for legal evidence export"""
    evidence_id: str
    case_number: str = Field(description="Legal case number")
    requesting_authority: str = Field(description="Law enforcement agency")
    authorization_token: str = Field(description="Authorization token for access")


class LegalExportResponse(BaseModel):
    """Response with legal evidence package"""
    evidence_id: str
    case_number: str
    evidence_package: Dict = Field(description="Complete evidence package")
    chain_of_custody: List[Dict] = Field(description="Chain of custody records")
    attestations: List[Dict] = Field(description="Validator attestations")
    export_timestamp: str
    authorized_by: str
