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
