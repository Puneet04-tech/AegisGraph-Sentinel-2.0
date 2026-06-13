"""
Zero Trust Security Architecture for AegisGraph Sentinel 2.0

Implements enterprise-grade Zero Trust principles:
- Never trust, always verify
- Continuous verification
- Least privilege access
- Assume breach

Modules:
    - trust_engine: Trust scoring and evaluation
    - device_manager: Device trust and fingerprinting
    - session_analyzer: Session risk analysis
    - policy_engine: Fine-grained policy enforcement
    - service: Combined Zero Trust service
"""

from .models import (
    TrustLevel,
    TrustScore,
    DeviceTrust,
    DeviceFingerprint,
    DeviceStatus,
    SessionRisk,
    SessionRiskLevel,
    PolicyResult,
    EvaluationContext,
    RiskFactors,
    Policy,
)
from .trust_engine import TrustEngine
from .device_manager import DeviceTrustManager
from .session_analyzer import SessionRiskAnalyzer
from .policy_engine import PolicyEnforcementEngine
from .store import ZeroTrustStore
from .service import ZeroTrustService, get_zero_trust_service

__all__ = [
    # Models
    "TrustLevel",
    "TrustScore",
    "DeviceTrust",
    "DeviceFingerprint",
    "DeviceStatus",
    "SessionRisk",
    "SessionRiskLevel",
    "PolicyResult",
    "EvaluationContext",
    "RiskFactors",
    "Policy",
    # Engine classes
    "TrustEngine",
    "DeviceTrustManager",
    "SessionRiskAnalyzer",
    "PolicyEnforcementEngine",
    # Store and service
    "ZeroTrustStore",
    "ZeroTrustService",
    "get_zero_trust_service",
]