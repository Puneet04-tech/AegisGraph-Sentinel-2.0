"""
Data models for Zero Trust Security Architecture
"""

from __future__ import annotations

import hashlib
import uuid
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone


class TrustLevel(str, Enum):
    BLOCKED = "BLOCKED"
    UNTRUSTED = "UNTRUSTED"
    SUSPICIOUS = "SUSPICIOUS"
    TRUSTED = "TRUSTED"
    HIGHLY_TRUSTED = "HIGHLY_TRUSTED"


class DeviceStatus(str, Enum):
    UNKNOWN = "UNKNOWN"
    REGISTERED = "REGISTERED"
    BLOCKED = "BLOCKED"
    LOST = "LOST"
    STOLEN = "STOLEN"


class SessionRiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class RiskFactors:
    device_trust_score: float = 0.5
    device_registered: bool = False
    device_age_days: int = 0
    behavioral_anomaly_score: float = 0.0
    login_velocity: int = 0
    failed_attempts: int = 0
    location_risk: float = 0.0
    ip_reputation: float = 0.5
    vpn_detected: bool = False
    tor_detected: bool = False
    session_duration: int = 0
    unusual_time: bool = False
    new_device: bool = False
    velocity_anomaly: bool = False
    historical_trust: float = 0.5
    threat_intelligence_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "device_trust_score": self.device_trust_score,
            "device_registered": self.device_registered,
            "device_age_days": self.device_age_days,
            "behavioral_anomaly_score": self.behavioral_anomaly_score,
            "login_velocity": self.login_velocity,
            "failed_attempts": self.failed_attempts,
            "location_risk": self.location_risk,
            "ip_reputation": self.ip_reputation,
            "vpn_detected": self.vpn_detected,
            "tor_detected": self.tor_detected,
            "session_duration": self.session_duration,
            "unusual_time": self.unusual_time,
            "new_device": self.new_device,
            "velocity_anomaly": self.velocity_anomaly,
            "historical_trust": self.historical_trust,
            "threat_intelligence_score": self.threat_intelligence_score,
        }


@dataclass
class TrustScore:
    score: float = 0.5
    level: TrustLevel = TrustLevel.SUSPICIOUS
    factors: RiskFactors = field(default_factory=RiskFactors)
    confidence: float = 0.5
    factors_breakdown: Dict[str, float] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)
    evaluated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": self.score,
            "level": self.level.value if isinstance(self.level, TrustLevel) else self.level,
            "factors": self.factors.to_dict() if isinstance(self.factors, RiskFactors) else self.factors,
            "confidence": self.confidence,
            "factors_breakdown": self.factors_breakdown,
            "recommendations": self.recommendations,
            "evaluated_at": self.evaluated_at,
        }


@dataclass
class DeviceFingerprint:
    fingerprint_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str = ""
    device_type: str = ""
    os_version: str = ""
    browser: str = ""
    browser_version: str = ""
    screen_resolution: str = ""
    timezone: str = ""
    language: str = ""
    ip_address: str = ""
    mac_address: Optional[str] = None
    serial_number: Optional[str] = None
    hash: str = ""

    def __post_init__(self):
        if not self.hash:
            self.hash = self._compute_hash()

    def _compute_hash(self) -> str:
        components = [self.device_type, self.os_version, self.browser, self.browser_version,
                     self.screen_resolution, self.timezone, self.language]
        combined = "|".join(str(c) for c in components)
        return hashlib.sha256(combined.encode()).hexdigest()[:32]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "fingerprint_id": self.fingerprint_id,
            "user_id": self.user_id,
            "device_type": self.device_type,
            "os_version": self.os_version,
            "browser": self.browser,
            "browser_version": self.browser_version,
            "screen_resolution": self.screen_resolution,
            "timezone": self.timezone,
            "language": self.language,
            "ip_address": self.ip_address,
            "hash": self.hash,
        }


@dataclass
class DeviceTrust:
    device_id: str
    fingerprint: DeviceFingerprint = field(default_factory=DeviceFingerprint)
    status: DeviceStatus = DeviceStatus.UNKNOWN
    trust_score: float = 0.5
    first_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_verified: Optional[str] = None
    verification_count: int = 0
    failed_verifications: int = 0
    risk_events: int = 0
    reputation_score: float = 0.5
    tags: List[str] = field(default_factory=list)
    attributes: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "device_id": self.device_id,
            "fingerprint": self.fingerprint.to_dict() if isinstance(self.fingerprint, DeviceFingerprint) else self.fingerprint,
            "status": self.status.value if isinstance(self.status, DeviceStatus) else self.status,
            "trust_score": self.trust_score,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "last_verified": self.last_verified,
            "verification_count": self.verification_count,
            "failed_verifications": self.failed_verifications,
            "risk_events": self.risk_events,
            "reputation_score": self.reputation_score,
            "tags": self.tags,
            "attributes": self.attributes,
        }


@dataclass
class SessionRisk:
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str = ""
    session_start: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    risk_level: SessionRiskLevel = SessionRiskLevel.LOW
    risk_score: float = 0.0
    anomalies_detected: List[str] = field(default_factory=list)
    location_risk: float = 0.0
    behavior_deviation: float = 0.0
    velocity_anomaly: bool = False
    unusual_operations: List[str] = field(default_factory=list)
    context_risks: Dict[str, Any] = field(default_factory=dict)
    recommended_actions: List[str] = field(default_factory=list)
    evaluated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "user_id": self.user_id,
            "session_start": self.session_start,
            "risk_level": self.risk_level.value if isinstance(self.risk_level, SessionRiskLevel) else self.risk_level,
            "risk_score": self.risk_score,
            "anomalies_detected": self.anomalies_detected,
            "location_risk": self.location_risk,
            "behavior_deviation": self.behavior_deviation,
            "velocity_anomaly": self.velocity_anomaly,
            "unusual_operations": self.unusual_operations,
            "context_risks": self.context_risks,
            "recommended_actions": self.recommended_actions,
            "evaluated_at": self.evaluated_at,
        }


@dataclass
class PolicyResult:
    allowed: bool = False
    policy_id: str = ""
    policy_name: str = ""
    decision: str = "DENY"
    matched_conditions: List[str] = field(default_factory=list)
    failed_conditions: List[str] = field(default_factory=list)
    required_actions: List[str] = field(default_factory=list)
    risk_adjustment: float = 0.0
    session_flags: List[str] = field(default_factory=list)
    evaluated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed": self.allowed,
            "policy_id": self.policy_id,
            "policy_name": self.policy_name,
            "decision": self.decision,
            "matched_conditions": self.matched_conditions,
            "failed_conditions": self.failed_conditions,
            "required_actions": self.required_actions,
            "risk_adjustment": self.risk_adjustment,
            "session_flags": self.session_flags,
            "evaluated_at": self.evaluated_at,
        }


@dataclass
class EvaluationContext:
    user_id: str
    session_id: Optional[str] = None
    device_id: Optional[str] = None
    device_fingerprint: Optional[DeviceFingerprint] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    location: Optional[Dict[str, Any]] = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    requested_resource: Optional[str] = None
    requested_action: Optional[str] = None
    authentication_method: Optional[str] = None
    authentication_strength: float = 0.5
    session_attributes: Dict[str, Any] = field(default_factory=dict)
    historical_context: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "user_id": self.user_id,
            "session_id": self.session_id,
            "device_id": self.device_id,
            "device_fingerprint": self.device_fingerprint.to_dict() if self.device_fingerprint and isinstance(self.device_fingerprint, DeviceFingerprint) else self.device_fingerprint,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "location": self.location,
            "timestamp": self.timestamp,
            "requested_resource": self.requested_resource,
            "requested_action": self.requested_action,
            "authentication_method": self.authentication_method,
            "authentication_strength": self.authentication_strength,
            "session_attributes": self.session_attributes,
            "historical_context": self.historical_context,
        }


@dataclass
class Policy:
    policy_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    description: str = ""
    priority: int = 100
    enabled: bool = True
    conditions: Dict[str, Any] = field(default_factory=dict)
    actions: Dict[str, Any] = field(default_factory=dict)
    scope: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "name": self.name,
            "description": self.description,
            "priority": self.priority,
            "enabled": self.enabled,
            "conditions": self.conditions,
            "actions": self.actions,
            "scope": self.scope,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }