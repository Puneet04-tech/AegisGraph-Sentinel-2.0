"""
Quantum Security Models.

Models for quantum-safe cryptography platform.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class CryptoAlgorithm(str, Enum):
    """Cryptographic algorithms."""
    RSA_2048 = "RSA-2048"
    RSA_4096 = "RSA-4096"
    AES_128 = "AES-128"
    AES_256 = "AES-256"
    ECC_P256 = "ECC-P256"
    ECC_P384 = "ECC-P384"
    CRYSTALS_KYBER = "CRYSTALS-Kyber"
    CRYSTALS_DILITHIUM = "CRYSTALS-Dilithium"
    FALCON = "Falcon"
    SPHINCS_PLUS = "SPHINCS+"


class CryptoType(str, Enum):
    """Cryptographic asset types."""
    SYMMETRIC_KEY = "symmetric_key"
    ASYMMETRIC_KEY = "asymmetric_key"
    CERTIFICATE = "certificate"
    HASH = "hash"
    SIGNATURE = "signature"


class RiskLevel(str, Enum):
    """Risk levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class MigrationStatus(str, Enum):
    """Migration status."""
    NOT_STARTED = "not_started"
    PLANNED = "planned"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    AT_RISK = "at_risk"


@dataclass
class CryptoAsset:
    """Cryptographic asset."""
    asset_id: str
    name: str
    algorithm: CryptoAlgorithm
    crypto_type: CryptoType
    key_size: int
    usage: str
    system: str
    location: str
    owner: Optional[str] = None
    rotation_period_days: Optional[int] = None
    last_rotated: Optional[datetime] = None
    expiration_date: Optional[datetime] = None
    quantum_resistant: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class Certificate:
    """Digital certificate."""
    cert_id: str
    subject: str
    issuer: str
    serial_number: str
    algorithm: CryptoAlgorithm
    key_size: int
    public_key_fingerprint: str
    valid_from: datetime
    valid_until: datetime
    san: List[str] = field(default_factory=list)
    status: str = "valid"
    quantum_resistant: bool = False


@dataclass
class QuantumRiskAssessment:
    """Quantum risk assessment."""
    assessment_id: str
    asset_id: str
    algorithm: CryptoAlgorithm
    quantum_vulnerable: bool
    time_to_crack_hours: Optional[float] = None
    risk_score: float = 0.0
    risk_level: RiskLevel = RiskLevel.LOW
    recommended_action: str = ""
    estimated_migration_effort: str = "unknown"
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class KeyLifecycleRecord:
    """Key lifecycle record."""
    record_id: str
    key_id: str
    event: str
    performed_by: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ComplianceReport:
    """Compliance report."""
    report_id: str
    framework: str
    compliant: bool
    total_assets: int
    compliant_assets: int
    non_compliant_assets: List[str] = field(default_factory=list)
    findings: List[str] = field(default_factory=list)
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class GovernancePolicy:
    """Cryptographic governance policy."""
    policy_id: str
    name: str
    description: str
    rules: List[Dict[str, Any]]
    enforced: bool = True
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class MigrationPlan:
    """Quantum migration plan."""
    plan_id: str
    name: str
    assets: List[str] = field(default_factory=list)
    target_algorithm: Optional[CryptoAlgorithm] = None
    status: MigrationStatus = MigrationStatus.NOT_STARTED
    priority: int = 1
    estimated_completion: Optional[datetime] = None
    progress: float = 0.0


@dataclass
class AuditEvent:
    """Audit event."""
    event_id: str
    timestamp: datetime
    user_id: str
    action: str
    resource_type: str
    resource_id: str
    details: Dict[str, Any] = field(default_factory=dict)
    success: bool = True