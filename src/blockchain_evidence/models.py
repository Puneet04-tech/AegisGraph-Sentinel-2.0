"""
Blockchain Evidence & Chain-of-Custody Models.

Data models for evidence ledger, blockchain verification, and custody tracking.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field
import uuid


class EvidenceType(str, Enum):
    """Evidence types."""
    TRANSACTION = "TRANSACTION"
    DOCUMENT = "DOCUMENT"
    COMMUNICATION = "COMMUNICATION"
    IMAGE = "IMAGE"
    VIDEO = "VIDEO"
    AUDIO = "AUDIO"
    METADATA = "METADATA"
    LOG = "LOG"


class CustodyAction(str, Enum):
    """Custody action types."""
    COLLECTED = "COLLECTED"
    TRANSFERRED = "TRANSFERRED"
    ACCESSED = "ACCESSED"
    MODIFIED = "MODIFIED"
    ARCHIVED = "ARCHIVED"
    DESTROYED = "DESTROYED"


class VerificationStatus(str, Enum):
    """Blockchain verification status."""
    PENDING = "PENDING"
    VERIFIED = "VERIFIED"
    INVALID = "INVALID"
    DISPUTED = "DISPUTED"


class EvidenceRecord(BaseModel):
    """Evidence record."""
    evidence_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    case_id: str
    evidence_type: EvidenceType
    description: str
    hash: str  # SHA-256 hash of evidence
    previous_hash: Optional[str] = None  # Previous block hash (blockchain)
    block_number: Optional[int] = None
    transaction_hash: Optional[str] = None
    collector_id: str
    collected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = Field(default_factory=dict)
    integrity_verified: bool = False


class ChainOfCustody(BaseModel):
    """Chain of custody record."""
    custody_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    evidence_id: str
    action: CustodyAction
    custodian_id: str
    custodian_name: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    location: str
    purpose: str
    hash: str  # Hash of custody record
    previous_custody_hash: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class BlockchainBlock(BaseModel):
    """Blockchain block."""
    block_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    block_number: int
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    evidence_hashes: List[str] = Field(default_factory=list)
    custody_hashes: List[str] = Field(default_factory=list)
    previous_hash: str
    merkle_root: str
    nonce: int = 0
    hash: Optional[str] = None


class VerificationResult(BaseModel):
    """Blockchain verification result."""
    verification_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    evidence_id: str
    status: VerificationStatus
    block_number: Optional[int] = None
    block_hash: Optional[str] = None
    verified_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    chain_integrity: bool = False
    details: Dict[str, Any] = Field(default_factory=dict)


class AuditTrail(BaseModel):
    """Audit trail entry."""
    entry_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    evidence_id: str
    action: str
    user_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    details: Dict[str, Any] = Field(default_factory=dict)
    signature: Optional[str] = None


class LegalHold(BaseModel):
    """Legal hold record."""
    hold_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    case_id: str
    evidence_ids: List[str] = Field(default_factory=list)
    reason: str
    imposed_by: str
    imposed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None
    released_at: Optional[datetime] = None
    status: str = "ACTIVE"  # ACTIVE, RELEASED, EXPIRED