"""
Blockchain Evidence & Chain-of-Custody Platform.

A production-grade blockchain module for immutable evidence recording,
verification, and custody tracking.

Modules:
    - Evidence Ledger: Immutable evidence recording
    - Custody Tracker: Chain-of-custody management
"""

from .models import (
    EvidenceType,
    CustodyAction,
    VerificationStatus,
    EvidenceRecord,
    ChainOfCustody,
    BlockchainBlock,
    VerificationResult,
    AuditTrail,
    LegalHold,
)
from .store import BlockchainEvidenceStore, get_blockchain_store
from .evidence_ledger import EvidenceLedger, get_evidence_ledger
from .custody_tracker import CustodyTracker, get_custody_tracker

__all__ = [
    # Enums
    "EvidenceType",
    "CustodyAction",
    "VerificationStatus",
    # Models
    "EvidenceRecord",
    "ChainOfCustody",
    "BlockchainBlock",
    "VerificationResult",
    "AuditTrail",
    "LegalHold",
    # Store
    "BlockchainEvidenceStore",
    "get_blockchain_store",
    # Modules
    "EvidenceLedger",
    "get_evidence_ledger",
    "CustodyTracker",
    "get_custody_tracker",
]