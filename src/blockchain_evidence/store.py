"""
Blockchain Evidence Storage Engine.

Thread-safe storage for evidence, custody records, and blockchain data.
"""

from threading import Lock
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
import logging

from .models import (
    EvidenceRecord,
    ChainOfCustody,
    BlockchainBlock,
    VerificationResult,
    AuditTrail,
    LegalHold,
)

logger = logging.getLogger(__name__)


class BlockchainEvidenceStore:
    """Thread-safe storage for blockchain evidence.
    
    Provides:
        - O(1) lookup by ID
        - Thread-safe operations
        - Full audit trail
        - Blockchain integrity
    """
    
    def __init__(self):
        """Initialize the blockchain evidence store."""
        self._lock = Lock()
        
        # Evidence records
        self._evidence: Dict[str, EvidenceRecord] = {}
        
        # Chain of custody records
        self._custody: Dict[str, ChainOfCustody] = {}
        
        # Blockchain blocks
        self._blocks: Dict[int, BlockchainBlock] = {}
        self._current_block_number = 0
        
        # Verification results
        self._verifications: Dict[str, VerificationResult] = {}
        
        # Audit trails
        self._audit_trail: Dict[str, List[AuditTrail]] = {}
        
        # Legal holds
        self._legal_holds: Dict[str, LegalHold] = {}
        
        logger.info("Blockchain evidence store initialized")
    
    # Evidence Methods
    def store_evidence(self, evidence: EvidenceRecord) -> EvidenceRecord:
        """Store evidence record."""
        with self._lock:
            self._evidence[evidence.evidence_id] = evidence
        return evidence
    
    def get_evidence(self, evidence_id: str) -> Optional[EvidenceRecord]:
        """Get evidence by ID."""
        return self._evidence.get(evidence_id)
    
    def get_case_evidence(self, case_id: str) -> List[EvidenceRecord]:
        """Get all evidence for a case."""
        return [e for e in self._evidence.values() if e.case_id == case_id]
    
    # Chain of Custody Methods
    def store_custody(self, custody: ChainOfCustody) -> ChainOfCustody:
        """Store custody record."""
        with self._lock:
            self._custody[custody.custody_id] = custody
        return custody
    
    def get_custody(self, custody_id: str) -> Optional[ChainOfCustody]:
        """Get custody record by ID."""
        return self._custody.get(custody_id)
    
    def get_evidence_custody_chain(self, evidence_id: str) -> List[ChainOfCustody]:
        """Get complete custody chain for evidence."""
        custodies = [c for c in self._custody.values() if c.evidence_id == evidence_id]
        return sorted(custodies, key=lambda c: c.timestamp)
    
    # Blockchain Methods
    def store_block(self, block: BlockchainBlock) -> BlockchainBlock:
        """Store blockchain block."""
        with self._lock:
            self._blocks[block.block_number] = block
            self._current_block_number = max(self._current_block_number, block.block_number)
        return block
    
    def get_block(self, block_number: int) -> Optional[BlockchainBlock]:
        """Get block by number."""
        return self._blocks.get(block_number)
    
    def get_latest_block(self) -> Optional[BlockchainBlock]:
        """Get latest block."""
        if self._current_block_number > 0:
            return self._blocks.get(self._current_block_number)
        return None
    
    def get_blockchain_stats(self) -> Dict[str, Any]:
        """Get blockchain statistics."""
        return {
            "total_blocks": self._current_block_number + 1,
            "total_evidence": len(self._evidence),
            "total_custody_records": len(self._custody),
            "total_verifications": len(self._verifications),
            "latest_block_hash": self.get_latest_block().hash if self.get_latest_block() else None,
        }
    
    # Verification Methods
    def store_verification(self, verification: VerificationResult) -> VerificationResult:
        """Store verification result."""
        with self._lock:
            self._verifications[verification.verification_id] = verification
        return verification
    
    def get_verification(self, verification_id: str) -> Optional[VerificationResult]:
        """Get verification by ID."""
        return self._verifications.get(verification_id)
    
    def get_evidence_verification(self, evidence_id: str) -> Optional[VerificationResult]:
        """Get latest verification for evidence."""
        for v in self._verifications.values():
            if v.evidence_id == evidence_id:
                return v
        return None
    
    # Audit Trail Methods
    def store_audit_entry(self, entry: AuditTrail) -> AuditTrail:
        """Store audit entry."""
        with self._lock:
            if entry.evidence_id not in self._audit_trail:
                self._audit_trail[entry.evidence_id] = []
            self._audit_trail[entry.evidence_id].append(entry)
        return entry
    
    def get_evidence_audit_trail(self, evidence_id: str) -> List[AuditTrail]:
        """Get audit trail for evidence."""
        entries = self._audit_trail.get(evidence_id, [])
        return sorted(entries, key=lambda e: e.timestamp)
    
    # Legal Hold Methods
    def store_legal_hold(self, hold: LegalHold) -> LegalHold:
        """Store legal hold."""
        with self._lock:
            self._legal_holds[hold.hold_id] = hold
        return hold
    
    def get_legal_hold(self, hold_id: str) -> Optional[LegalHold]:
        """Get legal hold by ID."""
        return self._legal_holds.get(hold_id)
    
    def get_active_holds(self) -> List[LegalHold]:
        """Get active legal holds."""
        return [h for h in self._legal_holds.values() if h.status == "ACTIVE"]
    
    def get_evidence_holds(self, evidence_id: str) -> List[LegalHold]:
        """Get legal holds for evidence."""
        return [h for h in self._legal_holds.values() if evidence_id in h.evidence_ids]
    
    # Statistics
    def get_stats(self) -> Dict[str, Any]:
        """Get store statistics."""
        return {
            "evidence_stored": len(self._evidence),
            "custody_records": len(self._custody),
            "blocks": self._current_block_number + 1,
            "verifications": len(self._verifications),
            "legal_holds": len(self._legal_holds),
            "active_holds": len(self.get_active_holds()),
        }


# Global singleton
_blockchain_store: Optional[BlockchainEvidenceStore] = None


def get_blockchain_store() -> BlockchainEvidenceStore:
    """Get or create the singleton store instance."""
    global _blockchain_store
    
    if _blockchain_store is None:
        _blockchain_store = BlockchainEvidenceStore()
    return _blockchain_store