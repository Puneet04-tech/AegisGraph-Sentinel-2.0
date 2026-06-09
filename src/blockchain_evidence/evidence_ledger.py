"""
Evidence Ledger Module.

Immutable evidence recording with blockchain verification.
"""

import hashlib
import random
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
import logging

from .models import (
    EvidenceRecord,
    EvidenceType,
    BlockchainBlock,
)
from .store import BlockchainEvidenceStore, get_blockchain_store

logger = logging.getLogger(__name__)


class EvidenceLedger:
    """Evidence Ledger for immutable evidence recording.
    
    Provides:
        - Evidence collection
        - Hash computation
        - Blockchain integration
        - Integrity verification
    """
    
    def __init__(self, store: Optional[BlockchainEvidenceStore] = None):
        """Initialize the evidence ledger."""
        self._store = store or get_blockchain_store()
        self._module_id = "evidence_ledger"
    
    def collect_evidence(
        self,
        case_id: str,
        evidence_type: EvidenceType,
        description: str,
        data: Any,
        collector_id: str,
        metadata: Dict[str, Any] = None,
    ) -> EvidenceRecord:
        """Collect and record evidence."""
        logger.info(f"Collecting evidence for case {case_id}")
        
        # Compute hash of evidence
        evidence_hash = self._compute_hash(data)
        
        # Get previous hash
        previous_hash = self._get_previous_block_hash()
        
        # Create evidence record
        evidence = EvidenceRecord(
            case_id=case_id,
            evidence_type=evidence_type,
            description=description,
            hash=evidence_hash,
            previous_hash=previous_hash,
            collector_id=collector_id,
            metadata=metadata or {},
        )
        
        # Add to blockchain
        self._add_to_blockchain(evidence)
        
        self._store.store_evidence(evidence)
        
        # Log audit
        self._log_audit(evidence.evidence_id, "COLLECTED", collector_id, {"hash": evidence_hash})
        
        return evidence
    
    def _compute_hash(self, data: Any) -> str:
        """Compute SHA-256 hash of data."""
        data_str = str(data).encode() if not isinstance(data, bytes) else data
        return hashlib.sha256(data_str).hexdigest()
    
    def _get_previous_block_hash(self) -> str:
        """Get hash of previous block."""
        latest_block = self._store.get_latest_block()
        if latest_block:
            return latest_block.hash or latest_block.merkle_root
        return "0" * 64  # Genesis block
    
    def _add_to_blockchain(self, evidence: EvidenceRecord) -> None:
        """Add evidence to blockchain."""
        latest_block = self._store.get_latest_block()
        
        if latest_block and len(latest_block.evidence_hashes) < 10:
            # Add to existing block
            latest_block.evidence_hashes.append(evidence.hash)
        else:
            # Create new block
            new_block_number = (latest_block.block_number + 1) if latest_block else 0
            block = BlockchainBlock(
                block_number=new_block_number,
                evidence_hashes=[evidence.hash],
                previous_hash=self._get_previous_block_hash(),
                merkle_root=self._compute_merkle_root([evidence.hash]),
            )
            block.hash = self._mine_block(block)
            self._store.store_block(block)
            evidence.block_number = new_block_number
        
        # Set transaction hash
        evidence.transaction_hash = self._compute_hash(f"{evidence.hash}{datetime.now(timezone.utc).isoformat()}")
    
    def _compute_merkle_root(self, hashes: List[str]) -> str:
        """Compute merkle root of hashes."""
        if not hashes:
            return "0" * 64
        
        if len(hashes) == 1:
            return hashes[0]
        
        new_hashes = []
        for i in range(0, len(hashes), 2):
            left = hashes[i]
            right = hashes[i + 1] if i + 1 < len(hashes) else left
            new_hashes.append(self._compute_hash(left + right))
        
        return self._compute_merkle_root(new_hashes)
    
    def _mine_block(self, block: BlockchainBlock, difficulty: int = 4) -> str:
        """Simple proof-of-work mining."""
        prefix = "0" * difficulty
        
        for nonce in range(1000000):
            block_string = f"{block.block_number}{block.timestamp.isoformat()}{block.previous_hash}{block.merkle_root}{nonce}"
            hash_result = self._compute_hash(block_string)
            
            if hash_result.startswith(prefix):
                block.nonce = nonce
                return hash_result
        
        return self._compute_hash(f"{block.merkle_root}{random.randint(0, 999999)}")
    
    def _log_audit(self, evidence_id: str, action: str, user_id: str, details: Dict[str, Any]) -> None:
        """Log audit entry."""
        from .models import AuditTrail
        
        entry = AuditTrail(
            evidence_id=evidence_id,
            action=action,
            user_id=user_id,
            details=details,
        )
        self._store.store_audit_entry(entry)
    
    def get_evidence(self, evidence_id: str) -> Optional[EvidenceRecord]:
        """Get evidence by ID."""
        return self._store.get_evidence(evidence_id)
    
    def get_case_evidence(self, case_id: str) -> List[EvidenceRecord]:
        """Get all evidence for a case."""
        return self._store.get_case_evidence(case_id)
    
    def verify_evidence_integrity(self, evidence_id: str) -> Dict[str, Any]:
        """Verify evidence integrity."""
        evidence = self._store.get_evidence(evidence_id)
        if not evidence:
            return {"error": "Evidence not found"}
        
        # Check blockchain chain
        chain_valid = self._verify_chain(evidence)
        
        return {
            "evidence_id": evidence_id,
            "hash": evidence.hash,
            "block_number": evidence.block_number,
            "chain_integrity": chain_valid,
            "verified": chain_valid,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    
    def _verify_chain(self, evidence: EvidenceRecord) -> bool:
        """Verify blockchain chain for evidence."""
        if evidence.block_number is None:
            return False
        
        # Check all blocks up to evidence block
        for block_num in range(evidence.block_number + 1):
            block = self._store.get_block(block_num)
            if not block:
                return False
            
            # Verify block hash
            block_string = f"{block.block_number}{block.timestamp.isoformat()}{block.previous_hash}{block.merkle_root}{block.nonce}"
            computed_hash = self._compute_hash(block_string)
            
            if block.hash != computed_hash:
                return False
        
        return True


# Global singleton
_evidence_ledger: Optional[EvidenceLedger] = None


def get_evidence_ledger(store: Optional[BlockchainEvidenceStore] = None) -> EvidenceLedger:
    """Get or create the singleton EvidenceLedger instance."""
    global _evidence_ledger
    
    if _evidence_ledger is None:
        _evidence_ledger = EvidenceLedger(store=store)
    return _evidence_ledger