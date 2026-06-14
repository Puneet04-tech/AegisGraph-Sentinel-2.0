"""
Chain-of-Custody Tracker Module.

Immutable custody tracking with full audit trail.
"""

import hashlib
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
import logging

from .models import (
    ChainOfCustody,
    CustodyAction,
    LegalHold,
)
from .store import BlockchainEvidenceStore, get_blockchain_store

logger = logging.getLogger(__name__)


class CustodyTracker:
    """Custody Tracker for chain-of-custody management.
    
    Provides:
        - Custody tracking
        - Transfer management
        - Access logging
        - Legal hold management
    """
    
    def __init__(self, store: Optional[BlockchainEvidenceStore] = None):
        """Initialize the custody tracker."""
        self._store = store or get_blockchain_store()
        self._module_id = "custody_tracker"
    
    def transfer_custody(
        self,
        evidence_id: str,
        from_custodian_id: str,
        to_custodian_id: str,
        to_custodian_name: str,
        location: str,
        purpose: str,
    ) -> ChainOfCustody:
        """Transfer custody of evidence."""
        logger.info(f"Transferring custody of {evidence_id}")
        
        # Get previous custody record
        previous_custody = self._get_latest_custody(evidence_id)
        previous_hash = previous_custody.hash if previous_custody else "0" * 64
        
        # Create custody record
        custody = ChainOfCustody(
            evidence_id=evidence_id,
            action=CustodyAction.TRANSFERRED,
            custodian_id=to_custodian_id,
            custodian_name=to_custodian_name,
            location=location,
            purpose=purpose,
            previous_custody_hash=previous_hash,
        )
        
        # Compute hash
        custody.hash = self._compute_custody_hash(custody)
        
        self._store.store_custody(custody)
        
        # Log audit
        self._log_audit(evidence_id, "CUSTODY_TRANSFERRED", to_custodian_id, {
            "from": from_custodian_id,
            "to": to_custodian_id,
            "custody_id": custody.custody_id,
        })
        
        return custody
    
    def record_access(
        self,
        evidence_id: str,
        user_id: str,
        user_name: str,
        purpose: str,
    ) -> ChainOfCustody:
        """Record access to evidence."""
        logger.info(f"Recording access to {evidence_id}")
        
        previous_custody = self._get_latest_custody(evidence_id)
        previous_hash = previous_custody.hash if previous_custody else "0" * 64
        
        custody = ChainOfCustody(
            evidence_id=evidence_id,
            action=CustodyAction.ACCESSED,
            custodian_id=user_id,
            custodian_name=user_name,
            location="System",
            purpose=purpose,
            previous_custody_hash=previous_hash,
        )
        
        custody.hash = self._compute_custody_hash(custody)
        
        self._store.store_custody(custody)
        
        return custody
    
    def record_modification(
        self,
        evidence_id: str,
        user_id: str,
        user_name: str,
        description: str,
    ) -> ChainOfCustody:
        """Record modification of evidence."""
        previous_custody = self._get_latest_custody(evidence_id)
        previous_hash = previous_custody.hash if previous_custody else "0" * 64
        
        custody = ChainOfCustody(
            evidence_id=evidence_id,
            action=CustodyAction.MODIFIED,
            custodian_id=user_id,
            custodian_name=user_name,
            location="System",
            purpose=description,
            previous_custody_hash=previous_hash,
            metadata={"original_hash": previous_hash},
        )
        
        custody.hash = self._compute_custody_hash(custody)
        
        self._store.store_custody(custody)
        
        return custody
    
    def _compute_custody_hash(self, custody: ChainOfCustody) -> str:
        """Compute hash of custody record."""
        data = f"{custody.evidence_id}{custody.action.value}{custody.custodian_id}{custody.timestamp.isoformat()}{custody.previous_custody_hash or ''}"
        return hashlib.sha256(data.encode()).hexdigest()
    
    def _get_latest_custody(self, evidence_id: str) -> Optional[ChainOfCustody]:
        """Get latest custody record for evidence."""
        chain = self._store.get_evidence_custody_chain(evidence_id)
        return chain[-1] if chain else None
    
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
    
    def get_custody_chain(self, evidence_id: str) -> List[ChainOfCustody]:
        """Get complete custody chain."""
        return self._store.get_evidence_custody_chain(evidence_id)
    
    def get_current_custodian(self, evidence_id: str) -> Optional[ChainOfCustody]:
        """Get current custodian of evidence."""
        return self._get_latest_custody(evidence_id)
    
    def get_custodian_history(self, custodian_id: str) -> List[ChainOfCustody]:
        """Get custody history for a custodian."""
        all_custodies = []
        for custody in self._store._custody.values():
            if custody.custodian_id == custodian_id:
                all_custodies.append(custody)
        return sorted(all_custodies, key=lambda c: c.timestamp, reverse=True)
    
    # Legal Hold Methods
    def place_legal_hold(
        self,
        case_id: str,
        evidence_ids: List[str],
        reason: str,
        imposed_by: str,
        expires_at: datetime = None,
    ) -> LegalHold:
        """Place legal hold on evidence."""
        logger.info(f"Placing legal hold on {len(evidence_ids)} evidence items")
        
        hold = LegalHold(
            case_id=case_id,
            evidence_ids=evidence_ids,
            reason=reason,
            imposed_by=imposed_by,
            expires_at=expires_at,
        )
        
        self._store.store_legal_hold(hold)
        
        # Log audit for each evidence
        for evidence_id in evidence_ids:
            self._log_audit(evidence_id, "LEGAL_HOLD_PLACED", imposed_by, {
                "hold_id": hold.hold_id,
                "reason": reason,
            })
        
        return hold
    
    def release_legal_hold(self, hold_id: str, released_by: str) -> LegalHold:
        """Release legal hold."""
        hold = self._store.get_legal_hold(hold_id)
        if not hold:
            raise ValueError(f"Legal hold {hold_id} not found")
        
        hold.status = "RELEASED"
        hold.released_at = datetime.now(timezone.utc)
        
        self._store.store_legal_hold(hold)
        
        # Log audit
        for evidence_id in hold.evidence_ids:
            self._log_audit(evidence_id, "LEGAL_HOLD_RELEASED", released_by, {
                "hold_id": hold.hold_id,
            })
        
        return hold
    
    def get_active_holds(self) -> List[LegalHold]:
        """Get all active legal holds."""
        return self._store.get_active_holds()
    
    def is_evidence_on_hold(self, evidence_id: str) -> bool:
        """Check if evidence is under legal hold."""
        holds = self._store.get_evidence_holds(evidence_id)
        return any(h.status == "ACTIVE" for h in holds)


# Global singleton
_custody_tracker: Optional[CustodyTracker] = None


def get_custody_tracker(store: Optional[BlockchainEvidenceStore] = None) -> CustodyTracker:
    """Get or create the singleton CustodyTracker instance."""
    global _custody_tracker
    
    if _custody_tracker is None:
        _custody_tracker = CustodyTracker(store=store)
    return _custody_tracker