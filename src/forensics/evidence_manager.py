"""Forensic Evidence Manager responsible for integrity preservation and auditing."""

from __future__ import annotations

import hashlib
import logging
from typing import Dict, List, Optional, Tuple

from .models import Evidence
from .store import get_forensics_store

logger = logging.getLogger("forensics.evidence_manager")


class EvidenceManager:
    """Manages forensic evidence lifecycle, integrity checks, and validation hashes."""

    def __init__(self) -> None:
        self.store = get_forensics_store()

    def register_evidence(
        self,
        case_id: str,
        evidence_type: str,
        source: str,
        value: str,
    ) -> Evidence:
        """Create, hash, and register forensic evidence for a case."""
        # Calculate SHA-256 integrity hash
        sha256_hash = hashlib.sha256(value.encode("utf-8")).hexdigest()
        
        evidence = Evidence(
            case_id=case_id,
            type=evidence_type,
            source=source,
            value=value,
            hash=sha256_hash,
        )
        
        self.store.add_evidence(evidence)
        
        logger.info(
            f"Forensic evidence registered. ID: {evidence.id}, Case: {case_id}, Type: {evidence_type}, Hash: {sha256_hash}",
            extra={
                "event_type": "forensic_evidence_registered",
                "evidence_id": evidence.id,
                "case_id": case_id,
                "integrity_hash": sha256_hash,
            }
        )
        return evidence

    def verify_evidence(self, evidence_id: str) -> Tuple[bool, Optional[Evidence]]:
        """Verify the integrity of a registered evidence entry.
        
        Returns a tuple: (is_valid, evidence_object)
        """
        evidence = self.store.get_evidence(evidence_id)
        if not evidence:
            logger.warning(
                f"Evidence ID '{evidence_id}' not found during verification.",
                extra={"event_type": "forensic_verification_missing_evidence", "evidence_id": evidence_id}
            )
            return False, None
            
        # Re-compute hash to verify integrity
        current_hash = hashlib.sha256(evidence.value.encode("utf-8")).hexdigest()
        is_valid = current_hash == evidence.hash
        
        if not is_valid:
            logger.error(
                f"TAMPER DETECTED: Evidence ID '{evidence_id}' hash mismatch! Expected: {evidence.hash}, Found: {current_hash}",
                extra={
                    "event_type": "forensic_evidence_tamper_alert",
                    "evidence_id": evidence_id,
                    "expected_hash": evidence.hash,
                    "computed_hash": current_hash,
                }
            )
        else:
            logger.info(
                f"Evidence ID '{evidence_id}' integrity verified successfully.",
                extra={"event_type": "forensic_evidence_verified", "evidence_id": evidence_id}
            )
            
        return is_valid, evidence

    def list_evidence_for_case(self, case_id: str) -> List[Evidence]:
        """Fetch all forensic evidence linked to a case."""
        return self.store.list_evidence_for_case(case_id)

