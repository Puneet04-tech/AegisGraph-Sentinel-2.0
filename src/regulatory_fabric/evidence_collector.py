"""
Evidence Collection Service for Regulatory Fabric.

Automates collection and verification of audit evidence.
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
import threading
import hashlib
import json


@dataclass
class EvidenceCollectionJob:
    """Evidence collection job."""
    job_id: str
    control_id: str
    evidence_type: str
    status: str = "PENDING"
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    collected_at: Optional[datetime] = None
    evidence_id: Optional[str] = None
    error: Optional[str] = None


class EvidenceCollector:
    """Automated evidence collection service.
    
    Collects, stores, and verifies audit evidence from various sources.
    """

    def __init__(self, store: Any):
        """Initialize the evidence collector.
        
        Args:
            store: Compliance store instance
        """
        self.store = store
        self._collection_jobs: Dict[str, EvidenceCollectionJob] = {}
        self._evidence_sources: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._collectors: Dict[str, Callable] = {}

    def register_source(
        self,
        source_id: str,
        source_config: Dict[str, Any],
        collector_func: Optional[Callable] = None,
    ) -> bool:
        """Register an evidence source.
        
        Args:
            source_id: Unique source identifier
            source_config: Source configuration
            collector_func: Optional function to collect evidence
            
        Returns:
            True if registered successfully
        """
        with self._lock:
            self._evidence_sources[source_id] = {
                **source_config,
                "registered_at": datetime.now(timezone.utc),
                "collection_count": 0,
            }
            if collector_func:
                self._collectors[source_id] = collector_func
            return True

    def register_collector(self, evidence_type: str, collector_func: Callable) -> None:
        """Register a collector function for an evidence type.
        
        Args:
            evidence_type: Type of evidence
            collector_func: Function to collect evidence data
        """
        with self._lock:
            self._collectors[evidence_type] = collector_func

    def collect_evidence(
        self,
        control_id: str,
        evidence_type: str,
        source_id: Optional[str] = None,
        description: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> EvidenceCollectionJob:
        """Create and execute an evidence collection job.
        
        Args:
            control_id: Control to collect evidence for
            evidence_type: Type of evidence
            source_id: Optional specific source to collect from
            description: Evidence description
            metadata: Additional metadata
            
        Returns:
            Collection job details
        """
        job = EvidenceCollectionJob(
            job_id=hashlib.md5(f"{control_id}{evidence_type}{datetime.now(timezone.utc)}".encode()).hexdigest()[:16],
            control_id=control_id,
            evidence_type=evidence_type,
        )
        
        with self._lock:
            self._collection_jobs[job.job_id] = job
        
        # Execute collection
        try:
            evidence_data = self._execute_collection(evidence_type, source_id)
            
            evidence = {
                "evidence_id": str(hashlib.md5(f"{job.job_id}{datetime.now(timezone.utc)}".encode()).hexdigest()[:16]),
                "control_id": control_id,
                "evidence_type": evidence_type,
                "description": description,
                "collection_date": datetime.now(timezone.utc),
                "status": "COLLECTED",
                "source_system": source_id or "AUTO",
                "captured_data": evidence_data,
                "hash": hashlib.sha256(json.dumps(evidence_data, sort_keys=True).encode()).hexdigest(),
                "metadata": metadata or {},
            }
            
            evidence_id = self.store.add_evidence(evidence)
            
            job.status = "COMPLETED"
            job.collected_at = datetime.now(timezone.utc)
            job.evidence_id = evidence_id
            
        except Exception as e:
            job.status = "FAILED"
            job.error = str(e)
        
        return job

    def _execute_collection(
        self,
        evidence_type: str,
        source_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Execute evidence collection.
        
        Args:
            evidence_type: Type of evidence
            source_id: Optional source to collect from
            
        Returns:
            Collected evidence data
        """
        # Try type-specific collector
        if evidence_type in self._collectors:
            return self._collectors[evidence_type]()
        
        # Try source-specific collector
        if source_id and source_id in self._collectors:
            return self._collectors[source_id]()
        
        # Return placeholder data (in production, integrate with actual systems)
        return {
            "collection_timestamp": datetime.now(timezone.utc).isoformat(),
            "status": "collected",
            "source": source_id or "unknown",
            "evidence_type": evidence_type,
        }

    def schedule_collection(
        self,
        control_id: str,
        evidence_type: str,
        schedule: str = "daily",
    ) -> str:
        """Schedule automatic evidence collection.
        
        Args:
            control_id: Control to collect for
            evidence_type: Type of evidence
            schedule: Collection schedule (hourly, daily, weekly)
            
        Returns:
            Schedule ID
        """
        schedule_id = hashlib.md5(f"{control_id}{evidence_type}{schedule}".encode()).hexdigest()[:16]
        
        # In production, this would integrate with a scheduler
        return schedule_id

    def verify_evidence(self, evidence_id: str) -> Dict[str, Any]:
        """Verify evidence integrity and validity.
        
        Args:
            evidence_id: Evidence to verify
            
        Returns:
            Verification result
        """
        evidence = self.store.get_evidence(evidence_id)
        if not evidence:
            return {"error": "Evidence not found"}
        
        # Verify hash
        stored_hash = evidence.get("hash", "")
        current_data = evidence.get("captured_data", {})
        current_hash = hashlib.sha256(json.dumps(current_data, sort_keys=True).encode()).hexdigest()
        hash_valid = stored_hash == current_hash
        
        # Check expiry
        expiry_date = evidence.get("expiry_date")
        is_expired = False
        if expiry_date:
            if isinstance(expiry_date, str):
                expiry_date = datetime.fromisoformat(expiry_date)
            is_expired = datetime.now(timezone.utc) > expiry_date
        
        # Determine status
        if is_expired:
            status = "EXPIRED"
        elif hash_valid:
            status = "VERIFIED"
        else:
            status = "INVALID"
        
        # Update evidence status
        evidence["status"] = status
        evidence["verified_at"] = datetime.now(timezone.utc)
        
        return {
            "evidence_id": evidence_id,
            "status": status,
            "hash_valid": hash_valid,
            "is_expired": is_expired,
            "verified_at": datetime.now(timezone.utc).isoformat(),
        }

    def get_evidence_for_control(
        self,
        control_id: str,
        status: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Get all evidence for a control.
        
        Args:
            control_id: Control ID
            status: Optional status filter
            limit: Maximum results
            
        Returns:
            List of evidence
        """
        evidence_list = self.store.list_evidence(control_id=control_id)
        
        if status:
            evidence_list = [e for e in evidence_list if e.get("status") == status]
        
        return evidence_list[:limit]

    def get_collection_stats(self) -> Dict[str, Any]:
        """Get evidence collection statistics."""
        all_evidence = list(self.store.evidence.values())
        
        status_counts = {}
        type_counts = {}
        
        for e in all_evidence:
            status = e.get("status", "UNKNOWN")
            evid_type = e.get("evidence_type", "UNKNOWN")
            status_counts[status] = status_counts.get(status, 0) + 1
            type_counts[evid_type] = type_counts.get(evid_type, 0) + 1
        
        return {
            "total_evidence": len(all_evidence),
            "by_status": status_counts,
            "by_type": type_counts,
            "sources_registered": len(self._evidence_sources),
            "collectors_registered": len(self._collectors),
            "pending_jobs": len([j for j in self._collection_jobs.values() if j.status == "PENDING"]),
            "completed_jobs": len([j for j in self._collection_jobs.values() if j.status == "COMPLETED"]),
        }

    def cleanup_expired_evidence(self, dry_run: bool = True) -> Dict[str, Any]:
        """Clean up expired evidence.
        
        Args:
            dry_run: If True, only return what would be deleted
            
        Returns:
            Cleanup report
        """
        now = datetime.now(timezone.utc)
        expired_ids = []
        
        for evid in self.store.evidence.values():
            expiry = evid.get("expiry_date")
            if expiry:
                if isinstance(expiry, str):
                    expiry = datetime.fromisoformat(expiry)
                if now > expiry:
                    expired_ids.append(evid.get("evidence_id"))
        
        if not dry_run:
            for evid_id in expired_ids:
                del self.store.evidence[evid_id]
        
        return {
            "expired_count": len(expired_ids),
            "cleaned": not dry_run,
            "expired_ids": expired_ids[:10],  # First 10 for preview
        }


def get_evidence_collector() -> EvidenceCollector:
    """Get the global evidence collector instance."""
    from .store import get_compliance_store
    store = get_compliance_store()
    return EvidenceCollector(store)