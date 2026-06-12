"""
Evidence Collection Engine for multi-source evidence gathering.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from .models import EvidenceArtifact, EvidenceType


class EvidenceCollector:
    """
    Collects evidence from multiple sources for investigations.

    Handles:
    - Transaction evidence
    - Account evidence
    - Device evidence
    - IP evidence
    - Behavior evidence
    - Threat intelligence
    - Alert data
    """

    def __init__(self):
        self._collectors: Dict[EvidenceType, EvidenceCollector] = {}
        self._initialize_collectors()

    def _initialize_collectors(self) -> None:
        """Initialize evidence collectors for each type."""
        self._collectors = {
            EvidenceType.TRANSACTION: self._collect_transaction_evidence,
            EvidenceType.ACCOUNT: self._collect_account_evidence,
            EvidenceType.DEVICE: self._collect_device_evidence,
            EvidenceType.IP_ADDRESS: self._collect_ip_evidence,
            EvidenceType.BEHAVIOR: self._collect_behavior_evidence,
            EvidenceType.LOCATION: self._collect_location_evidence,
            EvidenceType.ALERT: self._collect_alert_evidence,
            EvidenceType.THREAT_INTEL: self._collect_threat_intel_evidence,
        }

    async def collect_evidence(
        self,
        entity_ids: List[str],
        alert_ids: List[str],
        evidence_types: Optional[List[EvidenceType]] = None,
    ) -> List[EvidenceArtifact]:
        """Collect evidence from all relevant sources."""
        evidence = []
        types_to_collect = evidence_types or list(EvidenceType)

        # Create tasks for parallel collection
        tasks = []
        for evidence_type in types_to_collect:
            if evidence_type in self._collectors:
                task = self._collectors[evidence_type](entity_ids, alert_ids)
                tasks.append(task)

        # Execute in parallel
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Collect results
        for result in results:
            if isinstance(result, list):
                evidence.extend(result)

        # Sort by relevance
        evidence.sort(key=lambda e: e.relevance_score, reverse=True)

        return evidence

    async def _collect_transaction_evidence(
        self,
        entity_ids: List[str],
        alert_ids: List[str],
    ) -> List[EvidenceArtifact]:
        """Collect transaction evidence."""
        evidence = []

        for entity_id in entity_ids[:5]:  # Limit to 5 entities
            artifact = EvidenceArtifact(
                evidence_id=str(uuid.uuid4()),
                evidence_type=EvidenceType.TRANSACTION,
                source_system="transaction_db",
                source_id=entity_id,
                content={
                    "entity_id": entity_id,
                    "transaction_count": 0,
                    "total_amount": 0.0,
                    "avg_amount": 0.0,
                    "max_amount": 0.0,
                    "velocity": 0,
                    "high_risk_count": 0,
                    "recent_transactions": [],
                },
                relevance_score=0.9,
            )
            evidence.append(artifact)

        return evidence

    async def _collect_account_evidence(
        self,
        entity_ids: List[str],
        alert_ids: List[str],
    ) -> List[EvidenceArtifact]:
        """Collect account evidence."""
        evidence = []

        for entity_id in entity_ids[:5]:
            artifact = EvidenceArtifact(
                evidence_id=str(uuid.uuid4()),
                evidence_type=EvidenceType.ACCOUNT,
                source_system="account_db",
                source_id=entity_id,
                content={
                    "account_id": entity_id,
                    "age_days": 0,
                    "kyc_status": "verified",
                    "risk_score": 0.5,
                    "activity_level": "normal",
                    "verification_level": "basic",
                    "linked_accounts": [],
                },
                relevance_score=0.85,
            )
            evidence.append(artifact)

        return evidence

    async def _collect_device_evidence(
        self,
        entity_ids: List[str],
        alert_ids: List[str],
    ) -> List[EvidenceArtifact]:
        """Collect device evidence."""
        evidence = []

        for entity_id in entity_ids[:5]:
            artifact = EvidenceArtifact(
                evidence_id=str(uuid.uuid4()),
                evidence_type=EvidenceType.DEVICE,
                source_system="device_db",
                source_id=entity_id,
                content={
                    "device_id": entity_id,
                    "is_new_device": True,
                    "device_type": "mobile",
                    "os_version": "unknown",
                    "risk_score": 0.3,
                    "fingerprint": "unknown",
                },
                relevance_score=0.7,
            )
            evidence.append(artifact)

        return evidence

    async def _collect_ip_evidence(
        self,
        entity_ids: List[str],
        alert_ids: List[str],
    ) -> List[EvidenceArtifact]:
        """Collect IP address evidence."""
        evidence = []

        for entity_id in entity_ids[:5]:
            artifact = EvidenceArtifact(
                evidence_id=str(uuid.uuid4()),
                evidence_type=EvidenceType.IP_ADDRESS,
                source_system="ip_db",
                source_id=entity_id,
                content={
                    "ip_address": entity_id,
                    "country": "unknown",
                    "country_risk": "low",
                    "is_vpn": False,
                    "is_proxy": False,
                    "is_tor": False,
                    "isp": "unknown",
                },
                relevance_score=0.65,
            )
            evidence.append(artifact)

        return evidence

    async def _collect_behavior_evidence(
        self,
        entity_ids: List[str],
        alert_ids: List[str],
    ) -> List[EvidenceArtifact]:
        """Collect behavior evidence."""
        evidence = []

        for entity_id in entity_ids[:3]:
            artifact = EvidenceArtifact(
                evidence_id=str(uuid.uuid4()),
                evidence_type=EvidenceType.BEHAVIOR,
                source_system="behavior_engine",
                source_id=entity_id,
                content={
                    "entity_id": entity_id,
                    "login_pattern": "normal",
                    "transaction_pattern": "normal",
                    "session_duration": 0,
                    "click_pattern": "normal",
                    "anomaly_score": 0.2,
                },
                relevance_score=0.6,
            )
            evidence.append(artifact)

        return evidence

    async def _collect_location_evidence(
        self,
        entity_ids: List[str],
        alert_ids: List[str],
    ) -> List[EvidenceArtifact]:
        """Collect location evidence."""
        evidence = []

        for entity_id in entity_ids[:3]:
            artifact = EvidenceArtifact(
                evidence_id=str(uuid.uuid4()),
                evidence_type=EvidenceType.LOCATION,
                source_system="location_service",
                source_id=entity_id,
                content={
                    "entity_id": entity_id,
                    "current_location": "unknown",
                    "location_history": [],
                    "impossible_travel": False,
                    "location_confidence": 0.8,
                },
                relevance_score=0.55,
            )
            evidence.append(artifact)

        return evidence

    async def _collect_alert_evidence(
        self,
        entity_ids: List[str],
        alert_ids: List[str],
    ) -> List[EvidenceArtifact]:
        """Collect alert evidence."""
        evidence = []

        for alert_id in alert_ids[:10]:
            artifact = EvidenceArtifact(
                evidence_id=str(uuid.uuid4()),
                evidence_type=EvidenceType.ALERT,
                source_system="alert_system",
                source_id=alert_id,
                content={
                    "alert_id": alert_id,
                    "alert_type": "fraud",
                    "risk_score": 0.7,
                    "triggered_rules": [],
                    "entity_id": entity_ids[0] if entity_ids else None,
                },
                relevance_score=0.95,
            )
            evidence.append(artifact)

        return evidence

    async def _collect_threat_intel_evidence(
        self,
        entity_ids: List[str],
        alert_ids: List[str],
    ) -> List[EvidenceArtifact]:
        """Collect threat intelligence evidence."""
        evidence = []

        for entity_id in entity_ids[:5]:
            artifact = EvidenceArtifact(
                evidence_id=str(uuid.uuid4()),
                evidence_type=EvidenceType.THREAT_INTEL,
                source_system="threat_intel_feed",
                source_id=entity_id,
                content={
                    "entity_id": entity_id,
                    "threat_indicators": [],
                    "threat_categories": [],
                    "confidence_score": 0.5,
                    "last_seen": datetime.now(timezone.utc).isoformat(),
                },
                relevance_score=0.75,
            )
            evidence.append(artifact)

        return evidence

    def get_collection_stats(self) -> Dict[str, Any]:
        """Get evidence collection statistics."""
        return {
            "collectors_initialized": len(self._collectors),
            "evidence_types_supported": [e.value for e in EvidenceType],
        }


# Global collector instance
_collector: Optional[EvidenceCollector] = None


def get_evidence_collector() -> EvidenceCollector:
    """Get the evidence collector instance."""
    global _collector
    if _collector is None:
        _collector = EvidenceCollector()
    return _collector