"""
Federation Engine for cross-organization intelligence sharing.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional
import uuid

from .models import (
    FederatedEntity,
    FederationPartner,
    FederationStatus,
    IntelligenceSource,
    IntelligenceShare,
    SharingPolicy,
    ThreatLevel,
    EntityType,
    AuditRecord,
)
from .store import GlobalIntelligenceStore, get_global_intelligence_store


@dataclass
class FederationConfig:
    """Configuration for federation engine."""
    federation_id: str = "primary"
    sync_interval_seconds: int = 300
    trust_decay_days: int = 30
    max_sharing_depth: int = 3
    enable_anonymization: bool = True
    require_encryption: bool = True
    audit_all_operations: bool = True


@dataclass
class ShareRequest:
    """Request to share intelligence."""
    request_id: str
    partner_id: str
    entity: FederatedEntity
    share_type: str
    is_anonymized: bool
    requesting_user: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class ShareResponse:
    """Response from share request."""
    success: bool
    share_id: Optional[str]
    message: str
    accepted: bool
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class SyncResult:
    """Result from federation sync."""
    partner_id: str
    entities_shared: int
    entities_received: int
    indicators_shared: int
    indicators_received: int
    sync_duration_ms: float
    success: bool
    errors: List[str] = field(default_factory=list)


class FederationEngine:
    """
    Manages cross-organization intelligence sharing.

    Handles:
    - Partner registration and trust management
    - Intelligence sharing with anonymization
    - Federation synchronization
    - Access control and audit logging
    """

    def __init__(
        self,
        store: Optional[GlobalIntelligenceStore] = None,
        config: Optional[FederationConfig] = None,
    ):
        self._store = store or get_global_intelligence_store()
        self._config = config or FederationConfig()

    def register_partner(
        self,
        organization_name: str,
        organization_type: str,
        api_endpoint: Optional[str] = None,
        api_key: Optional[str] = None,
    ) -> FederationPartner:
        """Register a new federation partner."""
        partner_id = str(uuid.uuid4())

        # Hash API key if provided
        api_key_hash = None
        if api_key:
            api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()

        partner = FederationPartner(
            partner_id=partner_id,
            organization_name=organization_name,
            organization_type=organization_type,
            status=FederationStatus.PENDING,
            trust_level=0,
            api_endpoint=api_endpoint,
            api_key_hash=api_key_hash,
            joined_at=datetime.now(timezone.utc),
            last_sync=None,
            sharing_policy=self._default_sharing_policy(),
        )

        self._store.store_partner(partner)
        self._audit_operation("partner_register", partner_id, {"partner_id": partner_id})

        return partner

    def activate_partner(self, partner_id: str, trust_level: int = 50) -> bool:
        """Activate a pending partner."""
        partner = self._store.get_partner(partner_id)
        if not partner:
            return False

        partner.status = FederationStatus.ACTIVE
        partner.trust_level = min(trust_level, 100)
        self._store.store_partner(partner)
        self._audit_operation("partner_activate", partner_id, {"partner_id": partner_id})
        return True

    def suspend_partner(self, partner_id: str, reason: str = "") -> bool:
        """Suspend an active partner."""
        partner = self._store.get_partner(partner_id)
        if not partner:
            return False

        partner.status = FederationStatus.SUSPENDED
        self._store.store_partner(partner)
        self._audit_operation(
            "partner_suspend",
            partner_id,
            {"partner_id": partner_id, "reason": reason},
        )
        return True

    def validate_partner(self, partner_id: str, api_key: Optional[str] = None) -> bool:
        """Validate partner credentials."""
        partner = self._store.get_partner(partner_id)
        if not partner:
            return False

        if partner.status != FederationStatus.ACTIVE:
            return False

        # Check trust decay
        if partner.joined_at < datetime.now(timezone.utc) - timedelta(
            days=self._config.trust_decay_days
        ):
            partner.trust_level = max(0, partner.trust_level - 10)
            self._store.store_partner(partner)

        if partner.trust_level < 10:
            return False

        # Validate API key if required
        if api_key and partner.api_key_hash:
            provided_hash = hashlib.sha256(api_key.encode()).hexdigest()
            if not hmac.compare_digest(provided_hash, partner.api_key_hash):
                return False

        return True

    def share_intelligence(
        self,
        entity: FederatedEntity,
        target_partners: List[str],
        share_type: str = "direct",
        user_id: str = "system",
    ) -> ShareResponse:
        """Share intelligence with specified partners."""
        # Validate source partner
        source_partner = self._store.get_partner(entity.partner_id)
        if not source_partner or source_partner.status != FederationStatus.ACTIVE:
            return ShareResponse(
                success=False,
                share_id=None,
                message="Invalid source partner",
                accepted=False,
            )

        # Validate target partners
        valid_targets = []
        for target_id in target_partners:
            target = self._store.get_partner(target_id)
            if target and target.status == FederationStatus.ACTIVE:
                # Check sharing policy
                if self._can_share_with(source_partner, target, entity):
                    valid_targets.append(target_id)

        if not valid_targets:
            return ShareResponse(
                success=False,
                share_id=None,
                message="No valid target partners",
                accepted=False,
            )

        # Create share record
        share = IntelligenceShare(
            share_id=str(uuid.uuid4()),
            entity=entity,
            shared_by=entity.partner_id,
            shared_with=valid_targets,
            shared_at=datetime.now(timezone.utc),
            share_type=share_type,
            is_anonymized=self._config.enable_anonymization,
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        )

        # Store entity if not already present
        self._store.store_entity(entity)

        # Update partner stats
        for partner_id in valid_targets:
            partner = self._store.get_partner(partner_id)
            if partner:
                partner.received_intelligence += 1
                self._store.store_partner(partner)

        source_partner.shared_entities += 1
        self._store.store_partner(source_partner)

        self._audit_operation(
            "intelligence_share",
            user_id,
            {
                "entity_id": entity.entity_id,
                "targets": valid_targets,
                "share_type": share_type,
            },
        )

        return ShareResponse(
            success=True,
            share_id=share.share_id,
            message=f"Shared with {len(valid_targets)} partners",
            accepted=True,
        )

    def request_intelligence(
        self,
        requesting_partner_id: str,
        query: Dict[str, Any],
        user_id: str = "system",
    ) -> List[FederatedEntity]:
        """Request intelligence from federation."""
        # Validate requesting partner
        if not self.validate_partner(requesting_partner_id):
            return []

        results = []

        # Search local entities
        for entity in self._store._entities.values():
            if self._matches_query(entity, query):
                # Apply anonymization if required
                if self._should_anonymize(requesting_partner_id, entity.partner_id):
                    results.append(entity.to_anonymized())
                else:
                    results.append(entity)

        self._audit_operation(
            "intelligence_request",
            user_id,
            {"partner_id": requesting_partner_id, "results_count": len(results)},
        )

        return results[: query.get("max_results", 100)]

    def sync_with_partner(
        self,
        partner_id: str,
        direction: str = "bidirectional",
    ) -> SyncResult:
        """Synchronize intelligence with a partner."""
        partner = self._store.get_partner(partner_id)
        if not partner or partner.status != FederationStatus.ACTIVE:
            return SyncResult(
                partner_id=partner_id,
                entities_shared=0,
                entities_received=0,
                indicators_shared=0,
                indicators_received=0,
                sync_duration_ms=0,
                success=False,
                errors=["Partner not found or inactive"],
            )

        start_time = time.time()
        entities_shared = 0
        entities_received = 0

        try:
            # In a real implementation, this would make API calls to the partner
            # For now, we simulate the sync operation

            # Get entities to share
            entities_to_share = self._get_shareable_entities(partner)

            # Simulate sharing (in production, send to partner's API)
            for entity in entities_to_share[:100]:  # Limit per sync
                entities_shared += 1

            # Update partner sync timestamp
            partner.last_sync = datetime.now(timezone.utc)
            self._store.store_partner(partner)

            duration_ms = (time.time() - start_time) * 1000

            return SyncResult(
                partner_id=partner_id,
                entities_shared=entities_shared,
                entities_received=entities_received,
                indicators_shared=0,
                indicators_received=0,
                sync_duration_ms=duration_ms,
                success=True,
            )

        except Exception as e:
            return SyncResult(
                partner_id=partner_id,
                entities_shared=entities_shared,
                entities_received=entities_received,
                indicators_shared=0,
                indicators_received=0,
                sync_duration_ms=(time.time() - start_time) * 1000,
                success=False,
                errors=[str(e)],
            )

    def update_sharing_policy(
        self, partner_id: str, policy: SharingPolicy
    ) -> bool:
        """Update sharing policy for a partner."""
        partner = self._store.get_partner(partner_id)
        if not partner:
            return False

        partner.sharing_policy = {
            "entity_types_allowed": [e.value for e in policy.entity_types_allowed],
            "threat_levels_minimum": [t.value for t in policy.threat_levels_minimum],
            "anonymization_required": policy.anonymization_required,
            "retention_days": policy.retention_days,
        }
        self._store.store_partner(partner)
        return True

    def _default_sharing_policy(self) -> Dict[str, Any]:
        """Get default sharing policy."""
        return {
            "entity_types_allowed": [e.value for e in EntityType],
            "threat_levels_minimum": [ThreatLevel.LOW.value],
            "anonymization_required": True,
            "retention_days": 30,
        }

    def _can_share_with(
        self, source: FederationPartner, target: FederationPartner, entity: FederatedEntity
    ) -> bool:
        """Check if entity can be shared with target."""
        # Check trust levels
        if source.trust_level < 20 or target.trust_level < 20:
            return False

        # Check entity threat level
        if entity.threat_level == ThreatLevel.UNKNOWN:
            return False

        return True

    def _should_anonymize(self, target_id: str, source_id: str) -> bool:
        """Determine if sharing should be anonymized."""
        target = self._store.get_partner(target_id)
        if not target:
            return True

        return target.sharing_policy.get("anonymization_required", True)

    def _matches_query(self, entity: FederatedEntity, query: Dict[str, Any]) -> bool:
        """Check if entity matches query."""
        # Check entity type
        if "entity_type" in query:
            if entity.entity_type.value != query["entity_type"]:
                return False

        # Check threat level
        if "threat_levels" in query:
            if entity.threat_level.value not in query["threat_levels"]:
                return False

        # Check attributes
        if "attributes" in query:
            for key, value in query["attributes"].items():
                if entity.attributes.get(key) != value:
                    return False

        return True

    def _get_shareable_entities(self, partner: FederationPartner) -> List[FederatedEntity]:
        """Get entities that can be shared with partner."""
        shareable = []
        allowed_types = set(
            partner.sharing_policy.get("entity_types_allowed", [e.value for e in EntityType])
        )
        min_threat = partner.sharing_policy.get("threat_levels_minimum", [ThreatLevel.LOW.value])

        for entity in self._store._entities.values():
            if entity.entity_type.value not in allowed_types:
                continue
            if entity.threat_level.value not in min_threat:
                continue
            shareable.append(entity)

        return shareable

    def _audit_operation(
        self, operation: str, user_id: str, details: Dict[str, Any]
    ) -> None:
        """Record audit operation."""
        if not self._config.audit_all_operations:
            return

        record = AuditRecord(
            record_id=str(uuid.uuid4()),
            operation=operation,
            user_id=user_id,
            partner_id=details.get("partner_id"),
            entity_ids=details.get("entity_ids", []),
            timestamp=datetime.now(timezone.utc),
            ip_address="internal",
            user_agent="federation-engine",
            success=details.get("success", True),
            error_message=details.get("error"),
            metadata=details,
        )
        self._store.store_audit_record(record)


# Global engine instance
_engine: Optional[FederationEngine] = None


def get_federation_engine() -> FederationEngine:
    """Get the global federation engine instance."""
    global _engine
    if _engine is None:
        _engine = FederationEngine()
    return _engine


def reset_engine() -> None:
    """Reset the engine (for testing)."""
    global _engine
    _engine = None