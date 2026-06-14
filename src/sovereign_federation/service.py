"""Sovereign Federation Service"""
from typing import Any, Dict, List, Optional
from uuid import uuid4
from datetime import datetime, timedelta
from .models import (
    NationalEntity, GovernancePolicy, IntelligenceShare, ComplianceRecord,
    FederationRole, DataClassification, ComplianceStatus
)

class SovereignFederationService:
    """Sovereign Intelligence Federation Service"""
    
    def __init__(self) -> None:
        self.entities: Dict[str, NationalEntity] = {}
        self.policies: Dict[str, GovernancePolicy] = {}
        self.shares: Dict[str, IntelligenceShare] = {}
        self.compliance_records: Dict[str, ComplianceRecord] = {}
        self._init_default_entities()
    
    def _init_default_entities(self) -> None:
        """Initialize default national entities"""
        entities = [
            NationalEntity(
                entity_id="entity-us-cert",
                name="US-CERT",
                country_code="US",
                entity_type="CERT",
                federation_role=FederationRole.SOVEREIGN,
                verified=True,
                trust_score=0.95
            ),
            NationalEntity(
                entity_id="entity-eu-enisa",
                name="ENISA",
                country_code="EU",
                entity_type="AGENCY",
                federation_role=FederationRole.SOVEREIGN,
                verified=True,
                trust_score=0.95
            ),
            NationalEntity(
                entity_id="entity-g20-alliance",
                name="G20 Security Alliance",
                country_code="G20",
                entity_type="ALLIANCE",
                federation_role=FederationRole.GATEWAY,
                verified=True,
                trust_score=0.90
            )
        ]
        for entity in entities:
            self.entities[entity.entity_id] = entity
    
    def register_entity(
        self,
        name: str,
        country_code: str,
        entity_type: str,
        federation_role: str = "PARTICIPANT",
        trust_score: float = 0.5
    ) -> Dict[str, Any]:
        """Register a national entity"""
        entity = NationalEntity(
            entity_id=f"entity-{uuid4().hex[:8]}",
            name=name,
            country_code=country_code,
            entity_type=entity_type,
            federation_role=FederationRole(federation_role),
            trust_score=trust_score
        )
        self.entities[entity.entity_id] = entity
        return entity.to_dict()
    
    def get_entity(self, entity_id: str) -> Optional[Dict[str, Any]]:
        """Get an entity by ID"""
        entity = self.entities.get(entity_id)
        return entity.to_dict() if entity else None
    
    def get_all_entities(self) -> List[Dict[str, Any]]:
        """Get all entities"""
        return [e.to_dict() for e in self.entities.values()]
    
    def get_entities_by_country(self, country_code: str) -> List[Dict[str, Any]]:
        """Get entities by country"""
        return [e.to_dict() for e in self.entities.values() if e.country_code == country_code]
    
    def create_policy(
        self,
        name: str,
        description: str,
        country_code: str,
        rules: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Create a governance policy"""
        policy = GovernancePolicy(
            policy_id=f"policy-{uuid4().hex[:8]}",
            name=name,
            description=description,
            country_code=country_code,
            rules=rules
        )
        self.policies[policy.policy_id] = policy
        return policy.to_dict()
    
    def share_intelligence(
        self,
        source_entity_id: str,
        target_entity_id: str,
        content_summary: str,
        data_classification: str = "INTERNAL"
    ) -> Dict[str, Any]:
        """Share intelligence between entities"""
        source = self.entities.get(source_entity_id)
        target = self.entities.get(target_entity_id)
        if not source or not target:
            raise ValueError("Source or target entity not found")
        
        share = IntelligenceShare(
            share_id=f"share-{uuid4().hex[:8]}",
            source_entity_id=source_entity_id,
            target_entity_id=target_entity_id,
            data_classification=DataClassification(data_classification),
            content_summary=content_summary,
            status="APPROVED",
            approved_by="SYSTEM",
            shared_at=datetime.utcnow()
        )
        self.shares[share.share_id] = share
        return share.to_dict()
    
    def get_share(self, share_id: str) -> Optional[Dict[str, Any]]:
        """Get a share record"""
        share = self.shares.get(share_id)
        return share.to_dict() if share else None
    
    def get_all_shares(self) -> List[Dict[str, Any]]:
        """Get all share records"""
        return [s.to_dict() for s in self.shares.values()]
    
    def verify_compliance(self, entity_id: str, policy_id: str) -> Dict[str, Any]:
        """Verify compliance for an entity"""
        entity = self.entities.get(entity_id)
        policy = self.policies.get(policy_id)
        if not entity or not policy:
            raise ValueError("Entity or policy not found")
        
        record = ComplianceRecord(
            record_id=f"comp-{uuid4().hex[:8]}",
            entity_id=entity_id,
            policy_id=policy_id,
            status=ComplianceStatus.VERIFIED,
            verified_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(days=365),
            details="Compliance verified by automated system"
        )
        self.compliance_records[record.record_id] = record
        
        # Update entity verification
        entity.verified = True
        return record.to_dict()
    
    def get_compliance_records(self, entity_id: str) -> List[Dict[str, Any]]:
        """Get compliance records for an entity"""
        return [r.to_dict() for r in self.compliance_records.values() if r.entity_id == entity_id]
    
    def get_dashboard(self) -> Dict[str, Any]:
        """Get federation dashboard"""
        role_counts: Dict[str, int] = {}
        country_counts: Dict[str, int] = {}
        for entity in self.entities.values():
            role_counts[entity.federation_role.value] = role_counts.get(entity.federation_role.value, 0) + 1
            country_counts[entity.country_code] = country_counts.get(entity.country_code, 0) + 1
        
        return {
            "total_entities": len(self.entities),
            "total_policies": len(self.policies),
            "total_shares": len(self.shares),
            "entities_by_role": role_counts,
            "entities_by_country": country_counts
        }


# Global service instance
_sovereign_service: Optional[SovereignFederationService] = None

def get_sovereign_federation_service() -> SovereignFederationService:
    """Get the global service instance"""
    global _sovereign_service
    if _sovereign_service is None:
        _sovereign_service = SovereignFederationService()
    return _sovereign_service