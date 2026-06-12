"""
Fraud Ring Discovery Engine
Discovers organized fraud rings and criminal networks.
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set
from uuid import uuid4

from .models import FraudRing, InvestigationCase, InvestigationStatus


class FraudRingDiscovery:
    """Engine for discovering fraud rings."""
    
    def __init__(self):
        self.rings: Dict[str, FraudRing] = {}
        self.entity_connections: Dict[str, Set[str]] = {}
    
    def discover_ring(
        self,
        entities: List[Dict[str, Any]],
        connections: List[Dict[str, Any]],
        threshold: float = 0.7,
    ) -> FraudRing:
        """Discover a fraud ring from entities and connections."""
        ring_id = str(uuid4())
        
        for entity in entities:
            entity_id = entity.get("id", str(uuid4()))
            if entity_id not in self.entity_connections:
                self.entity_connections[entity_id] = set()
        
        for conn in connections:
            source = conn.get("source")
            target = conn.get("target")
            if source and target:
                self.entity_connections[source].add(target)
                self.entity_connections[target].add(source)
        
        member_ids = [e.get("id") for e in entities if e.get("id")]
        
        risk_score = self._calculate_ring_risk(member_ids)
        
        ring_type = self._classify_ring_type(entities)
        
        ring = FraudRing(
            ring_id=ring_id,
            members=member_ids,
            connections=connections,
            risk_score=risk_score,
            ring_type=ring_type,
        )
        
        self.rings[ring_id] = ring
        return ring
    
    def _calculate_ring_risk(self, member_ids: List[str]) -> float:
        """Calculate risk score for the ring."""
        if not member_ids:
            return 0.0
        
        total_connections = 0
        for member_id in member_ids:
            total_connections += len(self.entity_connections.get(member_id, set()))
        
        avg_connections = total_connections / len(member_ids)
        
        risk = min(1.0, avg_connections / 5)
        
        return risk
    
    def _classify_ring_type(self, entities: List[Dict[str, Any]]) -> str:
        """Classify the type of fraud ring."""
        entity_types = [e.get("type", "UNKNOWN") for e in entities]
        
        if "MULE_ACCOUNT" in entity_types:
            return "MULE_NETWORK"
        elif "SHELL_COMPANY" in entity_types:
            return "SHELL_COMPANY_RING"
        elif "CARD" in str(entity_types):
            return "CARD_FRAUD_RING"
        else:
            return "GENERAL_FRAUD_RING"
    
    def get_ring(self, ring_id: str) -> Optional[FraudRing]:
        """Get a ring by ID."""
        return self.rings.get(ring_id)
    
    def get_all_rings(self) -> List[FraudRing]:
        """Get all discovered rings."""
        return list(self.rings.values())
    
    def get_high_risk_rings(self, threshold: float = 0.7) -> List[FraudRing]:
        """Get high-risk fraud rings."""
        return [r for r in self.rings.values() if r.risk_score >= threshold]
    
    def analyze_ring_connections(self, ring_id: str) -> Dict[str, Any]:
        """Analyze connections within a ring."""
        ring = self.rings.get(ring_id)
        if not ring:
            return {"error": "Ring not found"}
        
        member_set = set(ring.members)
        
        internal_connections = []
        external_connections = []
        
        for conn in ring.connections:
            source = conn.get("source")
            target = conn.get("target")
            
            if source in member_set and target in member_set:
                internal_connections.append(conn)
            else:
                external_connections.append(conn)
        
        return {
            "ring_id": ring_id,
            "member_count": len(ring.members),
            "internal_connections": len(internal_connections),
            "external_connections": len(external_connections),
            "connectivity_score": len(internal_connections) / max(1, len(ring.members)),
            "risk_assessment": {
                "score": ring.risk_score,
                "type": ring.ring_type,
                "severity": "HIGH" if ring.risk_score > 0.7 else "MEDIUM",
            },
        }


class InvestigationManager:
    """Manages fraud investigations."""
    
    def __init__(self):
        self.cases: Dict[str, InvestigationCase] = {}
    
    def create_case(
        self,
        title: str,
        description: str,
        priority: str = "MEDIUM",
    ) -> InvestigationCase:
        """Create a new investigation case."""
        case_id = str(uuid4())
        case = InvestigationCase(
            case_id=case_id,
            title=title,
            description=description,
            priority=priority,
        )
        self.cases[case_id] = case
        return case
    
    def get_case(self, case_id: str) -> Optional[InvestigationCase]:
        """Get a case by ID."""
        return self.cases.get(case_id)
    
    def update_case(
        self,
        case_id: str,
        status: Optional[InvestigationStatus] = None,
        entities: Optional[List[str]] = None,
        evidence: Optional[List[str]] = None,
    ) -> bool:
        """Update a case."""
        case = self.cases.get(case_id)
        if not case:
            return False
        
        if status:
            case.status = status
        if entities:
            case.entities.extend(entities)
        if evidence:
            case.evidence.extend(evidence)
        
        case.updated_at = datetime.now(timezone.utc)
        return True
    
    def add_timeline_event(
        self,
        case_id: str,
        event: Dict[str, Any],
    ) -> bool:
        """Add a timeline event to a case."""
        case = self.cases.get(case_id)
        if not case:
            return False
        
        event["timestamp"] = datetime.now(timezone.utc).isoformat()
        case.timeline.append(event)
        case.updated_at = datetime.now(timezone.utc)
        return True
    
    def get_active_cases(self) -> List[InvestigationCase]:
        """Get all active cases."""
        return [c for c in self.cases.values() if c.status == InvestigationStatus.ACTIVE]


def get_fraud_ring_discovery() -> FraudRingDiscovery:
    """Get the global fraud ring discovery instance."""
    global _fraud_ring_discovery
    if _fraud_ring_discovery is None:
        _fraud_ring_discovery = FraudRingDiscovery()
    return _fraud_ring_discovery


def get_investigation_manager() -> InvestigationManager:
    """Get the global investigation manager instance."""
    global _investigation_manager
    if _investigation_manager is None:
        _investigation_manager = InvestigationManager()
    return _investigation_manager


_fraud_ring_discovery: Optional[FraudRingDiscovery] = None
_investigation_manager: Optional[InvestigationManager] = None