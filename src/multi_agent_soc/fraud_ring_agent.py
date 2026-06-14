"""
Fraud Ring Agent.

Analyzes fraud rings, detects network patterns, and tracks organized fraud activity.
"""

import random
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
import logging

from .models import (
    AgentTask,
    AgentType,
    TaskPriority,
    FraudRingAnalysis,
)
from .store import SOCStore, get_soc_store

logger = logging.getLogger(__name__)


class FraudRingAgent:
    """Fraud Ring Agent for organized fraud detection.
    
    Capabilities:
        - Fraud ring detection and analysis
        - Entity linking and relationship mapping
        - Network pattern recognition
        - Ring member identification
        - Connected campaign tracking
    """
    
    def __init__(self, store: Optional[SOCStore] = None):
        """Initialize the fraud ring agent.
        
        Args:
            store: Optional SOC store
        """
        self._store = store or get_soc_store()
        self._agent_id = "fraud_ring_agent"
    
    def detect_ring(
        self,
        seed_entities: List[str],
        ring_type: str = "unknown",
        context: Dict[str, Any] = None,
    ) -> FraudRingAnalysis:
        """Detect and analyze a fraud ring.
        
        Args:
            seed_entities: Initial entities to investigate
            ring_type: Type of fraud ring
            context: Additional context
            
        Returns:
            FraudRingAnalysis
        """
        logger.info(f"Detecting fraud ring from {len(seed_entities)} seed entities")
        
        context = context or {}
        
        # Expand ring membership
        member_entities = self._expand_ring_membership(seed_entities, context)
        
        # Identify relationships
        relationships = self._identify_relationships(member_entities)
        
        # Calculate ring score
        ring_score = self._calculate_ring_score(member_entities, relationships)
        
        # Estimate financial impact
        financial_impact = self._estimate_financial_impact(member_entities)
        
        # Identify geographic footprint
        geographic_footprint = self._identify_geography(member_entities)
        
        # Known techniques
        known_techniques = self._identify_techniques(ring_type)
        
        # Find connected campaigns
        connected_campaigns = self._find_connected_campaigns(member_entities)
        
        analysis = FraudRingAnalysis(
            ring_name=f"Ring_{ring_type}_{random.randint(1000, 9999)}",
            member_entities=member_entities,
            relationships=relationships,
            ring_score=ring_score,
            ring_type=ring_type,
            financial_impact=financial_impact,
            geographic_footprint=geographic_footprint,
            known_techniques=known_techniques,
            connected_campaigns=connected_campaigns,
            confidence=random.uniform(0.7, 0.95),
        )
        
        # Store analysis
        self._store.store_fraud_ring(analysis)
        
        logger.info(f"Fraud ring analysis complete: {analysis.ring_id}")
        return analysis
    
    def analyze_ring_expansion(
        self,
        ring_id: str,
        new_entity: str,
    ) -> Dict[str, Any]:
        """Analyze potential ring expansion.
        
        Args:
            ring_id: Ring to analyze
            new_entity: New entity to add
            
        Returns:
            Expansion analysis
        """
        ring = self._store.get_fraud_ring(ring_id)
        
        if not ring:
            return {"error": "Ring not found"}
        
        # Check if entity is already in ring
        if new_entity in ring.member_entities:
            return {"can_add": False, "reason": "Entity already in ring"}
        
        # Analyze connection strength
        connection_strength = random.uniform(0.3, 0.95)
        
        return {
            "can_add": connection_strength > 0.5,
            "connection_strength": connection_strength,
            "risk_increase": random.uniform(0.1, 0.3) if connection_strength > 0.5 else 0,
            "recommended_action": "monitor" if connection_strength < 0.7 else "investigate",
        }
    
    def link_entities_to_ring(
        self,
        entity_ids: List[str],
        ring_id: str,
    ) -> bool:
        """Link multiple entities to an existing ring.
        
        Args:
            entity_ids: Entities to link
            ring_id: Target ring
            
        Returns:
            True if successful
        """
        ring = self._store.get_fraud_ring(ring_id)
        
        if not ring:
            return False
        
        for entity_id in entity_ids:
            if entity_id not in ring.member_entities:
                ring.member_entities.append(entity_id)
        
        return True
    
    def create_ring_detection_task(
        self,
        seed_entities: List[str],
        ring_type: str,
        priority: TaskPriority = TaskPriority.HIGH,
    ) -> AgentTask:
        """Create a fraud ring detection task.
        
        Args:
            seed_entities: Seed entities
            ring_type: Type of ring
            priority: Task priority
            
        Returns:
            AgentTask
        """
        task = AgentTask(
            agent_type=AgentType.FRAUD_RING,
            title=f"Detect {ring_type} Fraud Ring",
            description=f"Detect and analyze fraud ring starting from {len(seed_entities)} entities",
            priority=priority,
            context={
                "seed_entities": seed_entities,
                "ring_type": ring_type,
                "type": "ring_detection",
            },
        )
        
        self._store.store_task(task)
        logger.info(f"Created ring detection task: {task.task_id}")
        
        return task
    
    def get_ring_details(self, ring_id: str) -> Optional[FraudRingAnalysis]:
        """Get fraud ring details."""
        return self._store.get_fraud_ring(ring_id)
    
    def get_all_rings(self) -> List[FraudRingAnalysis]:
        """Get all fraud rings."""
        return self._store.get_all_fraud_rings()
    
    def get_high_risk_rings(self, threshold: float = 0.7) -> List[FraudRingAnalysis]:
        """Get high-risk fraud rings."""
        all_rings = self.get_all_rings()
        return [r for r in all_rings if r.ring_score >= threshold]
    
    def _expand_ring_membership(
        self,
        seed_entities: List[str],
        context: Dict[str, Any],
    ) -> List[str]:
        """Expand ring membership from seed entities."""
        members = list(seed_entities)
        
        # Simulate membership expansion
        expansion_count = random.randint(5, 20)
        for _ in range(expansion_count):
            members.append(f"member_{random.randint(1000, 9999)}")
        
        return members
    
    def _identify_relationships(
        self,
        member_entities: List[str],
    ) -> List[Dict[str, Any]]:
        """Identify relationships between ring members."""
        relationships = []
        
        # Create various relationship types
        for i in range(min(len(member_entities), 10)):
            relationships.append({
                "from_entity": member_entities[i % len(member_entities)],
                "to_entity": member_entities[(i + 1) % len(member_entities)],
                "relationship_type": random.choice([
                    "shared_device",
                    "shared_ip",
                    "shared_account",
                    "financial_tie",
                    "communication",
                ]),
                "strength": random.uniform(0.5, 1.0),
            })
        
        return relationships
    
    def _calculate_ring_score(
        self,
        member_entities: List[str],
        relationships: List[Dict[str, Any]],
    ) -> float:
        """Calculate overall ring risk score."""
        base_score = min(len(member_entities) * 0.05, 0.5)
        relationship_bonus = len(relationships) * 0.03
        network_density = len(relationships) / max(len(member_entities), 1)
        
        score = min(1.0, base_score + relationship_bonus + network_density * 0.2)
        return round(score, 2)
    
    def _estimate_financial_impact(
        self,
        member_entities: List[str],
    ) -> float:
        """Estimate financial impact of ring."""
        base_impact = len(member_entities) * random.uniform(5000, 50000)
        return round(base_impact, 2)
    
    def _identify_geography(
        self,
        member_entities: List[str],
    ) -> List[str]:
        """Identify geographic footprint."""
        countries = ["US", "RU", "CN", "BR", "IN", "NG", "UA", "GB", "DE", "FR"]
        return random.sample(countries, k=random.randint(2, 5))
    
    def _identify_techniques(self, ring_type: str) -> List[str]:
        """Identify known fraud techniques."""
        technique_mapping = {
            "money_laundering": ["structuring", "layering", "integration", "smurfing"],
            "account_takeover": ["credential_stuffing", "phishing", "social_engineering"],
            "payment_fraud": ["card_testing", "BIN_attacks", "test_transactions"],
            "identity_theft": ["synthetic_identity", "true_name_theft", "account_open"],
        }
        return technique_mapping.get(ring_type, ["unknown_technique"])
    
    def _find_connected_campaigns(
        self,
        member_entities: List[str],
    ) -> List[str]:
        """Find campaigns connected to this ring."""
        campaign_count = random.randint(1, 5)
        return [f"campaign_{random.randint(100, 999)}" for _ in range(campaign_count)]


# Global singleton
_fraud_ring_agent: Optional[FraudRingAgent] = None


def get_fraud_ring_agent(store: Optional[SOCStore] = None) -> FraudRingAgent:
    """Get or create the singleton FraudRingAgent instance."""
    global _fraud_ring_agent
    
    if _fraud_ring_agent is None:
        _fraud_ring_agent = FraudRingAgent(store=store)
    return _fraud_ring_agent