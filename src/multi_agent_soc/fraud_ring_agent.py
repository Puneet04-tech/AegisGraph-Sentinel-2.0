"""
Fraud Ring Agent.

Analyzes fraud rings, detects network patterns, and tracks organized fraud activity.
"""

from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
import logging

from .models import (
    AgentTask,
    AgentType,
    TaskPriority,
    FraudRingAnalysis,
)
from src.graph_analytics.service import GraphService, get_graph_service

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
    
    #: Depth of the neighbourhood walked out from each seed entity when
    #: expanding ring membership. Two hops captures a member and the
    #: counterparty that links them without pulling in the whole component.
    EXPANSION_DEPTH = 2

    #: Upper bound on ring size. Expansion stops here so that a seed sitting in
    #: a densely connected component cannot walk the entire graph into a single
    #: "ring".
    MAX_RING_MEMBERS = 250

    #: Edge weight below which a link is treated as incidental rather than
    #: evidence of ring membership.
    MIN_RELATIONSHIP_STRENGTH = 0.1

    #: Connection strength above which a candidate entity is considered
    #: attached to the ring rather than merely adjacent to it.
    RING_ATTACHMENT_THRESHOLD = 0.5

    #: Connection strength above which expansion warrants active investigation
    #: rather than passive monitoring.
    RING_INVESTIGATION_THRESHOLD = 0.7

    #: Fallback per-member loss used when no member carries an observed
    #: transaction value, so impact stays proportional to ring size instead of
    #: being reported as zero.
    DEFAULT_MEMBER_EXPOSURE = 5000.0

    def __init__(
        self,
        store: Optional[SOCStore] = None,
        graph: Optional[GraphService] = None,
    ):
        """Initialize the fraud ring agent.

        Args:
            store: Optional SOC store
            graph: Optional graph analytics service supplying ring membership
                and relationships; defaults to the shared instance
        """
        self._store = store or get_soc_store()
        self._graph = graph or get_graph_service()
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

        # Membership, relationships and every derived figure below come from a
        # single traversal of the real graph. Each of these was previously
        # invented: membership was a run of `member_<random int>` identifiers
        # that matched no stored entity, so a "detected" ring named entities
        # that did not exist and could never be actioned by an analyst.
        nodes, edges = self._collect_network(seed_entities, context)

        member_entities = [node_id for node_id in nodes]

        relationships = self._identify_relationships(member_entities, edges)

        # Calculate ring score
        ring_score = self._calculate_ring_score(member_entities, relationships)

        # Estimate financial impact
        financial_impact = self._estimate_financial_impact(nodes)

        # Identify geographic footprint
        geographic_footprint = self._identify_geography(nodes)

        # Known techniques
        known_techniques = self._identify_techniques(ring_type)

        # Find connected campaigns
        connected_campaigns = self._find_connected_campaigns(nodes)

        analysis = FraudRingAnalysis(
            ring_name=self._build_ring_name(ring_type, seed_entities),
            member_entities=member_entities,
            relationships=relationships,
            ring_score=ring_score,
            ring_type=ring_type,
            financial_impact=financial_impact,
            geographic_footprint=geographic_footprint,
            known_techniques=known_techniques,
            connected_campaigns=connected_campaigns,
            confidence=self._calculate_confidence(
                seed_entities, member_entities, relationships
            ),
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
        
        # Strength is the entity's strongest real tie to any current member.
        # This was a random draw, so an unconnected entity was recommended for
        # addition roughly two times in three.
        connection_strength = 0.0
        linked_members = []

        for member in ring.member_entities:
            if member == new_entity:
                continue
            try:
                strength = float(
                    self._graph.get_connection_strength(new_entity, member) or 0.0
                )
            except Exception as e:
                logger.error(
                    "Failed to measure connection between %s and %s: %s",
                    new_entity,
                    member,
                    e,
                    exc_info=True,
                )
                continue

            if strength > 0:
                linked_members.append(member)
            connection_strength = max(connection_strength, strength)

        connection_strength = round(min(1.0, connection_strength), 2)
        can_add = connection_strength >= self.RING_ATTACHMENT_THRESHOLD

        return {
            "can_add": can_add,
            "connection_strength": connection_strength,
            # Risk grows with how many members the entity ties back to, not
            # with a random increment.
            "risk_increase": (
                round(min(0.3, 0.05 * len(linked_members)), 2) if can_add else 0
            ),
            "linked_members": linked_members,
            "recommended_action": (
                "investigate"
                if connection_strength >= self.RING_INVESTIGATION_THRESHOLD
                else "monitor"
            ),
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
    
    def _collect_network(
        self,
        seed_entities: List[str],
        context: Dict[str, Any],
    ) -> tuple:
        """Walk the graph out from each seed and collect the real membership.

        Args:
            seed_entities: Initial entities to investigate
            context: Additional context; an ``expansion_depth`` override is
                honoured so callers can widen or narrow the walk

        Returns:
            Tuple of (ordered {node_id: node dict}, list of edge dicts). Seeds
            are always present in the mapping even when the graph holds nothing
            for them, so a ring never silently drops the entity it was asked
            about.
        """
        depth = int(context.get("expansion_depth", self.EXPANSION_DEPTH))

        nodes: Dict[str, Dict[str, Any]] = {}
        edges: Dict[str, Dict[str, Any]] = {}

        # Seeds are recorded up front so membership order follows the caller's,
        # but a seed added this way carries no properties yet; it is resolved
        # as soon as the traversal returns the entity's real node.
        unresolved_seeds = set()

        for seed in seed_entities:
            if seed not in nodes and len(nodes) < self.MAX_RING_MEMBERS:
                nodes[seed] = {"node_id": seed}
                unresolved_seeds.add(seed)

            try:
                network = self._graph.get_entity_network(seed, depth=depth)
            except Exception as e:
                logger.error(
                    "Failed to expand ring membership from %s: %s", seed, e, exc_info=True
                )
                continue

            for node in network.get("nodes", []):
                node_id = node.get("node_id")
                if not node_id:
                    continue

                if node_id in unresolved_seeds:
                    # Replace the placeholder so the seed's own exposure,
                    # country and campaign attribution are not lost.
                    nodes[node_id] = node
                    unresolved_seeds.discard(node_id)
                    continue

                if node_id in nodes:
                    continue
                if len(nodes) >= self.MAX_RING_MEMBERS:
                    break
                nodes[node_id] = node

            for edge in network.get("edges", []):
                edge_id = edge.get("edge_id")
                if edge_id and edge_id not in edges:
                    edges[edge_id] = edge

        # Edges pulled in at the traversal frontier can point at nodes that the
        # member cap excluded; dropping them keeps relationships consistent
        # with the reported membership.
        retained = [
            edge
            for edge in edges.values()
            if edge.get("source_id") in nodes and edge.get("target_id") in nodes
        ]

        return nodes, retained

    def _identify_relationships(
        self,
        member_entities: List[str],
        edges: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Identify relationships between ring members.

        Relationships are the graph's own edges. Previously this fabricated a
        ring-shaped chain by walking members pairwise and attaching a random
        edge type, so the reported structure described no real connection.
        """
        relationships = []
        members = set(member_entities)

        for edge in edges:
            # Membership is authoritative: an edge is only a ring relationship
            # if both endpoints were actually reported as members.
            if edge.get("source_id") not in members or edge.get("target_id") not in members:
                continue

            strength = float(edge.get("weight", 0.0) or 0.0)
            if strength < self.MIN_RELATIONSHIP_STRENGTH:
                continue

            relationships.append({
                "from_entity": edge.get("source_id"),
                "to_entity": edge.get("target_id"),
                "relationship_type": edge.get("edge_type", "linked_to"),
                "strength": round(min(1.0, strength), 2),
            })

        # Strongest ties first so an analyst reads the load-bearing links of
        # the ring before incidental ones.
        relationships.sort(key=lambda r: (-r["strength"], str(r["from_entity"])))
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
        nodes: Dict[str, Dict[str, Any]],
    ) -> float:
        """Estimate financial impact of ring.

        Sums the exposure actually recorded against each member. The previous
        implementation multiplied the member count by a random per-member
        figure, so the same ring reported a different loss on every call and
        the number could not be reconciled against any transaction.
        """
        total = 0.0
        observed = 0

        for node in nodes.values():
            properties = node.get("properties") or {}
            exposure = self._coerce_amount(
                properties.get("total_amount")
                if properties.get("total_amount") is not None
                else properties.get("transaction_volume")
            )

            if exposure is not None:
                total += exposure
                observed += 1

        # Members with no recorded exposure still represent loss potential, so
        # they carry the fallback rather than contributing nothing.
        total += (len(nodes) - observed) * self.DEFAULT_MEMBER_EXPOSURE

        return round(total, 2)

    def _identify_geography(
        self,
        nodes: Dict[str, Dict[str, Any]],
    ) -> List[str]:
        """Identify geographic footprint.

        Reads the country recorded against each member instead of sampling a
        hardcoded country list, which previously attributed rings to
        jurisdictions they had no presence in.
        """
        countries = set()

        for node in nodes.values():
            properties = node.get("properties") or {}
            country = properties.get("country") or properties.get("country_code")
            if isinstance(country, str) and country.strip():
                countries.add(country.strip().upper())

        return sorted(countries)


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
        nodes: Dict[str, Dict[str, Any]],
    ) -> List[str]:
        """Find campaigns connected to this ring.

        Collects campaign attributions recorded against members. This used to
        mint `campaign_<random int>` identifiers, which linked rings to
        campaigns that did not exist.
        """
        campaigns = set()

        for node in nodes.values():
            properties = node.get("properties") or {}
            campaign = properties.get("campaign_id")
            if isinstance(campaign, str) and campaign.strip():
                campaigns.add(campaign.strip())

            for tag in node.get("tags") or []:
                if isinstance(tag, str) and tag.startswith("campaign:"):
                    label = tag.split(":", 1)[1].strip()
                    if label:
                        campaigns.add(label)

        return sorted(campaigns)

    def _calculate_confidence(
        self,
        seed_entities: List[str],
        member_entities: List[str],
        relationships: List[Dict[str, Any]],
    ) -> float:
        """Score how well the graph actually supports the reported ring.

        Confidence was a flat random draw in the 0.7-0.95 band, so a ring built
        from a single unknown entity was reported as confidently as a dense,
        fully evidenced one. It now rises with corroborating structure and
        stays low when the graph supplied nothing beyond the seeds.
        """
        discovered = max(len(member_entities) - len(seed_entities), 0)
        if discovered == 0 and not relationships:
            # Nothing beyond what the caller supplied — no evidence of a ring.
            return 0.1

        # Members found beyond the seeds, saturating at ten.
        expansion_support = min(discovered, 10) / 10.0

        # Edge density relative to a spanning tree over the membership.
        spanning = max(len(member_entities) - 1, 1)
        density_support = min(len(relationships) / spanning, 1.0)

        mean_strength = (
            sum(r["strength"] for r in relationships) / len(relationships)
            if relationships
            else 0.0
        )

        confidence = (
            0.2
            + 0.3 * expansion_support
            + 0.3 * density_support
            + 0.2 * mean_strength
        )
        return round(min(0.95, confidence), 2)

    def _build_ring_name(self, ring_type: str, seed_entities: List[str]) -> str:
        """Build a stable ring name.

        The name embedded a random integer, so re-running detection over the
        same seeds produced a differently named ring each time and duplicates
        could not be recognised.
        """
        anchor = min(seed_entities) if seed_entities else "unseeded"
        return f"Ring_{ring_type}_{anchor}"

    @staticmethod
    def _coerce_amount(value: Any) -> Optional[float]:
        """Coerce a stored exposure value to a non-negative float.

        Node properties are free-form, so a value may arrive as a string or be
        absent entirely; anything unusable is treated as unrecorded rather than
        crashing ring detection.
        """
        if value is None or isinstance(value, bool):
            return None

        try:
            amount = float(value)
        except (TypeError, ValueError):
            return None

        if amount != amount or amount in (float("inf"), float("-inf")):
            return None

        return abs(amount)


# Global singleton
_fraud_ring_agent: Optional[FraudRingAgent] = None


def get_fraud_ring_agent(store: Optional[SOCStore] = None) -> FraudRingAgent:
    """Get or create the singleton FraudRingAgent instance."""
    global _fraud_ring_agent
    
    if _fraud_ring_agent is None:
        _fraud_ring_agent = FraudRingAgent(store=store)
    return _fraud_ring_agent