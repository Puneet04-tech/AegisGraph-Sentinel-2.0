import uuid
import logging
from datetime import datetime, timezone
from typing import List, Optional
from src.soar.models import ThreatCorrelation
from src.soar.store import SOARStore
from src.soar.audit import SOARAuditLogger

logger = logging.getLogger("aegis.soar.correlation_engine")

class SOARCorrelationEngine:
    def __init__(self, store: SOARStore, audit_logger: SOARAuditLogger) -> None:
        self.store = store
        self.audit_logger = audit_logger

    def correlate_incidents(
        self,
        name: str,
        incident_ids: List[str],
        entities: List[str]
    ) -> ThreatCorrelation:
        correlation_id = f"CORR-{uuid.uuid4().hex[:8].upper()}"
        
        # Calculate a correlation score
        # Base score starts at 0.1, increments by 0.2 for each shared entity/incident up to a max of 1.0
        unique_entities = set(entities)
        score_calc = 0.1 + (0.2 * len(unique_entities)) + (0.1 * len(incident_ids))
        correlation_score = min(1.0, max(0.0, score_calc))
        
        correlation = ThreatCorrelation(
            correlation_id=correlation_id,
            name=name,
            correlation_score=correlation_score,
            matched_indicators=list(unique_entities),
            linked_incidents=incident_ids,
            timestamp=datetime.now(timezone.utc).isoformat()
        )
        
        self.store.add_correlation(correlation)
        
        self.audit_logger.log_action(
            action="CORRELATE_INCIDENTS",
            user_id="SYSTEM",
            ip_address="127.0.0.1",
            status="SUCCESS",
            details={
                "correlation_id": correlation_id,
                "name": name,
                "score": correlation_score,
                "incidents_count": len(incident_ids)
            }
        )
        
        return correlation

    def auto_correlate_all_incidents(self) -> List[ThreatCorrelation]:
        """Scans the store and auto-groups active incidents sharing common entities.

        Uses union-find to build connected components of incidents across all
        shared entities, producing a single composite correlation per cluster.
        Checks existing correlations in the store to avoid creating duplicates.
        """
        incidents = self.store.list_incidents()
        if not incidents:
            return []

        # Build union-find structure over incident IDs
        parent: dict = {}

        def find(x: str) -> str:
            while parent.get(x, x) != x:
                parent[x] = parent.get(parent[x], parent[x])
                x = parent[x]
            return x

        def union(a: str, b: str) -> None:
            ra, rb = find(a), find(b)
            if ra != rb:
                parent[ra] = rb

        # Map entity -> list of incident IDs
        entity_map: dict = {}
        for inc in incidents:
            parent.setdefault(inc.incident_id, inc.incident_id)
            for entity in inc.entities:
                if entity not in entity_map:
                    entity_map[entity] = []
                entity_map[entity].append(inc.incident_id)

        # Union incidents sharing the same entity
        for entity, inc_ids in entity_map.items():
            for i in range(1, len(inc_ids)):
                union(inc_ids[0], inc_ids[i])

        # Group incidents by connected component root
        clusters: dict = {}
        for inc in incidents:
            root = find(inc.incident_id)
            if root not in clusters:
                clusters[root] = set()
            clusters[root].add(inc.incident_id)

        # Collect shared entities per cluster
        cluster_entities: dict = {}
        for entity, inc_ids in entity_map.items():
            if len(inc_ids) > 1:
                root = find(inc_ids[0])
                if root not in cluster_entities:
                    cluster_entities[root] = set()
                cluster_entities[root].add(entity)

        # Build existing correlation index for deduplication
        existing_correlations = self.store.list_correlations()
        existing_incident_sets: dict = {}
        for corr in existing_correlations:
            key = frozenset(corr.linked_incidents)
            existing_incident_sets[key] = corr

        correlations = []
        for root, incident_ids in clusters.items():
            if len(incident_ids) < 2:
                continue

            sorted_ids = sorted(incident_ids)
            entities = sorted(cluster_entities.get(root, set()))
            key = frozenset(sorted_ids)

            # Skip if an identical correlation already exists
            if key in existing_incident_sets:
                continue

            name = f"Auto-correlation for {', '.join(entities[:3])}"
            if len(entities) > 3:
                name += f" (+{len(entities) - 3} more)"

            corr = self.correlate_incidents(
                name=name,
                incident_ids=sorted_ids,
                entities=entities,
            )
            correlations.append(corr)

        return correlations
