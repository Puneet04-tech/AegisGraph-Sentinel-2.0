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
        """Scans the store and auto-groups active incidents sharing common entities."""
        incidents = self.store.list_incidents()
        entity_map = {}
        
        for inc in incidents:
            for entity in inc.entities:
                if entity not in entity_map:
                    entity_map[entity] = []
                entity_map[entity].append(inc.incident_id)
                
        correlations = []
        for entity, inc_ids in entity_map.items():
            if len(inc_ids) > 1:
                # We have a correlation!
                name = f"Auto-correlation for {entity}"
                corr = self.correlate_incidents(
                    name=name,
                    incident_ids=inc_ids,
                    entities=[entity]
                )
                correlations.append(corr)
                
        return correlations
