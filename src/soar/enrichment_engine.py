import uuid
import logging
from datetime import datetime, timezone
from src.soar.models import CaseEnrichment
from src.soar.store import SOARStore
from src.soar.audit import SOARAuditLogger

logger = logging.getLogger("aegis.soar.enrichment_engine")

class EnrichmentEngine:
    def __init__(self, store: SOARStore, audit_logger: SOARAuditLogger) -> None:
        self.store = store
        self.audit_logger = audit_logger

    def enrich_entity(self, entity_id: str) -> CaseEnrichment:
        enrichment = self.store.get_enrichment(entity_id)
        if enrichment:
            return enrichment
            
        # Mock intelligence lookup
        threat_intel = {
            "reputation_score": 0.15,
            "malicious_reports": 0,
            "known_associations": []
        }
        
        behavior_summary = {
            "average_transaction_value": 500.0,
            "typical_login_hours": [9, 10, 11, 14, 15, 17],
            "common_device_ids": ["dev_default"]
        }
        
        # Adjust based on simulated patterns in entity_id
        if "malicious" in entity_id.lower() or "bad" in entity_id.lower():
            threat_intel["reputation_score"] = 0.95
            threat_intel["malicious_reports"] = 14
            threat_intel["known_associations"] = ["mule_network_east", "tor_exit_node"]
            
        if "ip" in entity_id.lower() or "." in entity_id:
            threat_intel["geo_ip_country"] = "IN"
            threat_intel["isp"] = "Aegis Telecom"

        enrichment_id = f"ENR-{uuid.uuid4().hex[:8].upper()}"
        
        enrichment = CaseEnrichment(
            enrichment_id=enrichment_id,
            entity_id=entity_id,
            threat_intel_data=threat_intel,
            behavior_summary=behavior_summary,
            resolved_entities=[entity_id],
            updated_at=datetime.now(timezone.utc).isoformat()
        )
        
        self.store.add_enrichment(enrichment)
        
        self.audit_logger.log_action(
            action="ENRICH_ENTITY",
            user_id="SYSTEM",
            ip_address="127.0.0.1",
            status="SUCCESS",
            details={"enrichment_id": enrichment_id, "entity_id": entity_id}
        )
        
        return enrichment
