"""
Threat Hunting Service Wrapper for AI Threat Hunting
"""

import threading
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone

from .models import (
    ThreatHunt,
    ThreatIndicator,
    BehaviorProfile,
    ThreatCampaign,
    AttackPath,
    ThreatCorrelation,
    ThreatScore,
    HuntResult,
)
from .store import ThreatHuntingStore, get_store
from .behavior_analytics import BehaviorAnalyticsEngine
from .anomaly_detector import AnomalyDetector
from .pattern_detector import AttackPatternDetector
from .campaign_detector import CampaignDetector
from .graph_explorer import GraphIntelligenceExplorer
from .intelligence_connector import ThreatIntelligenceConnector
from .threat_scoring import ThreatScoringEngine
from .hunting_engine import ThreatHuntingEngine


class ThreatHuntingService:
    """Service facade coordinating all AI threat hunting sub-engines."""

    def __init__(self, store: Optional[ThreatHuntingStore] = None):
        self.store = store or get_store()
        self.behavior_engine = BehaviorAnalyticsEngine(self.store)
        self.anomaly_detector = AnomalyDetector(self.store)
        self.pattern_detector = AttackPatternDetector(self.store)
        self.campaign_detector = CampaignDetector(self.store)
        self.graph_explorer = GraphIntelligenceExplorer(self.store)
        self.intel_connector = ThreatIntelligenceConnector(self.store)
        self.scoring_engine = ThreatScoringEngine(self.store)
        self.hunt_engine = ThreatHuntingEngine(self.store)

    def evaluate_entity_threat(
        self,
        entity_id: str,
        entity_type: str = "user",
        amount: float = 0.0,
        hour: int = 12,
        ip_address: str = "",
        device_id: str = "",
        device_status: str = "UNKNOWN",
        failed_attempts: int = 0,
        operation: str = "",
        recent_txn_count_1m: int = 0,
        events: Optional[List[Dict[str, Any]]] = None,
        relationships: Optional[List[Dict[str, Any]]] = None,
    ) -> ThreatScore:
        """Run context assessments, compile indicators, and output unified entity threat score."""
        events = events or []
        relationships = relationships or []

        # 1. Behavior deviation evaluation
        behav = self.behavior_engine.evaluate_behavior(
            entity_id=entity_id,
            amount=amount,
            hour=hour,
            ip=ip_address,
            device_id=device_id,
            recent_txn_count_1m=recent_txn_count_1m,
        )
        behav_score = behav["overall_deviation"]

        # 2. Context anomaly detection
        anom_indicators = self.anomaly_detector.detect_anomalies(
            entity_id=entity_id,
            operation=operation,
            ip_address=ip_address,
            device_status=device_status,
            failed_attempts=failed_attempts,
        )

        # 3. Pattern detection
        pattern_indicators = self.pattern_detector.detect_patterns(
            user_id=entity_id,
            events=events,
            relationships=relationships,
        )

        all_indicators = anom_indicators + pattern_indicators

        # 4. Threat Intelligence Enrichment
        intel_score = 0.0
        if ip_address:
            intel_ind = self.intel_connector.check_ip(ip_address)
            if intel_ind:
                all_indicators.append(intel_ind)
                intel_score = 0.8

        # 5. Graph propagation / Attack paths
        graph_score = 0.0
        if relationships:
            paths = self.graph_explorer.discover_attack_paths(
                start_entity=entity_id,
                relationships=relationships,
            )
            if paths:
                graph_score = max(p.risk_score for p in paths)

        # 6. Campaign association
        campaign_score = 0.0
        self.campaign_detector.detect_campaigns()
        for camp in self.store.list_campaigns():
            if entity_id in camp.associated_entities:
                campaign_score = max(campaign_score, 0.7)

        indicator_ids = [ind.indicator_id for ind in all_indicators]

        # Calculate final threat score
        threat_score = self.scoring_engine.calculate_score(
            entity_id=entity_id,
            entity_type=entity_type,
            behavior_score=behav_score,
            campaign_score=campaign_score,
            graph_score=graph_score,
            intel_score=intel_score,
            active_indicators=indicator_ids,
        )

        self.store.record_history(
            "evaluate_entity_threat",
            {"entity_id": entity_id, "score": threat_score.score},
        )

        return threat_score

    def start_hunt(
        self,
        name: str,
        description: str,
        query_criteria: Dict[str, Any],
        created_by: str = "analyst",
    ) -> ThreatHunt:
        """Execute a custom query configuration hunt."""
        return self.hunt_engine.start_hunt(name, description, query_criteria, created_by)

    def discover_attack_paths(
        self,
        start_entity: str,
        relationships: List[Dict[str, Any]],
        max_depth: int = 3,
    ) -> List[AttackPath]:
        """Trace threat propagation routes starting from a target entity."""
        return self.graph_explorer.discover_attack_paths(start_entity, relationships, max_depth)

    def correlate_threats(
        self,
        name: str,
        entities: List[str],
        indicator_ids: List[str],
    ) -> ThreatCorrelation:
        """Correlate multiple separate indicators/entities into a unified correlation report."""
        # Calculate correlation score based on indicators severity
        total_weight = 0.0
        for ind_id in indicator_ids:
            ind = self.store.get_indicator(ind_id)
            if ind:
                if ind.severity.value == "CRITICAL":
                    total_weight += 0.4
                elif ind.severity.value == "HIGH":
                    total_weight += 0.3
                elif ind.severity.value == "MEDIUM":
                    total_weight += 0.2
                else:
                    total_weight += 0.1

        correlation_score = min(1.0, total_weight)

        correlation = ThreatCorrelation(
            name=name,
            entities=entities,
            indicators=indicator_ids,
            correlation_score=correlation_score,
        )
        self.store.add_correlation(correlation)
        return correlation

    def get_dashboard_stats(self) -> Dict[str, Any]:
        """Aggregate global statistics, campaigns, hunts, and critical indicators."""
        indicators = self.store.list_indicators()
        critical_indicators = [ind.to_dict() for ind in indicators if ind.severity.value == "CRITICAL"]

        return {
            "store_stats": self.store.get_stats(),
            "critical_indicators_count": len(critical_indicators),
            "critical_indicators": critical_indicators[:10],
            "campaigns": [c.to_dict() for c in self.store.list_campaigns()[:5]],
            "recent_hunts": [h.to_dict() for h in self.store.list_hunts()[-5:]],
        }


_service: Optional[ThreatHuntingService] = None
_service_lock = threading.Lock()


def get_threat_hunting_service() -> ThreatHuntingService:
    global _service
    if _service is None:
        with _service_lock:
            if _service is None:
                _service = ThreatHuntingService()
    return _service
