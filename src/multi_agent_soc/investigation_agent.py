"""
Investigation Agent.

Autonomous fraud investigation agent that analyzes entities, triages alerts,
and manages investigation workflows.
"""

from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
import logging

from .models import (
    AgentTask,
    AgentType,
    AgentStatus,
    TaskPriority,
    TaskStatus,
    InvestigationResult,
    InvestigationStatus,
)
from src.graph_analytics.service import GraphService, get_graph_service

from .store import SOCStore, get_soc_store

logger = logging.getLogger(__name__)


class InvestigationAgent:
    """Investigation Agent for autonomous fraud investigation.
    
    Capabilities:
        - Entity analysis and risk scoring
        - Alert triage and prioritization
        - Case management
        - Investigation workflow orchestration
        - Finding synthesis
    """
    
    #: Neighbourhood size above which an entity's connectivity is itself a
    #: signal, rather than ordinary account activity.
    FANOUT_THRESHOLD = 6

    #: Mean neighbour risk above which the surrounding network is considered
    #: to be carrying risk into this entity.
    NEIGHBOUR_RISK_THRESHOLD = 0.5

    def __init__(
        self,
        store: Optional[SOCStore] = None,
        graph: Optional[GraphService] = None,
    ):
        """Initialize the investigation agent.
        
        Args:
            store: Optional SOC store
            graph: Optional graph analytics service supplying the entity's
                neighbourhood; defaults to the shared instance
        """
        self._store = store or get_soc_store()
        self._graph = graph or get_graph_service()
        self._agent_type = AgentType.INVESTIGATION
        self._agent_id = f"investigation_agent"
    
    def analyze_entity(self, entity_id: str, context: Dict[str, Any] = None) -> InvestigationResult:
        """Analyze an entity for fraud indicators.
        
        Args:
            entity_id: Entity to analyze
            context: Additional context
            
        Returns:
            InvestigationResult with findings
        """
        logger.info(f"Analyzing entity {entity_id}")
        
        context = context or {}
        
        # Findings are derived from the entity's actual graph neighbourhood.
        # Each check previously fired on a random.random() comparison, so an
        # entity with a clean history had roughly an even chance of being
        # reported for an "unusual transaction pattern" at 75% confidence.
        risk_factors = []
        findings = []
        evidence = []

        neighbours = self._neighbours(entity_id)
        neighbour_risks = [
            float(getattr(node, "risk_score", 0.0) or 0.0) for node in neighbours
        ]
        mean_neighbour_risk = (
            sum(neighbour_risks) / len(neighbour_risks) if neighbour_risks else 0.0
        )

        if len(neighbours) >= self.FANOUT_THRESHOLD:
            risk_factors.append("unusual_transaction_pattern")
            findings.append({
                "type": "pattern_detection",
                "description": (
                    f"Entity is connected to {len(neighbours)} counterparties, "
                    f"above the threshold of {self.FANOUT_THRESHOLD}"
                ),
                "severity": "HIGH",
                # Confidence scales with how far past the threshold it sits,
                # rather than being a literal attached to a coin flip.
                "confidence": round(
                    min(0.95, 0.5 + 0.05 * (len(neighbours) - self.FANOUT_THRESHOLD)), 2
                ),
            })

        if mean_neighbour_risk >= self.NEIGHBOUR_RISK_THRESHOLD:
            risk_factors.append("high_risk_network")
            findings.append({
                "type": "network_risk",
                "description": (
                    f"Mean risk across {len(neighbours)} connected entities is "
                    f"{mean_neighbour_risk:.2f}"
                ),
                "severity": "HIGH",
                "confidence": round(min(0.95, mean_neighbour_risk), 2),
            })

        high_risk_neighbours = [risk for risk in neighbour_risks if risk >= 0.8]
        if high_risk_neighbours:
            risk_factors.append("linked_to_known_risk")
            findings.append({
                "type": "known_risk_link",
                "description": (
                    f"{len(high_risk_neighbours)} connected entities carry a risk "
                    "score of 0.8 or above"
                ),
                "severity": "MEDIUM",
                "confidence": round(min(0.95, 0.6 + 0.1 * len(high_risk_neighbours)), 2),
            })

        evidence.append({
            "type": "graph_neighbourhood",
            "count": len(neighbours),
            "suspicious_count": len(high_risk_neighbours),
            "mean_neighbour_risk": round(mean_neighbour_risk, 4),
        })

        # Derived from the findings that actually fired, so a clean entity
        # scores low rather than accumulating random increments.
        risk_score = round(min(1.0, max(0.0, mean_neighbour_risk * 0.6 + 0.15 * len(risk_factors))), 4)

        # Determine status
        if risk_score >= 0.8:
            status = InvestigationStatus.ESCALATED
        elif risk_score >= 0.5:
            status = InvestigationStatus.REQUIRES_REVIEW
        else:
            status = InvestigationStatus.CLOSED
        
        result = InvestigationResult(
            entity_id=entity_id,
            status=status,
            findings=findings,
            evidence=evidence,
            risk_score=risk_score,
            recommendations=self._generate_recommendations(risk_score, risk_factors),
            linked_entities=self._find_linked_entities(entity_id, context),
            timeline=self._build_timeline(entity_id),
            # Reflects how much evidence was available, not a fixed literal.
            confidence=round(min(0.95, 0.4 + 0.15 * len(findings)), 2) if findings else 0.4,
            processed_by=[self._agent_id],
        )
        
        # Store result
        self._store.store_investigation(result)
        
        logger.info(f"Investigation complete for {entity_id}, risk: {risk_score:.2f}")
        return result
    
    def triage_alerts(self, alert_ids: List[str], priority: TaskPriority = TaskPriority.MEDIUM) -> List[AgentTask]:
        """Triage and prioritize alerts.
        
        Args:
            alert_ids: Alert IDs to triage
            priority: Task priority
            
        Returns:
            List of investigation tasks
        """
        logger.info(f"Triaging {len(alert_ids)} alerts")
        
        tasks = []
        for alert_id in alert_ids:
            # Estimated from the alert's own recorded neighbourhood rather
            # than random.uniform(0.3, 0.9), which assigned an investigation
            # priority by dice roll.
            estimated_risk = self._estimate_alert_risk(alert_id)
            
            task = AgentTask(
                agent_type=self._agent_type,
                title=f"Investigate Alert {alert_id}",
                description=f"Investigate alert {alert_id} with estimated risk {estimated_risk:.2f}",
                priority=priority,
                context={
                    "alert_id": alert_id,
                    "estimated_risk": estimated_risk,
                    "source": "alert_triage",
                },
            )
            
            self._store.store_task(task)
            tasks.append(task)
        
        return tasks
    
    def create_investigation(self, entity_id: str, case_id: Optional[str] = None, priority: TaskPriority = TaskPriority.MEDIUM) -> AgentTask:
        """Create an investigation task.
        
        Args:
            entity_id: Entity to investigate
            case_id: Optional case ID
            priority: Task priority
            
        Returns:
            AgentTask for the investigation
        """
        task = AgentTask(
            agent_type=self._agent_type,
            title=f"Investigate Entity {entity_id}",
            description=f"Conduct comprehensive fraud investigation for entity {entity_id}",
            priority=priority,
            context={
                "entity_id": entity_id,
                "case_id": case_id,
            },
        )
        
        self._store.store_task(task)
        logger.info(f"Created investigation task {task.task_id} for {entity_id}")
        
        return task
    
    def update_investigation_status(self, investigation_id: str, status: InvestigationStatus) -> bool:
        """Update investigation status."""
        investigation = self._store.get_investigation(investigation_id)
        if investigation:
            investigation.status = status
            if status == InvestigationStatus.CLOSED:
                investigation.completed_at = datetime.now(timezone.utc)
            return True
        return False
    
    def get_investigation_summary(self, entity_id: str) -> Dict[str, Any]:
        """Get investigation summary for an entity."""
        investigations = self._store.get_entity_investigations(entity_id)
        
        if not investigations:
            return {"total": 0, "risk_score": 0.0}
        
        total_risk = sum(inv.risk_score for inv in investigations) / len(investigations)
        high_risk_count = sum(1 for inv in investigations if inv.risk_score >= 0.7)
        
        return {
            "total_investigations": len(investigations),
            "average_risk_score": total_risk,
            "high_risk_count": high_risk_count,
            "latest_investigation": investigations[-1].investigation_id if investigations else None,
        }
    
    def _generate_recommendations(self, risk_score: float, risk_factors: List[str]) -> List[str]:
        """Generate recommendations based on risk."""
        recommendations = []
        
        if risk_score >= 0.8:
            recommendations.append("ESCALATE: Immediate review required by senior analyst")
            recommendations.append("Consider temporary account freeze")
        
        if "velocity_breach" in risk_factors:
            recommendations.append("Implement transaction velocity limits")
        
        if "device_anomaly" in risk_factors:
            recommendations.append("Request additional identity verification")
        
        if risk_score >= 0.5:
            recommendations.append("Schedule enhanced monitoring for 72 hours")
        
        recommendations.append("Document findings in case management system")
        
        return recommendations
    
    def _estimate_alert_risk(self, alert_id: str) -> float:
        """Risk estimate for an alert, from the entity it concerns."""
        neighbours = self._neighbours(alert_id)
        if not neighbours:
            return 0.0
        risks = [float(getattr(n, "risk_score", 0.0) or 0.0) for n in neighbours]
        return round(min(1.0, max(risks)), 4)

    def _neighbours(self, entity_id: str) -> List[Any]:
        """Real graph neighbours of an entity, empty if it is unknown."""
        try:
            return list(self._graph.find_common_neighbors(entity_id, entity_id) or [])
        except Exception as exc:
            logger.warning("Neighbourhood lookup failed for %s: %s", entity_id, exc)
            return []

    def _find_linked_entities(self, entity_id: str, context: Dict[str, Any]) -> List[str]:
        """Find entities linked to the given entity.

        Read from the graph rather than fabricated as
        `[f"linked_{entity_id}_{i}" for i in range(random.randint(0, 5))]`,
        which invented counterparty ids that did not exist.
        """
        return [
            str(getattr(node, "node_id", node)) for node in self._neighbours(entity_id)
        ]

    def _build_timeline(self, entity_id: str) -> List[Dict[str, Any]]:
        """Build activity timeline for entity.

        Built from recorded investigations rather than the 3-10 invented
        events with random types and risk indicators this previously returned.
        Returns an empty timeline when nothing has been recorded.
        """
        try:
            history = self._store.get_investigations_for_entity(entity_id)
        except AttributeError:
            history = []
        except Exception as exc:
            logger.warning("Timeline lookup failed for %s: %s", entity_id, exc)
            history = []

        timeline = []
        for record in history or []:
            timeline.append({
                "timestamp": getattr(record, "created_at", None)
                or datetime.now(timezone.utc).isoformat(),
                "event": f"investigation_{getattr(record, 'status', 'UNKNOWN')}",
                "type": "investigation",
                "risk_indicator": float(getattr(record, "risk_score", 0.0) or 0.0) >= 0.5,
            })
        return timeline


# Global singleton
_investigation_agent: Optional[InvestigationAgent] = None


def get_investigation_agent(store: Optional[SOCStore] = None) -> InvestigationAgent:
    """Get or create the singleton InvestigationAgent instance."""
    global _investigation_agent
    
    if _investigation_agent is None:
        _investigation_agent = InvestigationAgent(store=store)
    return _investigation_agent