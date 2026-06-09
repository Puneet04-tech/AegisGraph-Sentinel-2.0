"""
Multi-Agent SOC Storage Engine.

Thread-safe storage for SOC agents, tasks, and orchestration state.
"""

from collections import OrderedDict
from threading import Lock
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
import logging

from .models import (
    AgentTask,
    AgentState,
    AgentType,
    AgentStatus,
    InvestigationResult,
    ThreatIntelligenceReport,
    ForensicAnalysis,
    FraudRingAnalysis,
    SOCReport,
    AgentMessage,
    OrchestrationPlan,
)

logger = logging.getLogger(__name__)


class SOCStore:
    """Thread-safe storage for SOC agent data.
    
    Provides:
        - O(1) lookup by ID
        - LRU cache for bounded memory
        - Thread-safe operations
        - Task queue management
    """
    
    def __init__(self, max_size: int = 5000):
        """Initialize the SOC store.
        
        Args:
            max_size: Maximum records per category
        """
        self._max_size = max_size
        self._lock = Lock()
        
        # Agent state storage
        self._agents: Dict[str, AgentState] = {}
        
        # Task storage
        self._tasks: OrderedDict[str, AgentTask] = OrderedDict()
        self._task_by_agent: Dict[str, List[str]] = {}  # agent_type -> task_ids
        
        # Investigation storage
        self._investigations: Dict[str, InvestigationResult] = {}
        
        # Threat intelligence storage
        self._threat_reports: Dict[str, ThreatIntelligenceReport] = {}
        
        # Forensic analysis storage
        self._forensic_analyses: Dict[str, ForensicAnalysis] = {}
        
        # Fraud ring storage
        self._fraud_rings: Dict[str, FraudRingAnalysis] = {}
        
        # Report storage
        self._reports: Dict[str, SOCReport] = {}
        
        # Message storage
        self._messages: List[AgentMessage] = []
        
        # Orchestration plans
        self._plans: Dict[str, OrchestrationPlan] = {}
        
        # Initialize default agents
        self._initialize_default_agents()
    
    def _initialize_default_agents(self):
        """Initialize default SOC agents."""
        default_agents = [
            AgentState(
                agent_type=AgentType.INVESTIGATION,
                name="Investigation Agent",
                capabilities=[
                    "entity_analysis",
                    "alert_triage",
                    "case_management",
                    "risk_scoring",
                ],
            ),
            AgentState(
                agent_type=AgentType.THREAT_INTELLIGENCE,
                name="Threat Intelligence Agent",
                capabilities=[
                    "threat_detection",
                    "ioc_analysis",
                    "ttp_mapping",
                    "threat_actor_tracking",
                ],
            ),
            AgentState(
                agent_type=AgentType.FORENSICS,
                name="Forensics Agent",
                capabilities=[
                    "digital_forensics",
                    "evidence_collection",
                    "chain_of_custody",
                    "timeline_analysis",
                ],
            ),
            AgentState(
                agent_type=AgentType.FRAUD_RING,
                name="Fraud Ring Agent",
                capabilities=[
                    "ring_detection",
                    "entity_linking",
                    "network_analysis",
                    "pattern_recognition",
                ],
            ),
            AgentState(
                agent_type=AgentType.REPORTING,
                name="Reporting Agent",
                capabilities=[
                    "report_generation",
                    "metric_calculation",
                    "trend_analysis",
                    "compliance_reporting",
                ],
            ),
        ]
        
        for agent in default_agents:
            self._agents[agent.agent_id] = agent
    
    def store_task(self, task: AgentTask) -> AgentTask:
        """Store a task."""
        with self._lock:
            self._tasks[task.task_id] = task
            
            # Track by agent type
            agent_key = task.agent_type.value
            if agent_key not in self._task_by_agent:
                self._task_by_agent[agent_key] = []
            self._task_by_agent[agent_key].append(task.task_id)
            
            # Enforce size limit
            while len(self._tasks) > self._max_size:
                self._tasks.popitem(last=False)
        
        logger.debug(f"Stored task {task.task_id}")
        return task
    
    def get_task(self, task_id: str) -> Optional[AgentTask]:
        """Get a task by ID."""
        return self._tasks.get(task_id)
    
    def get_tasks_by_agent(self, agent_type: AgentType) -> List[AgentTask]:
        """Get all tasks for an agent type."""
        task_ids = self._task_by_agent.get(agent_type.value, [])
        return [self._tasks[tid] for tid in task_ids if tid in self._tasks]
    
    def get_pending_tasks(self, agent_type: Optional[AgentType] = None) -> List[AgentTask]:
        """Get pending tasks, optionally filtered by agent type."""
        tasks = []
        for task in self._tasks.values():
            if task.status.value == "PENDING":
                if agent_type is None or task.agent_type == agent_type:
                    tasks.append(task)
        return sorted(tasks, key=lambda t: (
            {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(t.priority.value, 4),
            t.created_at
        ))
    
    def store_investigation(self, result: InvestigationResult) -> InvestigationResult:
        """Store investigation result."""
        with self._lock:
            self._investigations[result.investigation_id] = result
        
        logger.debug(f"Stored investigation {result.investigation_id}")
        return result
    
    def get_investigation(self, investigation_id: str) -> Optional[InvestigationResult]:
        """Get investigation by ID."""
        return self._investigations.get(investigation_id)
    
    def get_entity_investigations(self, entity_id: str) -> List[InvestigationResult]:
        """Get all investigations for an entity."""
        return [
            inv for inv in self._investigations.values()
            if inv.entity_id == entity_id
        ]
    
    def store_threat_report(self, report: ThreatIntelligenceReport) -> ThreatIntelligenceReport:
        """Store threat intelligence report."""
        with self._lock:
            self._threat_reports[report.report_id] = report
        
        logger.debug(f"Stored threat report {report.report_id}")
        return report
    
    def get_threat_report(self, report_id: str) -> Optional[ThreatIntelligenceReport]:
        """Get threat report by ID."""
        return self._threat_reports.get(report_id)
    
    def get_recent_threats(self, hours: int = 24) -> List[ThreatIntelligenceReport]:
        """Get recent threat reports."""
        cutoff = datetime.now(timezone.utc).timestamp() - (hours * 3600)
        return [
            r for r in self._threat_reports.values()
            if r.created_at.timestamp() > cutoff
        ]
    
    def store_forensic_analysis(self, analysis: ForensicAnalysis) -> ForensicAnalysis:
        """Store forensic analysis."""
        with self._lock:
            self._forensic_analyses[analysis.analysis_id] = analysis
        
        logger.debug(f"Stored forensic analysis {analysis.analysis_id}")
        return analysis
    
    def get_forensic_analysis(self, analysis_id: str) -> Optional[ForensicAnalysis]:
        """Get forensic analysis by ID."""
        return self._forensic_analyses.get(analysis_id)
    
    def get_entity_forensics(self, entity_id: str) -> List[ForensicAnalysis]:
        """Get all forensic analyses for an entity."""
        return [
            f for f in self._forensic_analyses.values()
            if f.target_entity_id == entity_id
        ]
    
    def store_fraud_ring(self, ring: FraudRingAnalysis) -> FraudRingAnalysis:
        """Store fraud ring analysis."""
        with self._lock:
            self._fraud_rings[ring.ring_id] = ring
        
        logger.debug(f"Stored fraud ring {ring.ring_id}")
        return ring
    
    def get_fraud_ring(self, ring_id: str) -> Optional[FraudRingAnalysis]:
        """Get fraud ring by ID."""
        return self._fraud_rings.get(ring_id)
    
    def get_all_fraud_rings(self) -> List[FraudRingAnalysis]:
        """Get all fraud rings."""
        return list(self._fraud_rings.values())
    
    def store_report(self, report: SOCReport) -> SOCReport:
        """Store SOC report."""
        with self._lock:
            self._reports[report.report_id] = report
        
        logger.debug(f"Stored report {report.report_id}")
        return report
    
    def get_report(self, report_id: str) -> Optional[SOCReport]:
        """Get report by ID."""
        return self._reports.get(report_id)
    
    def get_recent_reports(self, hours: int = 24) -> List[SOCReport]:
        """Get recent reports."""
        cutoff = datetime.now(timezone.utc).timestamp() - (hours * 3600)
        return [
            r for r in self._reports.values()
            if r.created_at.timestamp() > cutoff
        ]
    
    def store_plan(self, plan: OrchestrationPlan) -> OrchestrationPlan:
        """Store orchestration plan."""
        with self._lock:
            self._plans[plan.plan_id] = plan
        
        logger.debug(f"Stored plan {plan.plan_id}")
        return plan
    
    def get_plan(self, plan_id: str) -> Optional[OrchestrationPlan]:
        """Get orchestration plan by ID."""
        return self._plans.get(plan_id)
    
    def get_active_plan(self) -> Optional[OrchestrationPlan]:
        """Get the active orchestration plan."""
        for plan in self._plans.values():
            if plan.status in ["PENDING", "IN_PROGRESS"]:
                return plan
        return None
    
    def get_stats(self) -> Dict[str, Any]:
        """Get store statistics."""
        return {
            "total_agents": len(self._agents),
            "total_tasks": len(self._tasks),
            "pending_tasks": len(self.get_pending_tasks()),
            "investigations_stored": len(self._investigations),
            "threat_reports_stored": len(self._threat_reports),
            "forensic_analyses_stored": len(self._forensic_analyses),
            "fraud_rings_stored": len(self._fraud_rings),
            "reports_stored": len(self._reports),
            "messages_stored": len(self._messages),
            "plans_stored": len(self._plans),
        }


# Global singleton
_soc_store: Optional[SOCStore] = None


def get_soc_store() -> SOCStore:
    """Get or create the singleton SOC store instance."""
    global _soc_store
    
    if _soc_store is None:
        _soc_store = SOCStore()
    return _soc_store