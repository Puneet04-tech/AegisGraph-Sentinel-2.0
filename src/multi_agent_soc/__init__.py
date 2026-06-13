"""
Multi-Agent Fraud Security Operations Center (SOC).

A production-grade multi-agent framework for autonomous fraud investigation,
threat intelligence, digital forensics, fraud ring detection, and SOC reporting.

Agents:
    - Investigation Agent: Entity analysis, alert triage, case management
    - Threat Intelligence Agent: Threat detection, IOC analysis, MITRE ATT&CK mapping
    - Forensics Agent: Digital forensics, evidence collection, chain of custody
    - Fraud Ring Agent: Ring detection, entity linking, network analysis
    - Reporting Agent: Report generation, metrics, compliance reporting
    - Agent Orchestrator: Workflow orchestration, agent coordination, task management
"""

from .models import (
    AgentType,
    AgentStatus,
    TaskPriority,
    TaskStatus,
    InvestigationStatus,
    AgentTask,
    AgentState,
    InvestigationRequest,
    InvestigationResult,
    ThreatIntelligenceReport,
    ForensicAnalysis,
    FraudRingAnalysis,
    SOCReport,
    AgentMessage,
    OrchestrationPlan,
)
from .store import SOCStore, get_soc_store
from .investigation_agent import InvestigationAgent, get_investigation_agent
from .threat_intelligence_agent import ThreatIntelligenceAgent, get_threat_intelligence_agent
from .forensics_agent import ForensicsAgent, get_forensics_agent
from .fraud_ring_agent import FraudRingAgent, get_fraud_ring_agent
from .reporting_agent import ReportingAgent, get_reporting_agent
from .orchestrator import AgentOrchestrator, get_orchestrator

__all__ = [
    # Models
    "AgentType",
    "AgentStatus",
    "TaskPriority",
    "TaskStatus",
    "InvestigationStatus",
    "AgentTask",
    "AgentState",
    "InvestigationRequest",
    "InvestigationResult",
    "ThreatIntelligenceReport",
    "ForensicAnalysis",
    "FraudRingAnalysis",
    "SOCReport",
    "AgentMessage",
    "OrchestrationPlan",
    # Store
    "SOCStore",
    "get_soc_store",
    # Agents
    "InvestigationAgent",
    "get_investigation_agent",
    "ThreatIntelligenceAgent",
    "get_threat_intelligence_agent",
    "ForensicsAgent",
    "get_forensics_agent",
    "FraudRingAgent",
    "get_fraud_ring_agent",
    "ReportingAgent",
    "get_reporting_agent",
    "AgentOrchestrator",
    "get_orchestrator",
]