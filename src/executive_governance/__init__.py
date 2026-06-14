"""
Executive Risk Governance Platform.

A production-grade governance module for executive dashboards, board reporting,
compliance analytics, risk governance, and audit intelligence.

Modules:
    - Executive Dashboard: Executive KPI summaries and dashboards
    - Board Reporting: Board and executive report generation
    - Compliance Analytics: Compliance tracking and framework management
    - Risk Governance: Enterprise risk management and oversight
    - Audit Intelligence: Audit management and finding tracking
"""

from .models import (
    RiskLevel,
    ComplianceStatus,
    AuditFindingSeverity,
    ReportType,
    GovernanceMetric,
    RiskScorecard,
    ComplianceFramework,
    ControlAssessment,
    AuditFinding,
    BoardMetric,
    ExecutiveDashboard,
    GovernanceReport,
    PolicyViolation,
    RiskThreshold,
)
from .store import GovernanceStore, get_governance_store
from .executive_dashboard import ExecutiveDashboardModule, get_executive_dashboard_module
from .board_reporting import BoardReportingModule, get_board_reporting_module
from .compliance_analytics import ComplianceAnalyticsModule, get_compliance_analytics_module
from .risk_governance import RiskGovernanceModule, get_risk_governance_module
from .audit_intelligence import AuditIntelligenceModule, get_audit_intelligence_module

__all__ = [
    # Enums
    "RiskLevel",
    "ComplianceStatus",
    "AuditFindingSeverity",
    "ReportType",
    # Models
    "GovernanceMetric",
    "RiskScorecard",
    "ComplianceFramework",
    "ControlAssessment",
    "AuditFinding",
    "BoardMetric",
    "ExecutiveDashboard",
    "GovernanceReport",
    "PolicyViolation",
    "RiskThreshold",
    # Store
    "GovernanceStore",
    "get_governance_store",
    # Modules
    "ExecutiveDashboardModule",
    "get_executive_dashboard_module",
    "BoardReportingModule",
    "get_board_reporting_module",
    "ComplianceAnalyticsModule",
    "get_compliance_analytics_module",
    "RiskGovernanceModule",
    "get_risk_governance_module",
    "AuditIntelligenceModule",
    "get_audit_intelligence_module",
]