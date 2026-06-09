"""
Executive Governance Storage Engine.

Thread-safe storage for governance data, reports, and metrics.
"""

from collections import OrderedDict
from threading import Lock
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
import logging

from .models import (
    GovernanceMetric,
    RiskScorecard,
    ComplianceFramework,
    ControlAssessment,
    AuditFinding,
    ExecutiveDashboard,
    GovernanceReport,
    PolicyViolation,
    RiskThreshold,
)

logger = logging.getLogger(__name__)


class GovernanceStore:
    """Thread-safe storage for governance data.
    
    Provides:
        - O(1) lookup by ID
        - LRU cache for bounded memory
        - Thread-safe operations
        - Report management
    """
    
    def __init__(self, max_size: int = 5000):
        """Initialize the governance store.
        
        Args:
            max_size: Maximum records per category
        """
        self._max_size = max_size
        self._lock = Lock()
        
        # Metrics storage
        self._metrics: OrderedDict[str, GovernanceMetric] = OrderedDict()
        
        # Risk scorecards
        self._scorecards: Dict[str, RiskScorecard] = {}
        
        # Compliance frameworks
        self._frameworks: Dict[str, ComplianceFramework] = {}
        
        # Control assessments
        self._assessments: Dict[str, ControlAssessment] = {}
        
        # Audit findings
        self._findings: Dict[str, AuditFinding] = {}
        
        # Executive dashboards
        self._dashboards: Dict[str, ExecutiveDashboard] = {}
        
        # Governance reports
        self._reports: OrderedDict[str, GovernanceReport] = OrderedDict()
        
        # Policy violations
        self._violations: Dict[str, PolicyViolation] = {}
        
        # Risk thresholds
        self._thresholds: Dict[str, RiskThreshold] = {}
        
        # Initialize default frameworks
        self._initialize_default_frameworks()
    
    def _initialize_default_frameworks(self):
        """Initialize default compliance frameworks."""
        frameworks = [
            ComplianceFramework(
                framework_name="SOC 2 Type II",
                version="2017",
                status="COMPLIANT",
                compliance_percentage=95.0,
                controls=[
                    {"id": "CC1.1", "name": "Control Environment", "status": "EFFECTIVE"},
                    {"id": "CC2.1", "name": "Communication", "status": "EFFECTIVE"},
                    {"id": "CC6.1", "name": "Logical Access", "status": "EFFECTIVE"},
                ],
                findings_count=2,
                open_findings=1,
                critical_findings=0,
            ),
            ComplianceFramework(
                framework_name="PCI-DSS",
                version="4.0",
                status="PARTIAL",
                compliance_percentage=78.0,
                controls=[
                    {"id": "1.1", "name": "Firewall Configuration", "status": "EFFECTIVE"},
                    {"id": "3.1", "name": "Cardholder Data Protection", "status": "NEEDS_IMPROVEMENT"},
                ],
                findings_count=5,
                open_findings=3,
                critical_findings=1,
            ),
            ComplianceFramework(
                framework_name="ISO 27001",
                version="2022",
                status="COMPLIANT",
                compliance_percentage=92.0,
                controls=[
                    {"id": "A.5.1", "name": "Information Security Policies", "status": "EFFECTIVE"},
                    {"id": "A.8.1", "name": "Asset Management", "status": "EFFECTIVE"},
                ],
                findings_count=1,
                open_findings=0,
                critical_findings=0,
            ),
        ]
        
        for fw in frameworks:
            self._frameworks[fw.framework_id] = fw
    
    def store_metric(self, metric: GovernanceMetric) -> GovernanceMetric:
        """Store a governance metric."""
        with self._lock:
            self._metrics[metric.metric_id] = metric
            self._metrics.move_to_end(metric.metric_id)
            
            while len(self._metrics) > self._max_size:
                self._metrics.popitem(last=False)
        
        return metric
    
    def get_metric(self, metric_id: str) -> Optional[GovernanceMetric]:
        """Get metric by ID."""
        return self._metrics.get(metric_id)
    
    def get_recent_metrics(self, limit: int = 100) -> List[GovernanceMetric]:
        """Get recent metrics."""
        metrics = list(self._metrics.values())[-limit:]
        return sorted(metrics, key=lambda m: m.timestamp, reverse=True)
    
    def store_scorecard(self, scorecard: RiskScorecard) -> RiskScorecard:
        """Store risk scorecard."""
        with self._lock:
            self._scorecards[scorecard.scorecard_id] = scorecard
        
        return scorecard
    
    def get_scorecard(self, scorecard_id: str) -> Optional[RiskScorecard]:
        """Get scorecard by ID."""
        return self._scorecards.get(scorecard_id)
    
    def get_latest_scorecard(self) -> Optional[RiskScorecard]:
        """Get the latest risk scorecard."""
        if not self._scorecards:
            return None
        return max(self._scorecards.values(), key=lambda s: s.created_at)
    
    def store_framework(self, framework: ComplianceFramework) -> ComplianceFramework:
        """Store compliance framework."""
        with self._lock:
            self._frameworks[framework.framework_id] = framework
        
        return framework
    
    def get_framework(self, framework_id: str) -> Optional[ComplianceFramework]:
        """Get framework by ID."""
        return self._frameworks.get(framework_id)
    
    def get_all_frameworks(self) -> List[ComplianceFramework]:
        """Get all compliance frameworks."""
        return list(self._frameworks.values())
    
    def store_assessment(self, assessment: ControlAssessment) -> ControlAssessment:
        """Store control assessment."""
        with self._lock:
            self._assessments[assessment.assessment_id] = assessment
        
        return assessment
    
    def get_assessment(self, assessment_id: str) -> Optional[ControlAssessment]:
        """Get assessment by ID."""
        return self._assessments.get(assessment_id)
    
    def store_finding(self, finding: AuditFinding) -> AuditFinding:
        """Store audit finding."""
        with self._lock:
            self._findings[finding.finding_id] = finding
        
        return finding
    
    def get_finding(self, finding_id: str) -> Optional[AuditFinding]:
        """Get finding by ID."""
        return self._findings.get(finding_id)
    
    def get_open_findings(self) -> List[AuditFinding]:
        """Get all open audit findings."""
        return [f for f in self._findings.values() if f.status == "OPEN"]
    
    def get_critical_findings(self) -> List[AuditFinding]:
        """Get all critical audit findings."""
        return [f for f in self._findings.values() if f.severity.value == "CRITICAL"]
    
    def store_dashboard(self, dashboard: ExecutiveDashboard) -> ExecutiveDashboard:
        """Store executive dashboard."""
        with self._lock:
            self._dashboards[dashboard.dashboard_id] = dashboard
        
        return dashboard
    
    def get_dashboard(self, dashboard_id: str) -> Optional[ExecutiveDashboard]:
        """Get dashboard by ID."""
        return self._dashboards.get(dashboard_id)
    
    def store_report(self, report: GovernanceReport) -> GovernanceReport:
        """Store governance report."""
        with self._lock:
            self._reports[report.report_id] = report
            self._reports.move_to_end(report.report_id)
            
            while len(self._reports) > self._max_size:
                self._reports.popitem(last=False)
        
        return report
    
    def get_report(self, report_id: str) -> Optional[GovernanceReport]:
        """Get report by ID."""
        return self._reports.get(report_id)
    
    def get_recent_reports(self, report_type: str = None, limit: int = 50) -> List[GovernanceReport]:
        """Get recent reports, optionally filtered by type."""
        reports = list(self._reports.values())
        if report_type:
            reports = [r for r in reports if r.report_type.value == report_type]
        return sorted(reports, key=lambda r: r.created_at, reverse=True)[:limit]
    
    def store_violation(self, violation: PolicyViolation) -> PolicyViolation:
        """Store policy violation."""
        with self._lock:
            self._violations[violation.violation_id] = violation
        
        return violation
    
    def get_violation(self, violation_id: str) -> Optional[PolicyViolation]:
        """Get violation by ID."""
        return self._violations.get(violation_id)
    
    def get_open_violations(self) -> List[PolicyViolation]:
        """Get all open violations."""
        return [v for v in self._violations.values() if v.status == "OPEN"]
    
    def store_threshold(self, threshold: RiskThreshold) -> RiskThreshold:
        """Store risk threshold."""
        with self._lock:
            self._thresholds[threshold.threshold_id] = threshold
        
        return threshold
    
    def get_threshold(self, threshold_id: str) -> Optional[RiskThreshold]:
        """Get threshold by ID."""
        return self._thresholds.get(threshold_id)
    
    def get_enabled_thresholds(self) -> List[RiskThreshold]:
        """Get all enabled thresholds."""
        return [t for t in self._thresholds.values() if t.enabled]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get store statistics."""
        return {
            "metrics_stored": len(self._metrics),
            "scorecards_stored": len(self._scorecards),
            "frameworks_stored": len(self._frameworks),
            "assessments_stored": len(self._assessments),
            "findings_stored": len(self._findings),
            "open_findings": len(self.get_open_findings()),
            "critical_findings": len(self.get_critical_findings()),
            "dashboards_stored": len(self._dashboards),
            "reports_stored": len(self._reports),
            "violations_stored": len(self._violations),
            "open_violations": len(self.get_open_violations()),
            "thresholds_stored": len(self._thresholds),
        }


# Global singleton
_governance_store: Optional[GovernanceStore] = None


def get_governance_store() -> GovernanceStore:
    """Get or create the singleton governance store instance."""
    global _governance_store
    
    if _governance_store is None:
        _governance_store = GovernanceStore()
    return _governance_store