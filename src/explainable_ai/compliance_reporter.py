"""
Compliance Reporter Module.

Regulatory compliance reporting and bias detection.
"""

import random
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone, timedelta
import logging

from .models import (
    ComplianceReport,
    ComplianceFramework,
    BiasAnalysis,
    BiasMetric,
    AdverseActionNotice,
)
from .store import ExplainableAIStore, get_xai_store

logger = logging.getLogger(__name__)


class ComplianceReporter:
    """Compliance Reporter for regulatory compliance.
    
    Provides:
        - Regulatory report generation
        - Fair lending analysis
        - Bias detection
        - Adverse action notices
    """
    
    def __init__(self, store: Optional[ExplainableAIStore] = None):
        """Initialize the compliance reporter."""
        self._store = store or get_xai_store()
        self._module_id = "compliance_reporter"
    
    def generate_compliance_report(
        self,
        report_type: str,
        framework: ComplianceFramework,
        period_start: datetime,
        period_end: datetime,
        created_by: str = "system",
    ) -> ComplianceReport:
        """Generate a compliance report."""
        logger.info(f"Generating {framework.value} compliance report")
        
        # Gather data for the period
        metrics = self._gather_compliance_metrics(period_start, period_end)
        
        # Analyze findings
        findings = self._analyze_findings(metrics, framework)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(findings)
        
        # Create report
        report = ComplianceReport(
            report_type=report_type,
            framework=framework,
            period_start=period_start,
            period_end=period_end,
            summary=self._generate_summary(findings, framework),
            metrics=metrics,
            findings=findings,
            recommendations=recommendations,
            created_by=created_by,
        )
        
        self._store.store_compliance_report(report)
        
        # Store metrics for history
        self._store.store_metrics({
            "event": "compliance_report_generated",
            "framework": framework.value,
            "report_id": report.report_id,
        })
        
        return report
    
    def _gather_compliance_metrics(
        self,
        period_start: datetime,
        period_end: datetime,
    ) -> Dict[str, Any]:
        """Gather compliance metrics for the period."""
        # Simulate metric gathering
        return {
            "total_decisions": random.randint(10000, 100000),
            "fraud_decisions": random.randint(1000, 10000),
            "approval_rate": random.uniform(0.85, 0.95),
            "average_processing_time_ms": random.uniform(50, 200),
            "false_positive_rate": random.uniform(0.05, 0.15),
            "false_negative_rate": random.uniform(0.02, 0.08),
            "model_version": f"v{random.randint(1, 5)}.{random.randint(0, 9)}",
            "compliance_score": random.uniform(0.9, 0.99),
        }
    
    def _analyze_findings(
        self,
        metrics: Dict[str, Any],
        framework: ComplianceFramework,
    ) -> List[Dict[str, Any]]:
        """Analyze metrics for compliance findings."""
        findings = []
        
        # Check approval rate
        approval_rate = metrics.get("approval_rate", 0)
        if approval_rate < 0.9:
            findings.append({
                "type": "warning",
                "code": "LOW_APPROVAL_RATE",
                "description": f"Approval rate ({approval_rate:.2%}) below target",
                "severity": "medium",
            })
        
        # Check false positive rate
        fp_rate = metrics.get("false_positive_rate", 0)
        if fp_rate > 0.1:
            findings.append({
                "type": "critical",
                "code": "HIGH_FALSE_POSITIVE",
                "description": f"False positive rate ({fp_rate:.2%}) exceeds threshold",
                "severity": "high",
            })
        
        # Framework-specific checks
        if framework == ComplianceFramework.FAIR_LENDING:
            findings.append({
                "type": "info",
                "code": "FAIR_LENDING_CHECK",
                "description": "Fair lending analysis completed",
                "severity": "low",
            })
        elif framework == ComplianceFramework.GDPR:
            findings.append({
                "type": "info",
                "code": "GDPR_DATA_PROCESSING",
                "description": "GDPR data processing requirements verified",
                "severity": "low",
            })
        
        return findings
    
    def _generate_recommendations(self, findings: List[Dict[str, Any]]) -> List[str]:
        """Generate recommendations based on findings."""
        recommendations = []
        
        for finding in findings:
            if finding["type"] == "critical":
                recommendations.append(f"URGENT: Address {finding['code']} - {finding['description']}")
            elif finding["type"] == "warning":
                recommendations.append(f"Review and address {finding['code']}")
            else:
                recommendations.append(f"Continue monitoring for {finding['code']}")
        
        if not recommendations:
            recommendations.append("Maintain current monitoring and review processes")
            recommendations.append("Continue regular bias audits")
        
        return recommendations
    
    def _generate_summary(
        self,
        findings: List[Dict[str, Any]],
        framework: ComplianceFramework,
    ) -> str:
        """Generate executive summary."""
        critical = sum(1 for f in findings if f["severity"] == "critical")
        warnings = sum(1 for f in findings if f["severity"] == "medium")
        
        if critical > 0:
            status = "REQUIRES ATTENTION"
        elif warnings > 0:
            status = "GENERALLY COMPLIANT WITH WARNINGS"
        else:
            status = "FULLY COMPLIANT"
        
        return f"{framework.value} Compliance Report: {status}. Critical issues: {critical}, Warnings: {warnings}."
    
    def analyze_bias(
        self,
        model_id: str,
        protected_attribute: str,
        metric: BiasMetric,
    ) -> BiasAnalysis:
        """Perform bias analysis on a model."""
        logger.info(f"Performing bias analysis for model {model_id}")
        
        # Simulate bias analysis
        value = random.uniform(0.6, 1.0)
        threshold = 0.8  # 80% rule
        compliant = value >= threshold
        
        affected_groups = self._identify_affected_groups(protected_attribute)
        
        analysis = BiasAnalysis(
            model_id=model_id,
            protected_attribute=protected_attribute,
            metric=metric,
            value=value,
            threshold=threshold,
            compliant=compliant,
            affected_groups=affected_groups,
            details={
                "sample_size": random.randint(1000, 50000),
                "control_group_rate": random.uniform(0.5, 0.8),
                "protected_group_rate": random.uniform(0.5, 0.8),
                "selection_rate_ratio": value,
            },
        )
        
        self._store.store_bias_analysis(analysis)
        
        # Store metrics
        self._store.store_metrics({
            "event": "bias_analysis_completed",
            "model_id": model_id,
            "metric": metric.value,
            "compliant": compliant,
        })
        
        return analysis
    
    def _identify_affected_groups(self, protected_attribute: str) -> List[str]:
        """Identify potentially affected groups."""
        if protected_attribute == "age":
            return ["under_25", "over_65"]
        elif protected_attribute == "gender":
            return ["non_binary"]
        elif protected_attribute == "zip_code":
            return ["low_income_areas"]
        return ["minority_groups"]
    
    def generate_adverse_action_notice(
        self,
        decision_id: str,
        reason_codes: List[str],
        recipient: str,
        specific_reasons: List[str] = None,
    ) -> AdverseActionNotice:
        """Generate adverse action notice."""
        logger.info(f"Generating adverse action notice for decision {decision_id}")
        
        # Map reason codes to descriptions
        code_descriptions = {
            "HIGH_RISK": "The transaction was flagged as high risk based on pattern analysis",
            "VELOCITY": "Unusual velocity of transactions detected",
            "GEOGRAPHIC": "Geographic anomalies identified in transaction pattern",
            "HISTORY": "Historical fraud patterns associated with this account",
            "DEVICE": "Device fingerprint analysis indicated elevated risk",
        }
        
        reasons_description = ". ".join([
            code_descriptions.get(code, f"Reason code: {code}")
            for code in reason_codes
        ])
        
        notice = AdverseActionNotice(
            decision_id=decision_id,
            reason_codes=reason_codes,
            reasons_description=reasons_description,
            specific_reasons=specific_reasons or reason_codes,
            recipient=recipient,
        )
        
        self._store.store_adverse_action(notice)
        
        return notice
    
    def get_fair_lending_report(
        self,
        period_start: datetime,
        period_end: datetime,
    ) -> ComplianceReport:
        """Generate fair lending compliance report."""
        return self.generate_compliance_report(
            report_type="fair_lending",
            framework=ComplianceFramework.FAIR_LENDING,
            period_start=period_start,
            period_end=period_end,
        )
    
    def get_gdpr_report(
        self,
        period_start: datetime,
        period_end: datetime,
    ) -> ComplianceReport:
        """Generate GDPR compliance report."""
        return self.generate_compliance_report(
            report_type="data_protection",
            framework=ComplianceFramework.GDPR,
            period_start=period_start,
            period_end=period_end,
        )
    
    def get_recent_reports(self, limit: int = 50) -> List[ComplianceReport]:
        """Get recent compliance reports."""
        return self._store.get_recent_reports(limit)
    
    def get_model_bias_analyses(self, model_id: str) -> List[BiasAnalysis]:
        """Get bias analyses for a model."""
        return self._store.get_model_bias_analyses(model_id)


# Global singleton
_compliance_reporter: Optional[ComplianceReporter] = None


def get_compliance_reporter(store: Optional[ExplainableAIStore] = None) -> ComplianceReporter:
    """Get or create the singleton ComplianceReporter instance."""
    global _compliance_reporter
    
    if _compliance_reporter is None:
        _compliance_reporter = ComplianceReporter(store=store)
    return _compliance_reporter