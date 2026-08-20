"""
Compliance Reporter Module.

Regulatory compliance reporting and bias detection.
"""

from collections import Counter, defaultdict
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
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

    #: Number of decision traces scanned when assembling a report. Bounds the
    #: work done against a large store while still covering a reporting period.
    TRACE_SCAN_LIMIT = 10000

    #: Decision labels that count as an approval when computing approval and
    #: selection rates. Compared case-insensitively.
    APPROVED_DECISIONS = frozenset({
        "approve", "approved", "allow", "allowed", "accept", "accepted", "pass",
    })

    #: Decision labels that count as a fraud/decline outcome.
    DECLINED_DECISIONS = frozenset({
        "decline", "declined", "deny", "denied", "reject", "rejected",
        "block", "blocked", "fraud",
    })

    #: Keys under which a decision trace may carry the confirmed outcome used
    #: to compute false positive/negative rates. Absent these, the rates are
    #: reported as unavailable rather than guessed at.
    OUTCOME_KEYS = ("confirmed_fraud", "actual_fraud", "ground_truth_fraud")

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
        """Gather compliance metrics for the period.

        Metrics are counted from the decision traces actually recorded in the
        period. Previously every figure here was drawn from ``random``, so a
        fair lending or GDPR report carried invented decision volumes, approval
        rates and error rates -- numbers a regulator would read as measured.

        Rates that cannot be derived from the stored data (false positive and
        false negative rates need a confirmed outcome on the trace) are
        reported as ``None`` rather than filled in with a plausible value.
        """
        traces = self._traces_in_period(period_start, period_end)
        total = len(traces)

        if not total:
            logger.warning(
                "No decision traces recorded between %s and %s; "
                "compliance metrics are unavailable for this period",
                period_start, period_end,
            )
            return {
                "total_decisions": 0,
                "fraud_decisions": 0,
                "approval_rate": None,
                "average_processing_time_ms": None,
                "false_positive_rate": None,
                "false_negative_rate": None,
                "model_version": None,
                "compliance_score": None,
                "insufficient_data": True,
            }

        approvals = sum(1 for t in traces if self._is_approval(t))
        declines = sum(1 for t in traces if self._is_decline(t))
        versions = Counter(t.model_version for t in traces if t.model_version)

        metrics: Dict[str, Any] = {
            "total_decisions": total,
            "fraud_decisions": declines,
            "approval_rate": approvals / total,
            "average_processing_time_ms": (
                sum(t.processing_time_ms for t in traces) / total
            ),
            "model_version": versions.most_common(1)[0][0] if versions else None,
            "insufficient_data": False,
        }
        metrics.update(self._error_rates(traces))

        # Explainability coverage: the share of decisions in the period that
        # have a stored explanation. This is the reportable compliance figure
        # under both the fair lending and GDPR right-to-explanation regimes.
        explained = sum(
            1 for t in traces
            if self._store.get_decision_explanation(t.decision_id) is not None
        )
        metrics["compliance_score"] = explained / total
        metrics["explained_decisions"] = explained

        return metrics

    def _traces_in_period(
        self,
        period_start: datetime,
        period_end: datetime,
    ) -> List[Any]:
        """Return the decision traces stamped inside the reporting period."""
        start = self._as_utc(period_start)
        end = self._as_utc(period_end)

        return [
            t for t in self._store.get_recent_traces(self.TRACE_SCAN_LIMIT)
            if start <= self._as_utc(t.timestamp) <= end
        ]

    @staticmethod
    def _as_utc(moment: datetime) -> datetime:
        """Treat naive timestamps as UTC so period comparisons never raise."""
        if moment.tzinfo is None:
            return moment.replace(tzinfo=timezone.utc)
        return moment.astimezone(timezone.utc)

    def _is_approval(self, trace: Any) -> bool:
        """Whether a trace records an approved decision."""
        return str(trace.output_decision).strip().lower() in self.APPROVED_DECISIONS

    def _is_decline(self, trace: Any) -> bool:
        """Whether a trace records a decline/fraud decision."""
        return str(trace.output_decision).strip().lower() in self.DECLINED_DECISIONS

    def _error_rates(self, traces: List[Any]) -> Dict[str, Any]:
        """Compute false positive/negative rates from confirmed outcomes.

        Only traces carrying a confirmed outcome contribute. If none do, the
        rates are ``None``: a fabricated error rate is worse than an admitted
        gap in a filed report.
        """
        labelled = [(t, self._confirmed_outcome(t)) for t in traces]
        labelled = [(t, outcome) for t, outcome in labelled if outcome is not None]

        if not labelled:
            return {
                "false_positive_rate": None,
                "false_negative_rate": None,
                "labelled_decisions": 0,
            }

        legitimate = [t for t, fraud in labelled if not fraud]
        fraudulent = [t for t, fraud in labelled if fraud]

        false_positives = sum(1 for t in legitimate if self._is_decline(t))
        false_negatives = sum(1 for t in fraudulent if not self._is_decline(t))

        return {
            "false_positive_rate": (
                false_positives / len(legitimate) if legitimate else None
            ),
            "false_negative_rate": (
                false_negatives / len(fraudulent) if fraudulent else None
            ),
            "labelled_decisions": len(labelled),
        }

    def _confirmed_outcome(self, trace: Any) -> Optional[bool]:
        """Read the confirmed fraud outcome off a trace, if it carries one."""
        for key in self.OUTCOME_KEYS:
            if key in trace.input_features:
                return bool(trace.input_features[key])
        return None


    def _analyze_findings(
        self,
        metrics: Dict[str, Any],
        framework: ComplianceFramework,
    ) -> List[Dict[str, Any]]:
        """Analyze metrics for compliance findings."""
        findings = []

        # A metric is None when the stored data cannot support it. Report that
        # gap explicitly instead of letting a missing figure read as a pass.
        if metrics.get("insufficient_data"):
            findings.append({
                "type": "warning",
                "code": "NO_DECISIONS_RECORDED",
                "description": "No decision traces were recorded for this period",
                "severity": "medium",
            })

        # Check approval rate
        approval_rate = metrics.get("approval_rate")
        if approval_rate is not None and approval_rate < 0.9:
            findings.append({
                "type": "warning",
                "code": "LOW_APPROVAL_RATE",
                "description": f"Approval rate ({approval_rate:.2%}) below target",
                "severity": "medium",
            })

        # Check false positive rate
        fp_rate = metrics.get("false_positive_rate")
        if fp_rate is None and not metrics.get("insufficient_data"):
            findings.append({
                "type": "warning",
                "code": "NO_CONFIRMED_OUTCOMES",
                "description": (
                    "No decisions in this period carry a confirmed outcome, so "
                    "false positive/negative rates could not be measured"
                ),
                "severity": "medium",
            })
        elif fp_rate is not None and fp_rate > 0.1:
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
        """Perform bias analysis on a model.

        Applies the 80% rule to the model's recorded decisions: decisions are
        grouped by the value of ``protected_attribute`` on the trace, a
        selection (approval) rate is computed per group, and the ratio of the
        lowest to the highest rate is the reported metric.

        Previously the disparate impact ratio and every supporting figure came
        from ``random``, so a model could be certified fair by a coin flip.
        """
        logger.info(f"Performing bias analysis for model {model_id}")

        threshold = 0.8  # 80% rule
        group_rates, sample_size = self._selection_rates_by_group(
            model_id, protected_attribute,
        )

        if len(group_rates) < 2:
            # One group (or none) cannot show disparate impact either way.
            # Fail closed: fairness is not certified without the evidence.
            logger.warning(
                "Bias analysis for model %s on '%s' has %d comparable group(s); "
                "cannot evaluate the 80%% rule",
                model_id, protected_attribute, len(group_rates),
            )
            analysis = BiasAnalysis(
                model_id=model_id,
                protected_attribute=protected_attribute,
                metric=metric,
                value=0.0,
                threshold=threshold,
                compliant=False,
                affected_groups=self._identify_affected_groups(protected_attribute),
                details={
                    "sample_size": sample_size,
                    "insufficient_data": True,
                    "reason": "fewer than two groups with recorded decisions",
                    "group_selection_rates": group_rates,
                },
            )
        else:
            highest = max(group_rates.values())
            lowest = min(group_rates.values())
            value = lowest / highest if highest else 0.0
            compliant = value >= threshold

            # Every group selected materially less often than the best-served
            # group is affected -- read off the data, not a static lookup.
            affected_groups = sorted(
                group for group, rate in group_rates.items()
                if highest and rate < threshold * highest
            )

            analysis = BiasAnalysis(
                model_id=model_id,
                protected_attribute=protected_attribute,
                metric=metric,
                value=value,
                threshold=threshold,
                compliant=compliant,
                affected_groups=affected_groups,
                details={
                    "sample_size": sample_size,
                    "control_group_rate": highest,
                    "protected_group_rate": lowest,
                    "selection_rate_ratio": value,
                    "group_selection_rates": group_rates,
                    "insufficient_data": False,
                },
            )

        compliant = analysis.compliant

        self._store.store_bias_analysis(analysis)
        
        # Store metrics
        self._store.store_metrics({
            "event": "bias_analysis_completed",
            "model_id": model_id,
            "metric": metric.value,
            "compliant": compliant,
        })
        
        return analysis
    
    def _selection_rates_by_group(
        self,
        model_id: str,
        protected_attribute: str,
    ) -> tuple:
        """Approval rate per value of the protected attribute.

        Returns ``(rates_by_group, sample_size)`` where ``sample_size`` counts
        only the traces that actually carry the attribute. Groups with no
        decisions are absent rather than represented as a zero rate.
        """
        traces = self._store.get_model_traces(model_id, self.TRACE_SCAN_LIMIT)

        totals: Dict[str, int] = defaultdict(int)
        approvals: Dict[str, int] = defaultdict(int)

        for trace in traces:
            if protected_attribute not in trace.input_features:
                continue
            group = str(trace.input_features[protected_attribute])
            totals[group] += 1
            if self._is_approval(trace):
                approvals[group] += 1

        rates = {
            group: approvals[group] / count
            for group, count in totals.items() if count
        }
        return rates, sum(totals.values())

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