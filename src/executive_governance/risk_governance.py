"""
Risk Governance Module.

Provides enterprise risk management, risk scoring, and governance oversight.
"""

from statistics import mean, pstdev
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone, timedelta
import logging

from .models import (
    RiskScorecard,
    RiskLevel,
    GovernanceMetric,
    RiskThreshold,
)
from .store import GovernanceStore, get_governance_store

logger = logging.getLogger(__name__)


class RiskGovernanceModule:
    """Risk Governance for enterprise risk management.
    
    Provides:
        - Risk scorecard generation
        - Risk threshold monitoring
        - Risk trend analysis
        - Governance oversight
    """

    #: Risk categories reported on a scorecard, and the substrings matched
    #: against a finding's or violation's category to attribute it.
    RISK_CATEGORIES: Dict[str, tuple] = {
        "fraud_risk": ("fraud", "aml", "financial_crime"),
        "cyber_risk": ("cyber", "security", "intrusion", "malware"),
        # No bare "policy" keyword here: a PolicyViolation's name almost
        # always contains it, which would attribute every violation to
        # compliance risk on top of its real category.
        "compliance_risk": ("compliance", "regulatory", "privacy", "gdpr"),
        "operational_risk": ("operational", "process", "availability", "vendor"),
        "reputational_risk": ("reputation", "brand", "conduct", "customer"),
    }

    #: Severity weights used when an open item contributes to a category
    #: score. Mirrors the AuditFindingSeverity ladder.
    SEVERITY_WEIGHTS: Dict[str, float] = {
        "CRITICAL": 1.0,
        "HIGH": 0.75,
        "MEDIUM": 0.5,
        "LOW": 0.25,
        "INFO": 0.1,
    }

    #: Number of open items in one category at which volume pressure alone is
    #: treated as saturated. Above this, more items do not raise the score.
    VOLUME_SATURATION = 10

    #: Share of a category score that comes from the severity of its open
    #: items; the remainder comes from how many there are.
    SEVERITY_WEIGHT = 0.7

    #: Change in overall score between consecutive scorecards that counts as a
    #: real move rather than noise.
    TREND_DELTA = 0.05

    #: Percentage change over the comparison window that counts as a trend.
    TREND_PERCENT = 5.0

    #: Recorded metrics scanned when reconstructing a metric's history.
    HISTORY_SCAN_LIMIT = 5000

    def __init__(self, store: Optional[GovernanceStore] = None):
        """Initialize the risk governance module.
        
        Args:
            store: Optional governance store
        """
        self._store = store or get_governance_store()
        self._module_id = "risk_governance"
    
    def generate_risk_scorecard(
        self,
        period: str = "quarterly",
    ) -> RiskScorecard:
        """Generate enterprise risk scorecard.
        
        Args:
            period: Reporting period
            
        Returns:
            RiskScorecard
        """
        logger.info(f"Generating risk scorecard for {period}")

        # Score each category from the open findings and policy violations
        # attributed to it. Previously every category score, the overall trend
        # and every risk indicator came from ``random``, so a scorecard
        # presented to executives reflected nothing in the store.
        previous = self._store.get_latest_scorecard()
        risk_categories = self._score_categories()

        overall_score = sum(risk_categories.values()) / len(risk_categories)
        risk_level = self._calculate_risk_level(overall_score)

        scorecard = RiskScorecard(
            period=period,
            overall_risk_score=round(overall_score, 3),
            risk_level=risk_level,
            risk_categories=risk_categories,
            risk_trend=self._compare_scores(
                overall_score,
                previous.overall_risk_score if previous else None,
            ),
            key_risks=self._generate_key_risks(risk_categories, previous),
            risk_indicators=self._generate_risk_indicators(),
            mitigation_actions=self._generate_mitigation_actions(risk_categories),
            next_review_date=datetime.now(timezone.utc) + timedelta(days=30),
        )
        
        self._store.store_scorecard(scorecard)
        return scorecard
    
    def assess_entity_risk(
        self,
        entity_id: str,
        entity_type: str,
        risk_factors: Dict[str, float],
    ) -> Dict[str, Any]:
        """Assess risk for a specific entity.
        
        Args:
            entity_id: Entity identifier
            entity_type: Type of entity
            risk_factors: Risk factor scores
            
        Returns:
            Risk assessment result
        """
        logger.info(f"Assessing risk for {entity_type}: {entity_id}")
        
        # Calculate weighted risk score
        weights = {
            "transaction_history": 0.3,
            "device_fingerprint": 0.2,
            "behavioral_pattern": 0.25,
            "network_connections": 0.15,
            "historical_incidents": 0.1,
        }
        
        weighted_score = sum(
            risk_factors.get(factor, 0.5) * weights.get(factor, 0.1)
            for factor in risk_factors
        )
        
        risk_level = self._calculate_risk_level(weighted_score)
        
        return {
            "entity_id": entity_id,
            "entity_type": entity_type,
            "risk_score": round(weighted_score, 3),
            "risk_level": risk_level.value,
            "risk_factors": risk_factors,
            "top_risk_factors": self._get_top_risk_factors(risk_factors),
            "recommendation": self._generate_risk_recommendation(risk_level),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    
    def monitor_risk_thresholds(
        self,
        metrics: Dict[str, float],
    ) -> List[Dict[str, Any]]:
        """Monitor risk metrics against thresholds.
        
        Args:
            metrics: Current metric values
            
        Returns:
            List of threshold breaches
        """
        logger.info("Monitoring risk thresholds")
        
        thresholds = self._store.get_enabled_thresholds()
        breaches = []
        
        for threshold in thresholds:
            current_value = metrics.get(threshold.metric_name, 0)
            
            if current_value >= threshold.critical_level:
                breaches.append({
                    "metric": threshold.metric_name,
                    "current_value": current_value,
                    "threshold": threshold.critical_level,
                    "severity": "CRITICAL",
                    "action": threshold.action_required,
                    "notifications_sent": len(threshold.notification_list),
                })
            elif current_value >= threshold.warning_level:
                breaches.append({
                    "metric": threshold.metric_name,
                    "current_value": current_value,
                    "threshold": threshold.warning_level,
                    "severity": "WARNING",
                    "action": threshold.action_required,
                })
        
        return breaches
    
    def track_risk_trend(
        self,
        metric_name: str,
        period_days: int = 30,
    ) -> Dict[str, Any]:
        """Track risk metric trend.
        
        Args:
            metric_name: Metric to track
            period_days: Number of days to analyze
            
        Returns:
            Trend analysis
        """
        logger.info(f"Tracking trend for {metric_name}")

        # Read the metric's recorded history rather than inventing three points
        # and computing percentage changes between them, which is what this
        # did before -- the "trend" it reported was noise.
        history = [
            m for m in self._store.get_recent_metrics(self.HISTORY_SCAN_LIMIT)
            if m.name == metric_name
        ]

        if not history:
            logger.warning("No recorded history for metric '%s'", metric_name)
            return {
                "metric": metric_name,
                "current_value": None,
                "previous_7d": None,
                "previous_30d": None,
                "change_7d_percent": None,
                "change_30d_percent": None,
                "trend": "insufficient_history",
                "volatility": None,
                "observations": 0,
            }

        # get_recent_metrics returns newest first.
        now = datetime.now(timezone.utc)
        current = history[0].value
        previous_7d = self._baseline(history, now, 7)
        previous_30d = self._baseline(history, now, period_days)

        change_7d = self._percent_change(current, previous_7d)
        change_30d = self._percent_change(current, previous_30d)

        values = [m.value for m in history]

        return {
            "metric": metric_name,
            "current_value": round(current, 3),
            "previous_7d": round(previous_7d, 3) if previous_7d is not None else None,
            "previous_30d": round(previous_30d, 3) if previous_30d is not None else None,
            "change_7d_percent": round(change_7d, 2) if change_7d is not None else None,
            "change_30d_percent": round(change_30d, 2) if change_30d is not None else None,
            "trend": self._describe_change(change_30d),
            "volatility": round(pstdev(values), 3) if len(values) > 1 else 0.0,
            "observations": len(history),
        }

    def _baseline(
        self,
        history: List[GovernanceMetric],
        now: datetime,
        days: int,
    ) -> Optional[float]:
        """Mean of the observations recorded within the last ``days``."""
        cutoff = now - timedelta(days=days)
        window = [
            m.value for m in history
            if self._as_utc(m.timestamp) >= cutoff
        ]
        return mean(window) if window else None

    @staticmethod
    def _as_utc(moment: datetime) -> datetime:
        """Treat naive timestamps as UTC so window comparisons never raise."""
        if moment.tzinfo is None:
            return moment.replace(tzinfo=timezone.utc)
        return moment.astimezone(timezone.utc)

    @staticmethod
    def _percent_change(current: float, baseline: Optional[float]) -> Optional[float]:
        """Percentage change, guarding the divide-by-zero the old code had."""
        if baseline is None or baseline == 0:
            return None
        return ((current - baseline) / baseline) * 100

    def _describe_change(self, change_percent: Optional[float]) -> str:
        """Label a percentage change, or admit there is nothing to compare."""
        if change_percent is None:
            return "insufficient_history"
        if change_percent > self.TREND_PERCENT:
            return "increasing"
        if change_percent < -self.TREND_PERCENT:
            return "decreasing"
        return "stable"


    def create_risk_threshold(
        self,
        metric_name: str,
        warning_level: float,
        critical_level: float,
        action_required: str,
    ) -> RiskThreshold:
        """Create a risk threshold.
        
        Args:
            metric_name: Metric name
            warning_level: Warning threshold
            critical_level: Critical threshold
            action_required: Action to take
            
        Returns:
            RiskThreshold
        """
        threshold = RiskThreshold(
            metric_name=metric_name,
            warning_level=warning_level,
            critical_level=critical_level,
            action_required=action_required,
            notification_list=["ciso@company.com", "risk@company.com"],
        )
        
        self._store.store_threshold(threshold)
        return threshold
    
    def get_risk_summary(self) -> Dict[str, Any]:
        """Get overall risk summary."""
        latest_scorecard = self._store.get_latest_scorecard()
        
        if not latest_scorecard:
            # Generate if none exists
            latest_scorecard = self.generate_risk_scorecard()
        
        return {
            "overall_risk_score": latest_scorecard.overall_risk_score,
            "risk_level": latest_scorecard.risk_level.value,
            "risk_trend": latest_scorecard.risk_trend,
            "risk_categories": latest_scorecard.risk_categories,
            "key_risks_count": len(latest_scorecard.key_risks),
            "mitigation_actions_count": len(latest_scorecard.mitigation_actions),
            "next_review": latest_scorecard.next_review_date.isoformat() if latest_scorecard.next_review_date else None,
        }
    
    def _calculate_risk_level(self, score: float) -> RiskLevel:
        """Calculate risk level from score."""
        if score >= 0.8:
            return RiskLevel.CRITICAL
        elif score >= 0.6:
            return RiskLevel.HIGH
        elif score >= 0.4:
            return RiskLevel.MEDIUM
        elif score >= 0.2:
            return RiskLevel.LOW
        else:
            return RiskLevel.MINIMAL
    
    def _score_categories(self) -> Dict[str, float]:
        """Score each risk category from open governance items.

        A category's score blends the severity of its open findings and policy
        violations with how many there are. A category with nothing open scores
        zero -- absence of recorded risk, not an invented baseline.
        """
        findings = self._store.get_open_findings()
        violations = self._store.get_open_violations()

        scores = {}
        for category, keywords in self.RISK_CATEGORIES.items():
            severities = [
                self._severity_weight(f.severity)
                for f in findings if self._matches(f.category, keywords)
            ]
            # A finding's own risk_impact is a direct assessment; prefer it.
            impacts = [
                max(0.0, min(1.0, f.risk_impact))
                for f in findings if self._matches(f.category, keywords)
            ]
            severities.extend(
                self._severity_weight(v.severity)
                for v in violations if self._matches(v.policy_name, keywords)
            )

            if not severities:
                scores[category] = 0.0
                continue

            intensity = mean(impacts) if impacts else mean(severities)
            volume = min(1.0, len(severities) / self.VOLUME_SATURATION)
            score = (
                self.SEVERITY_WEIGHT * max(intensity, mean(severities))
                + (1 - self.SEVERITY_WEIGHT) * volume
            )
            scores[category] = round(min(1.0, score), 3)

        return scores

    @staticmethod
    def _matches(label: Optional[str], keywords: tuple) -> bool:
        """Whether a finding/policy label belongs to a risk category."""
        text = (label or "").lower()
        return any(keyword in text for keyword in keywords)

    def _severity_weight(self, severity: Any) -> float:
        """Numeric weight for a severity enum or string."""
        name = getattr(severity, "value", severity)
        return self.SEVERITY_WEIGHTS.get(str(name).upper(), 0.5)

    def _compare_scores(
        self,
        current: float,
        previous: Optional[float],
    ) -> str:
        """Describe the move between two scores.

        Without a prior scorecard there is no trend to report; saying so beats
        picking one of the three labels at random.
        """
        if previous is None:
            return "insufficient_history"
        if current - previous > self.TREND_DELTA:
            return "increasing"
        if previous - current > self.TREND_DELTA:
            return "decreasing"
        return "stable"

    def _generate_key_risks(
        self,
        categories: Dict[str, float],
        previous: Optional[RiskScorecard] = None,
    ) -> List[Dict[str, Any]]:
        """Generate key risks from categories.

        Only categories carrying recorded risk are reported; a category that
        scored zero is not a "key risk".
        """
        risks = []
        ranked = sorted(categories.items(), key=lambda x: x[1], reverse=True)

        for category, score in ranked[:3]:
            if score <= 0:
                continue
            prior = (previous.risk_categories or {}).get(category) if previous else None
            risks.append({
                "risk_category": category,
                "risk_score": round(score, 3),
                "risk_level": self._calculate_risk_level(score).value,
                "trend": self._compare_scores(score, prior),
                "recommended_action": self._get_risk_action(category),
            })
        return risks

    def _generate_risk_indicators(self) -> Dict[str, Any]:
        """Count risk indicators from the governance store.

        The previous indicator set (fraud attempts, suspicious transactions)
        was invented and had no source in this store at all. These are the
        indicators governance data can actually support.
        """
        open_findings = self._store.get_open_findings()
        open_violations = self._store.get_open_violations()

        # An entity is high risk if any open finding or violation names it.
        high_risk_entities = {
            entity for f in open_findings for entity in f.affected_entities
        }
        high_risk_entities.update(v.entity_id for v in open_violations)

        frameworks = self._store.get_all_frameworks()

        return {
            "open_findings": len(open_findings),
            "critical_findings": len(self._store.get_critical_findings()),
            "open_policy_violations": len(open_violations),
            "high_risk_entities": len(high_risk_entities),
            "compliance_gaps": sum(f.open_findings for f in frameworks),
            "frameworks_below_full_compliance": sum(
                1 for f in frameworks if f.compliance_percentage < 100
            ),
        }


    def _generate_mitigation_actions(self, categories: Dict[str, float]) -> List[str]:
        """Generate mitigation actions based on risk categories."""
        actions = []
        
        if categories.get("fraud_risk", 0) > 0.6:
            actions.append("Enhance fraud detection rules")
            actions.append("Implement additional monitoring")
        
        if categories.get("cyber_risk", 0) > 0.5:
            actions.append("Review security controls")
            actions.append("Update threat detection")
        
        if categories.get("compliance_risk", 0) > 0.4:
            actions.append("Complete compliance gap assessment")
            actions.append("Update control documentation")
        
        return actions
    
    def _get_top_risk_factors(self, factors: Dict[str, float]) -> List[Dict[str, Any]]:
        """Get top risk factors."""
        sorted_factors = sorted(factors.items(), key=lambda x: x[1], reverse=True)[:3]
        return [{"factor": k, "score": round(v, 3)} for k, v in sorted_factors]
    
    def _generate_risk_recommendation(self, level: RiskLevel) -> str:
        """Generate recommendation based on risk level."""
        recommendations = {
            RiskLevel.CRITICAL: "Immediate action required - escalate to executive management",
            RiskLevel.HIGH: "High priority review required within 24 hours",
            RiskLevel.MEDIUM: "Review required within 7 days",
            RiskLevel.LOW: "Monitor and review in next scheduled assessment",
            RiskLevel.MINIMAL: "Continue routine monitoring",
        }
        return recommendations.get(level, "Standard review process")
    
    def _get_risk_action(self, category: str) -> str:
        """Get recommended action for risk category."""
        actions = {
            "fraud_risk": "Review and enhance fraud detection controls",
            "cyber_risk": "Conduct security assessment and patching",
            "compliance_risk": "Complete compliance gap remediation",
            "operational_risk": "Review operational procedures",
            "reputational_risk": "Develop communication and response plan",
        }
        return actions.get(category, "Standard risk monitoring")


# Global singleton
_risk_governance: Optional[RiskGovernanceModule] = None


def get_risk_governance_module(store: Optional[GovernanceStore] = None) -> RiskGovernanceModule:
    """Get or create the singleton RiskGovernanceModule instance."""
    global _risk_governance
    
    if _risk_governance is None:
        _risk_governance = RiskGovernanceModule(store=store)
    return _risk_governance