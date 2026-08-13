"""
Risk Governance Module.

Provides enterprise risk management, risk scoring, and governance oversight.
"""

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
        
        # Calculate category risk scores
        risk_categories = self._compute_risk_categories()
        overall_score = sum(risk_categories.values()) / len(risk_categories)
        risk_level = self._calculate_risk_level(overall_score)
        risk_trend = self._compute_risk_trend(overall_score)
        
        scorecard = RiskScorecard(
            period=period,
            overall_risk_score=round(overall_score, 3),
            risk_level=risk_level,
            risk_categories=risk_categories,
            risk_trend=risk_trend,
            key_risks=self._generate_key_risks(risk_categories, risk_trend),
            risk_indicators=self._generate_risk_indicators(risk_categories),
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
        
        now = datetime.now(timezone.utc)
        latest = self._store.get_latest_scorecard()
        current = latest.risk_categories.get(metric_name, 0.0) if latest else 0.0
        
        recent_week = self._store.get_scorecards_since(now - timedelta(days=7))
        recent_period = self._store.get_scorecards_since(now - timedelta(days=period_days))
        previous_7d = recent_week[0].risk_categories.get(metric_name, current) if recent_week else current
        previous_30d = recent_period[0].risk_categories.get(metric_name, current) if recent_period else current
        
        change_7d = ((current - previous_7d) / previous_7d * 100) if previous_7d else 0.0
        change_30d = ((current - previous_30d) / previous_30d * 100) if previous_30d else 0.0
        
        return {
            "metric": metric_name,
            "current_value": round(current, 3),
            "previous_7d": round(previous_7d, 3),
            "previous_30d": round(previous_30d, 3),
            "change_7d_percent": round(change_7d, 2),
            "change_30d_percent": round(change_30d, 2),
            "trend": "increasing" if change_30d > 5 else "decreasing" if change_30d < -5 else "stable",
            "volatility": round(abs(change_7d - change_30d) / 100, 3),
        }
    
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

    def _compute_risk_categories(self) -> Dict[str, float]:
        """Derive risk category scores from open findings and compliance data."""
        findings = self._store.get_open_findings()
        critical = len(self._store.get_critical_findings())
        frameworks = self._store.get_all_frameworks()
        compliance_gap = (
            1 - sum(f.compliance_percentage for f in frameworks) / len(frameworks) / 100
            if frameworks else 0.3
        )
        finding_pressure = min(1.0, len(findings) / 20 + critical / 5)
            
        return {
            "fraud_risk": round(min(1.0, 0.2 + finding_pressure), 3),
            "cyber_risk": round(min(1.0, 0.2 + critical * 0.1), 3),
            "compliance_risk": round(min(1.0, compliance_gap), 3),
            "operational_risk": round(min(1.0, 0.15 + finding_pressure * 0.6), 3),
            "reputational_risk": round(min(1.0, 0.15 + critical * 0.08), 3),
        }
        
    def _compute_risk_trend(self, overall_score: float) -> str:
        """Compare against the last stored scorecard to determine trend."""
        previous = self._store.get_latest_scorecard()
        if previous is None or abs(overall_score - previous.overall_risk_score) < 0.02:
            return "stable"
        return "increasing" if overall_score > previous.overall_risk_score else "decreasing"

    def _generate_key_risks(self, categories: Dict[str, float], risk_trend: str) -> List[Dict[str, Any]]:
        """Generate key risks from categories."""
        risks = []
        for category, score in sorted(categories.items(), key=lambda x: x[1], reverse=True)[:3]:
            risks.append({
                "risk_category": category,
                "risk_score": round(score, 3),
                "risk_level": self._calculate_risk_level(score).value,
                "trend": risk_trend,
                "recommended_action": self._get_risk_action(category),
            })
        return risks
    
    def _generate_risk_indicators(self, categories: Dict[str, float]) -> Dict[str, Any]:
        """Generate risk indicators from current risk data."""
        findings = self._store.get_open_findings()
        return {
            "fraud_attempts_detected": int(categories["fraud_risk"] * 100),
            "high_risk_entities": len([f for f in findings if f.risk_impact >= 0.7]),
            "suspicious_transactions": int(categories["fraud_risk"] * 200),
            "emerging_threats": int(categories["cyber_risk"] * 20),
            "compliance_gaps": len(self._store.get_open_violations()),
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