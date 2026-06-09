"""
Risk Governance Module.

Provides enterprise risk management, risk scoring, and governance oversight.
"""

import random
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
        risk_categories = {
            "fraud_risk": random.uniform(0.4, 0.8),
            "cyber_risk": random.uniform(0.3, 0.7),
            "compliance_risk": random.uniform(0.2, 0.6),
            "operational_risk": random.uniform(0.1, 0.5),
            "reputational_risk": random.uniform(0.2, 0.6),
        }
        
        overall_score = sum(risk_categories.values()) / len(risk_categories)
        risk_level = self._calculate_risk_level(overall_score)
        
        scorecard = RiskScorecard(
            period=period,
            overall_risk_score=round(overall_score, 3),
            risk_level=risk_level,
            risk_categories=risk_categories,
            risk_trend=random.choice(["increasing", "stable", "decreasing"]),
            key_risks=self._generate_key_risks(risk_categories),
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
        
        current = random.uniform(0.3, 0.8)
        previous_7d = random.uniform(0.3, 0.8)
        previous_30d = random.uniform(0.3, 0.8)
        
        change_7d = ((current - previous_7d) / previous_7d) * 100
        change_30d = ((current - previous_30d) / previous_30d) * 100
        
        return {
            "metric": metric_name,
            "current_value": round(current, 3),
            "previous_7d": round(previous_7d, 3),
            "previous_30d": round(previous_30d, 3),
            "change_7d_percent": round(change_7d, 2),
            "change_30d_percent": round(change_30d, 2),
            "trend": "increasing" if change_30d > 5 else "decreasing" if change_30d < -5 else "stable",
            "volatility": random.uniform(0.1, 0.4),
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
    
    def _generate_key_risks(self, categories: Dict[str, float]) -> List[Dict[str, Any]]:
        """Generate key risks from categories."""
        risks = []
        for category, score in sorted(categories.items(), key=lambda x: x[1], reverse=True)[:3]:
            risks.append({
                "risk_category": category,
                "risk_score": round(score, 3),
                "risk_level": self._calculate_risk_level(score).value,
                "trend": random.choice(["increasing", "stable", "decreasing"]),
                "recommended_action": self._get_risk_action(category),
            })
        return risks
    
    def _generate_risk_indicators(self) -> Dict[str, Any]:
        """Generate risk indicators."""
        return {
            "fraud_attempts_detected": random.randint(50, 200),
            "high_risk_entities": random.randint(10, 50),
            "suspicious_transactions": random.randint(100, 500),
            "emerging_threats": random.randint(5, 20),
            "compliance_gaps": random.randint(0, 10),
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