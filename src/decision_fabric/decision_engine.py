"""
Decision Engine
AI-powered decision evaluation and explanation.
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

from .models import (
    Decision,
    DecisionType,
    DecisionStatus,
    DecisionConfidence,
    DecisionExplanation,
    PolicyRule,
    DecisionAudit,
)


class AIReasoningLayer:
    """AI reasoning for decisions."""
    
    def evaluate(
        self,
        context: Dict[str, Any],
        decision_type: DecisionType,
    ) -> Dict[str, Any]:
        """Evaluate a decision context."""
        risk_score = context.get("risk_score", 0.5)
        amount = context.get("amount", 0)
        
        factors = []
        reasoning = []
        
        if amount > 10000:
            factors.append({"name": "High Value Transaction", "impact": 0.3})
            reasoning.append("Transaction exceeds high-value threshold")
        
        if context.get("new_recipient"):
            factors.append({"name": "New Recipient", "impact": 0.2})
            reasoning.append("First-time recipient detected")
        
        if context.get("velocity_anomaly"):
            factors.append({"name": "Velocity Anomaly", "impact": 0.4})
            reasoning.append("Unusual transaction velocity pattern")
        
        if context.get("high_risk_country"):
            factors.append({"name": "High Risk Jurisdiction", "impact": 0.3})
            reasoning.append("Transaction involves high-risk country")
        
        confidence = min(1.0, 0.5 + len(factors) * 0.1)
        
        return {
            "factors": factors,
            "reasoning": reasoning,
            "confidence": confidence,
            "risk_indicators": len(factors),
        }


class PolicyIntelligenceEngine:
    """Policy evaluation engine."""
    
    def __init__(self):
        self.rules: Dict[str, PolicyRule] = {}
        self._initialize_default_rules()
    
    def _initialize_default_rules(self):
        """Initialize default policy rules."""
        rules = [
            PolicyRule(
                rule_id="rule-001",
                name="High Value Transaction Review",
                description="Require additional review for transactions over $10,000",
                decision_type=DecisionType.TRANSACTION_APPROVAL,
                conditions=[{"field": "amount", "operator": ">", "value": 10000}],
                actions=["ESCALATE", "ADD_REVIEWER"],
                priority=10,
            ),
            PolicyRule(
                rule_id="rule-002",
                name="Fraud Block",
                description="Block transactions with high fraud score",
                decision_type=DecisionType.FRAUD_APPROVAL,
                conditions=[{"field": "fraud_score", "operator": ">=", "value": 0.8}],
                actions=["BLOCK", "ALERT_SECURITY"],
                priority=100,
            ),
            PolicyRule(
                rule_id="rule-003",
                name="AML Alert",
                description="Alert for suspicious AML patterns",
                decision_type=DecisionType.AML_ALERT,
                conditions=[{"field": "aml_score", "operator": ">=", "value": 0.7}],
                actions=["FLAG", "CREATE_CASE"],
                priority=50,
            ),
        ]
        
        for rule in rules:
            self.rules[rule.rule_id] = rule
    
    def evaluate_rules(
        self,
        context: Dict[str, Any],
        decision_type: DecisionType,
    ) -> List[PolicyRule]:
        """Evaluate policy rules for a context."""
        matching_rules = []
        
        for rule in self.rules.values():
            if rule.decision_type != decision_type or not rule.enabled:
                continue
            
            if self._matches_conditions(context, rule.conditions):
                matching_rules.append(rule)
        
        return sorted(matching_rules, key=lambda r: r.priority, reverse=True)
    
    def _matches_conditions(
        self,
        context: Dict[str, Any],
        conditions: List[Dict[str, Any]],
    ) -> bool:
        """Check if context matches conditions."""
        for cond in conditions:
            field = cond.get("field")
            operator = cond.get("operator")
            value = cond.get("value")
            
            if field not in context:
                return False
            
            ctx_value = context[field]
            
            if operator == ">" and not (ctx_value > value):
                return False
            elif operator == ">=" and not (ctx_value >= value):
                return False
            elif operator == "<" and not (ctx_value < value):
                return False
            elif operator == "==" and not (ctx_value == value):
                return False
        
        return True
    
    def add_rule(self, rule: PolicyRule) -> str:
        """Add a new policy rule."""
        self.rules[rule.rule_id] = rule
        return rule.rule_id


class DecisionEngine:
    """Main decision engine."""
    
    def __init__(self):
        self.decisions: Dict[str, Decision] = {}
        self.reasoning = AIReasoningLayer()
        self.policy_engine = PolicyIntelligenceEngine()
        self.audit_log: List[DecisionAudit] = []
    
    def evaluate(
        self,
        decision_type: DecisionType,
        context: Dict[str, Any],
        decided_by: str = "SYSTEM",
    ) -> Decision:
        """Evaluate a decision."""
        decision_id = str(uuid4())
        
        reasoning_result = self.reasoning.evaluate(context, decision_type)
        
        matching_rules = self.policy_engine.evaluate_rules(context, decision_type)
        
        outcome = "APPROVED"
        status = DecisionStatus.APPROVED
        
        if matching_rules:
            top_rule = matching_rules[0]
            if "BLOCK" in top_rule.actions:
                outcome = "BLOCKED"
                status = DecisionStatus.REJECTED
            elif "ESCALATE" in top_rule.actions:
                outcome = "ESCALATED"
                status = DecisionStatus.ESCALATED
        
        if reasoning_result["confidence"] < 0.5:
            status = DecisionStatus.ESCALATED
            outcome = "NEEDS_REVIEW"
        
        decision = Decision(
            decision_id=decision_id,
            decision_type=decision_type,
            context=context,
            outcome=outcome,
            status=status,
            confidence=reasoning_result["confidence"],
            confidence_level=self._get_confidence_level(reasoning_result["confidence"]),
            reasoning=reasoning_result["reasoning"],
            alternatives=self._generate_alternatives(context),
            decided_by=decided_by,
        )
        
        self.decisions[decision_id] = decision
        return decision
    
    def _get_confidence_level(self, confidence: float) -> DecisionConfidence:
        """Get confidence level from score."""
        if confidence >= 0.8:
            return DecisionConfidence.HIGH
        elif confidence >= 0.5:
            return DecisionConfidence.MEDIUM
        return DecisionConfidence.LOW
    
    def _generate_alternatives(self, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate alternative decisions."""
        return [
            {
                "option": "Approve with monitoring",
                "risk": "MEDIUM",
                "reason": "Approve and add transaction to watch list",
            },
            {
                "option": "Request additional verification",
                "risk": "LOW",
                "reason": "Require user verification before processing",
            },
        ]
    
    def get_decision(self, decision_id: str) -> Optional[Decision]:
        """Get a decision by ID."""
        return self.decisions.get(decision_id)
    
    def explain_decision(self, decision_id: str) -> Optional[DecisionExplanation]:
        """Generate explanation for a decision."""
        decision = self.decisions.get(decision_id)
        if not decision:
            return None
        
        factors = [
            {"name": f"Factor {i+1}", "weight": 0.2, "value": r}
            for i, r in enumerate(decision.reasoning)
        ]
        
        return DecisionExplanation(
            explanation_id=str(uuid4()),
            decision_id=decision_id,
            factors=factors,
            recommendations=["Continue monitoring", "Enable additional controls"],
            risk_factors=decision.reasoning[:2] if decision.reasoning else [],
            mitigation_suggestions=["Verify recipient identity", "Review transaction history"],
        )
    
    def get_decision_history(
        self,
        decision_type: Optional[DecisionType] = None,
        limit: int = 100,
    ) -> List[Decision]:
        """Get decision history."""
        decisions = list(self.decisions.values())
        
        if decision_type:
            decisions = [d for d in decisions if d.decision_type == decision_type]
        
        return sorted(decisions, key=lambda d: d.created_at, reverse=True)[:limit]
    
    def log_audit(
        self,
        decision_id: str,
        action: str,
        user: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> DecisionAudit:
        """Log a decision audit."""
        audit = DecisionAudit(
            audit_id=str(uuid4()),
            decision_id=decision_id,
            action=action,
            user=user,
            details=details or {},
        )
        self.audit_log.append(audit)
        return audit
    
    def get_audit_log(self, decision_id: Optional[str] = None) -> List[DecisionAudit]:
        """Get audit log."""
        if decision_id:
            return [a for a in self.audit_log if a.decision_id == decision_id]
        return self.audit_log


def get_decision_engine() -> DecisionEngine:
    """Get the global decision engine instance."""
    global _decision_engine
    if _decision_engine is None:
        _decision_engine = DecisionEngine()
    return _decision_engine


_decision_engine: Optional[DecisionEngine] = None