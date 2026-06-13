"""MetaBrain Strategic Planning Engine"""
from typing import Any, Dict, List, Optional
from uuid import uuid4
from .models import Strategy, StrategicInsight, IntelligenceLevel

class Planner:
    """Strategic planning engine for security operations"""
    
    def __init__(self) -> None:
        self.strategies: Dict[str, Strategy] = {}
        self.planning_templates: Dict[str, Dict[str, Any]] = self._init_templates()
    
    def _init_templates(self) -> Dict[str, Dict[str, Any]]:
        """Initialize strategic planning templates"""
        return {
            "FRAUD_PREVENTION": {
                "objectives": [
                    "Reduce fraud losses by 30%",
                    "Improve detection accuracy",
                    "Minimize false positives"
                ],
                "phases": [
                    "Phase 1: Enhanced monitoring (30 days)",
                    "Phase 2: ML model updates (60 days)",
                    "Phase 3: Process automation (90 days)"
                ],
                "metrics": ["Fraud rate", "Detection time", "False positive rate"]
            },
            "CYBER_DEFENSE": {
                "objectives": [
                    "Strengthen perimeter security",
                    "Improve threat detection",
                    "Reduce mean time to respond"
                ],
                "phases": [
                    "Phase 1: Security audit (30 days)",
                    "Phase 2: Control implementation (60 days)",
                    "Phase 3: Continuous monitoring (90 days)"
                ],
                "metrics": ["Incident count", "MTTR", "Coverage"]
            },
            "COMPLIANCE_ENHANCEMENT": {
                "objectives": [
                    "Achieve compliance posture",
                    "Reduce audit findings",
                    "Automate compliance reporting"
                ],
                "phases": [
                    "Phase 1: Gap analysis (30 days)",
                    "Phase 2: Control implementation (60 days)",
                    "Phase 3: Validation (90 days)"
                ],
                "metrics": ["Compliance score", "Findings", "Report time"]
            }
        }
    
    def create_strategy(
        self,
        strategy_type: str,
        name: str,
        description: str,
        insights: Optional[List[StrategicInsight]] = None
    ) -> Strategy:
        """Create a strategic defense plan"""
        template = self.planning_templates.get(strategy_type, self.planning_templates["CYBER_DEFENSE"])
        
        strategy = Strategy(
            strategy_id=str(uuid4()),
            name=name,
            description=description,
            objectives=template["objectives"],
            phases=template["phases"],
            success_metrics=template["metrics"]
        )
        
        self.strategies[strategy.strategy_id] = strategy
        return strategy
    
    def get_strategy(self, strategy_id: str) -> Optional[Strategy]:
        """Get a specific strategy"""
        return self.strategies.get(strategy_id)
    
    def get_all_strategies(self) -> List[Strategy]:
        """Get all strategies"""
        return list(self.strategies.values())
    
    def generate_roadmap(
        self,
        insights: List[StrategicInsight],
        timeframe_days: int = 90
    ) -> List[Dict[str, Any]]:
        """Generate a strategic roadmap from insights"""
        roadmap: List[Dict[str, Any]] = []
        
        # Group insights by intelligence level
        tactical = [i for i in insights if i.intelligence_level == IntelligenceLevel.TACTICAL]
        operational = [i for i in insights if i.intelligence_level == IntelligenceLevel.OPERATIONAL]
        strategic = [i for i in insights if i.intelligence_level == IntelligenceLevel.STRATEGIC]
        
        # Generate roadmap items
        if tactical:
            roadmap.append({
                "phase": "Immediate (0-30 days)",
                "items": [f"Tactical: {i.title}" for i in tactical[:5]],
                "priority": "HIGH"
            })
        
        if operational:
            roadmap.append({
                "phase": "Short-term (30-60 days)",
                "items": [f"Operational: {i.title}" for i in operational[:5]],
                "priority": "MEDIUM"
            })
        
        if strategic:
            roadmap.append({
                "phase": "Long-term (60-90 days)",
                "items": [f"Strategic: {i.title}" for i in strategic[:5]],
                "priority": "LOW"
            })
        
        return roadmap