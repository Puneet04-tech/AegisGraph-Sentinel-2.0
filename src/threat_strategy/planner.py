"""Threat Strategy Planner"""
from typing import Any, Dict, List, Optional
from uuid import uuid4
from datetime import datetime, timedelta
from .models import (
    ThreatStrategy, ThreatAssessment, DefenseInitiative,
    ThreatCategory, ThreatLevel, StrategyStatus
)

class StrategyPlanner:
    """Strategic planning for threat defense"""
    
    def __init__(self) -> None:
        self.strategies: Dict[str, ThreatStrategy] = {}
        self.initiative_templates: Dict[str, List[DefenseInitiative]] = self._init_templates()
    
    def _init_templates(self) -> Dict[str, List[DefenseInitiative]]:
        """Initialize initiative templates by threat category"""
        return {
            ThreatCategory.FRAUD: [
                DefenseInitiative(
                    initiative_id="fraud-001",
                    name="Enhanced Transaction Monitoring",
                    description="Implement advanced ML-based transaction monitoring",
                    objective="Reduce fraud losses by 40%",
                    timeline="30 days",
                    resources_required=["ML team", "Data platform"],
                    success_criteria=["Fraud rate < 0.5%", "False positive < 2%"]
                ),
                DefenseInitiative(
                    initiative_id="fraud-002",
                    name="Real-time Scoring",
                    description="Deploy real-time fraud scoring engine",
                    objective="Score 99% of transactions in < 100ms",
                    timeline="45 days",
                    resources_required=["Scoring infrastructure", "API team"],
                    success_criteria=["Latency < 100ms", "Uptime 99.99%"]
                )
            ],
            ThreatCategory.CYBER: [
                DefenseInitiative(
                    initiative_id="cyber-001",
                    name="Zero Trust Architecture",
                    description="Implement zero trust security model",
                    objective="Achieve zero trust compliance",
                    timeline="90 days",
                    resources_required=["Security team", "Network team"],
                    success_criteria=["All access authenticated", "Micro-segmentation active"]
                ),
                DefenseInitiative(
                    initiative_id="cyber-002",
                    name="Threat Detection Enhancement",
                    description="Enhance threat detection capabilities",
                    objective="Reduce MTTD by 50%",
                    timeline="60 days",
                    resources_required=["SIEM team", "Threat intel"],
                    success_criteria=["MTTD < 1 hour", "Detection rate > 95%"]
                )
            ]
        }
    
    def create_strategy(
        self,
        name: str,
        description: str,
        threat_category: ThreatCategory,
        threat_level: ThreatLevel,
        threat_description: str,
        affected_areas: List[str],
        likelihood: float,
        impact: float,
        timeline_days: int = 90
    ) -> ThreatStrategy:
        """Create a new threat defense strategy"""
        # Create threat assessment
        assessment = ThreatAssessment(
            assessment_id=str(uuid4()),
            threat_category=threat_category,
            threat_level=threat_level,
            description=threat_description,
            affected_areas=affected_areas,
            likelihood=likelihood,
            impact=impact
        )
        
        # Get initiative templates
        initiatives = self.initiative_templates.get(threat_category, [])
        
        # Create strategy
        strategy = ThreatStrategy(
            strategy_id=str(uuid4()),
            name=name,
            description=description,
            threat_assessment=assessment,
            initiatives=initiatives,
            status=StrategyStatus.DRAFT,
            timeline_days=timeline_days
        )
        
        self.strategies[strategy.strategy_id] = strategy
        return strategy
    
    def get_strategy(self, strategy_id: str) -> Optional[ThreatStrategy]:
        """Get a strategy by ID"""
        return self.strategies.get(strategy_id)
    
    def get_all_strategies(self) -> List[ThreatStrategy]:
        """Get all strategies"""
        return list(self.strategies.values())
    
    def approve_strategy(self, strategy_id: str) -> Optional[ThreatStrategy]:
        """Approve a strategy"""
        strategy = self.strategies.get(strategy_id)
        if strategy:
            strategy.status = StrategyStatus.APPROVED
        return strategy
    
    def update_strategy_status(
        self,
        strategy_id: str,
        status: StrategyStatus
    ) -> Optional[ThreatStrategy]:
        """Update strategy status"""
        strategy = self.strategies.get(strategy_id)
        if strategy:
            strategy.status = status
        return strategy
    
    def generate_roadmap(self, strategy_id: str) -> Dict[str, Any]:
        """Generate implementation roadmap for a strategy"""
        strategy = self.strategies.get(strategy_id)
        if not strategy:
            return {"error": "Strategy not found"}
        
        roadmap: List[Dict[str, Any]] = []
        days_per_phase = strategy.timeline_days // len(strategy.initiatives)
        
        for i, initiative in enumerate(strategy.initiatives):
            start_date = datetime.utcnow() + timedelta(days=i * days_per_phase)
            end_date = start_date + timedelta(days=days_per_phase)
            
            roadmap.append({
                "phase": i + 1,
                "initiative": initiative.name,
                "start_date": start_date.isoformat(),
                "end_date": end_date.isoformat(),
                "resources": initiative.resources_required,
                "success_criteria": initiative.success_criteria
            })
        
        return {
            "strategy_id": strategy_id,
            "total_days": strategy.timeline_days,
            "phases": roadmap
        }