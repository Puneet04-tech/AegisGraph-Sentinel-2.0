"""Threat Strategy Service"""
from typing import Any, Dict, List, Optional
from .models import ThreatStrategy, ThreatCategory, ThreatLevel, StrategyStatus
from .planner import StrategyPlanner
from .simulator import StrategySimulator

class ThreatStrategyService:
    """Main service for threat strategy operations"""
    
    def __init__(self) -> None:
        self.planner = StrategyPlanner()
        self.simulator = StrategySimulator()
    
    def create_strategy(
        self,
        name: str,
        description: str,
        threat_category: str,
        threat_level: str,
        threat_description: str,
        affected_areas: List[str],
        likelihood: float,
        impact: float,
        timeline_days: int = 90
    ) -> Dict[str, Any]:
        """Create a new threat defense strategy"""
        strategy = self.planner.create_strategy(
            name=name,
            description=description,
            threat_category=ThreatCategory(threat_category),
            threat_level=ThreatLevel(threat_level),
            threat_description=threat_description,
            affected_areas=affected_areas,
            likelihood=likelihood,
            impact=impact,
            timeline_days=timeline_days
        )
        return strategy.to_dict()
    
    def get_strategy(self, strategy_id: str) -> Optional[Dict[str, Any]]:
        """Get a strategy by ID"""
        strategy = self.planner.get_strategy(strategy_id)
        return strategy.to_dict() if strategy else None
    
    def get_all_strategies(self) -> List[Dict[str, Any]]:
        """Get all strategies"""
        return [s.to_dict() for s in self.planner.get_all_strategies()]
    
    def approve_strategy(self, strategy_id: str) -> Optional[Dict[str, Any]]:
        """Approve a strategy"""
        strategy = self.planner.approve_strategy(strategy_id)
        return strategy.to_dict() if strategy else None
    
    def simulate_attack(
        self,
        scenario_id: str,
        defense_controls: List[str]
    ) -> Dict[str, Any]:
        """Simulate a threat scenario"""
        return self.simulator.simulate_scenario(scenario_id, defense_controls)
    
    def generate_forecast(
        self,
        threat_type: str,
        timeframe_days: int = 30
    ) -> Dict[str, Any]:
        """Generate threat forecast"""
        forecast = self.simulator.forecast_campaign(threat_type, timeframe_days)
        return forecast.to_dict()
    
    def generate_roadmap(self, strategy_id: str) -> Dict[str, Any]:
        """Generate implementation roadmap"""
        return self.planner.generate_roadmap(strategy_id)
    
    def get_available_scenarios(self) -> List[Dict[str, Any]]:
        """Get available threat scenarios"""
        return self.simulator.threat_scenarios
    
    def get_simulations(self) -> List[Dict[str, Any]]:
        """Get simulation history"""
        return self.simulator.get_simulation_history()
    
    def generate_report(self, strategy_id: str) -> Dict[str, Any]:
        """Generate comprehensive strategy report"""
        strategy = self.planner.get_strategy(strategy_id)
        if not strategy:
            return {"error": "Strategy not found"}
        
        roadmap = self.planner.generate_roadmap(strategy_id)
        
        return {
            "strategy": strategy.to_dict(),
            "roadmap": roadmap,
            "simulations": self.simulator.get_simulation_history(),
            "generated_at": str(strategy.created_at)
        }


# Global service instance
_threat_strategy_service: Optional[ThreatStrategyService] = None

def get_threat_strategy_service() -> ThreatStrategyService:
    """Get the global service instance"""
    global _threat_strategy_service
    if _threat_strategy_service is None:
        _threat_strategy_service = ThreatStrategyService()
    return _threat_strategy_service