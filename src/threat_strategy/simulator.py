"""Threat Strategy Simulator"""
from typing import Any, Dict, List, Optional
from datetime import datetime, timedelta
from uuid import uuid4
from .models import ThreatStrategy, ThreatCategory, ThreatLevel, CampaignForecast

class StrategySimulator:
    """Simulate threat scenarios and defense strategies"""
    
    def __init__(self) -> None:
        self.simulations: Dict[str, Dict[str, Any]] = {}
        self.threat_scenarios: List[Dict[str, Any]] = self._init_scenarios()
    
    def _init_scenarios(self) -> List[Dict[str, Any]]:
        """Initialize threat scenario templates"""
        return [
            {
                "scenario_id": "apt-attack",
                "name": "APT Attack Simulation",
                "description": "Simulate advanced persistent threat attack",
                "steps": [
                    "Reconnaissance",
                    "Initial access via phishing",
                    "Lateral movement",
                    "Privilege escalation",
                    "Data exfiltration"
                ],
                "success_rate": 0.75,
                "detection_rate": 0.4
            },
            {
                "scenario_id": "fraud-campaign",
                "name": "Coordinated Fraud Campaign",
                "description": "Simulate organized fraud attack",
                "steps": [
                    "Credential harvesting",
                    "Account takeover",
                    "Unauthorized transactions",
                    "Money laundering",
                    "Exit"
                ],
                "success_rate": 0.65,
                "detection_rate": 0.6
            },
            {
                "scenario_id": "insider-threat",
                "name": "Insider Threat Scenario",
                "description": "Simulate insider attack",
                "steps": [
                    "Privilege abuse",
                    "Data access",
                    "Data exfiltration",
                    "Cover tracks"
                ],
                "success_rate": 0.85,
                "detection_rate": 0.3
            }
        ]
    
    def simulate_scenario(
        self,
        scenario_id: str,
        defense_controls: List[str]
    ) -> Dict[str, Any]:
        """Simulate a threat scenario with given defenses"""
        scenario = next((s for s in self.threat_scenarios if s["scenario_id"] == scenario_id), None)
        if not scenario:
            return {"error": "Scenario not found"}
        
        sim_id = str(uuid4())
        
        # Calculate effectiveness based on defense controls
        defense_score = len(defense_controls) * 0.15
        detection_boost = min(defense_score * 0.5, 0.4)
        
        simulated_detection = min(scenario["detection_rate"] + detection_boost, 0.99)
        simulated_success = scenario["success_rate"] * (1 - defense_score)
        
        # Simulate each step
        steps_survived = []
        steps_detected = []
        
        for step in scenario["steps"]:
            import random
            detected = random.random() < simulated_detection
            if detected:
                steps_detected.append(step)
            else:
                steps_survived.append(step)
        
        result = {
            "simulation_id": sim_id,
            "scenario": scenario["name"],
            "defense_controls_applied": defense_controls,
            "defense_score": defense_score,
            "overall_detection_rate": simulated_detection,
            "attack_success_probability": simulated_success,
            "steps_detected": steps_detected,
            "steps_survived": steps_survived,
            "risk_level": self._calculate_risk(simulated_success, simulated_detection),
            "recommendations": self._generate_recommendations(scenario, defense_controls)
        }
        
        self.simulations[sim_id] = result
        return result
    
    def _calculate_risk(self, success_prob: float, detection_rate: float) -> str:
        """Calculate risk level"""
        risk_score = success_prob * (1 - detection_rate)
        if risk_score > 0.5:
            return "CRITICAL"
        elif risk_score > 0.3:
            return "HIGH"
        elif risk_score > 0.15:
            return "MEDIUM"
        return "LOW"
    
    def _generate_recommendations(
        self,
        scenario: Dict[str, Any],
        defenses: List[str]
    ) -> List[str]:
        """Generate defense recommendations"""
        recommendations = []
        
        if len(defenses) < 3:
            recommendations.append("Add more defense layers (defense in depth)")
        
        if "SIEM" not in defenses:
            recommendations.append("Implement SIEM for threat detection")
        
        if "MFA" not in defenses:
            recommendations.append("Enforce multi-factor authentication")
        
        if "encryption" not in " ".join(defenses).lower():
            recommendations.append("Implement data encryption")
        
        if scenario["scenario_id"] == "apt-attack":
            recommendations.append("Deploy endpoint detection and response (EDR)")
            recommendations.append("Implement network segmentation")
        
        if scenario["scenario_id"] == "fraud-campaign":
            recommendations.append("Deploy real-time fraud scoring")
            recommendations.append("Implement transaction monitoring")
        
        return recommendations if recommendations else ["Current defenses are adequate"]
    
    def forecast_campaign(
        self,
        threat_type: str,
        timeframe_days: int = 30
    ) -> CampaignForecast:
        """Generate threat campaign forecast"""
        import random
        
        predictions = {
            "FRAUD": "Increased account takeover attacks expected",
            "CYBER": "Ransomware attacks targeting financial sector",
            "INSIDER": "Data exfiltration attempts via cloud storage",
            "PHISHING": "Spear phishing campaigns targeting executives"
        }
        
        sectors = ["Banking", "Healthcare", "Retail", "Government", "Technology"]
        
        forecast = CampaignForecast(
            forecast_id=str(uuid4()),
            threat_type=threat_type,
            prediction=predictions.get(threat_type, "General threat activity"),
            confidence=0.7 + random.random() * 0.2,
            timeframe_start=datetime.utcnow(),
            timeframe_end=datetime.utcnow() + timedelta(days=timeframe_days),
            affected_sectors=random.sample(sectors, random.randint(2, 4))
        )
        
        return forecast
    
    def get_simulation_history(self) -> List[Dict[str, Any]]:
        """Get simulation history"""
        return list(self.simulations.values())