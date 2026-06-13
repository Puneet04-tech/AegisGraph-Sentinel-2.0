"""Threat Prediction Models"""
from dataclasses import dataclass
from typing import Dict, Any

@dataclass
class ThreatPrediction:
    prediction_id: str
    threat_type: str
    probability: float
    def to_dict(self) -> Dict[str, Any]:
        return {"prediction_id": self.prediction_id, "threat_type": self.threat_type}
