"""Threat Observatory Models"""
from dataclasses import dataclass
from typing import Dict, Any

@dataclass
class GlobalThreat:
    threat_id: str
    name: str
    severity: str = "HIGH"
    
    def to_dict(self) -> Dict[str, Any]:
        return {"threat_id": self.threat_id, "name": self.name}