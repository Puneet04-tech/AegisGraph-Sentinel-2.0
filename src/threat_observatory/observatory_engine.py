"""Threat Observatory Engine"""
from typing import Dict, Any
from uuid import uuid4

class ThreatObservatory:
    def __init__(self):
        self.threats = {}
    
    def add_threat(self, name: str) -> str:
        threat_id = str(uuid4())
        self.threats[threat_id] = {"threat_id": threat_id, "name": name}
        return threat_id
    
    def get_stats(self) -> Dict[str, Any]:
        return {"total_threats": len(self.threats)}