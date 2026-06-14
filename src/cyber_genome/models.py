"""Cyber Genome Models"""
from dataclasses import dataclass
from typing import Dict, Any

@dataclass
class BehaviorPattern:
    pattern_id: str
    name: str
    threat_type: str
    def to_dict(self) -> Dict[str, Any]:
        return {"pattern_id": self.pattern_id, "name": self.name}
