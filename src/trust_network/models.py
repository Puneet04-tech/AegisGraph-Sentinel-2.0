"""Trust Network Models"""
from dataclasses import dataclass
from typing import Dict, Any

@dataclass
class TrustEntity:
    entity_id: str
    name: str
    trust_score: float = 0.5
    def to_dict(self) -> Dict[str, Any]:
        return {"entity_id": self.entity_id, "name": self.name}
