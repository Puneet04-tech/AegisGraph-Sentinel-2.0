"""Federated Learning Models"""
from dataclasses import dataclass
from enum import Enum
from typing import Dict, Any

class NodeRole(Enum):
    PARTICIPANT = "PARTICIPANT"
    AGGREGATOR = "AGGREGATOR"

@dataclass
class FederatedNode:
    node_id: str
    name: str
    role: NodeRole
    def to_dict(self) -> Dict[str, Any]:
        return {"node_id": self.node_id, "name": self.name}
