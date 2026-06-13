"""Multi-Cloud Fabric Models"""
from dataclasses import dataclass
from typing import Dict, Any

@dataclass
class CloudConnector:
    connector_id: str
    provider: str
    status: str = "ACTIVE"
    def to_dict(self) -> Dict[str, Any]:
        return {"connector_id": self.connector_id, "provider": self.provider}
