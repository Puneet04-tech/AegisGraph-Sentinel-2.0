"""MLOps Platform Models"""
from dataclasses import dataclass
from typing import Dict, Any

@dataclass
class TrainingRun:
    run_id: str
    model_name: str
    status: str = "PENDING"
    
    def to_dict(self) -> Dict[str, Any]:
        return {"run_id": self.run_id, "model_name": self.model_name}