"""Trust Network Engine"""
from typing import Dict, Any
from uuid import uuid4

class TrustEngine:
    def __init__(self):
        self.entities = {}
    def add_entity(self, name: str) -> str:
        entity_id = str(uuid4())
        self.entities[entity_id] = {"entity_id": entity_id, "name": name}
        return entity_id
    def get_stats(self) -> Dict[str, Any]:
        return {"total_entities": len(self.entities)}
