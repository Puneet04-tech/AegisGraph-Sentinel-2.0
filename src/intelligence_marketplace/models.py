"""Marketplace Models"""
from dataclasses import dataclass
from enum import Enum
from typing import Dict, Any
from uuid import uuid4

class ListingType(Enum):
    DATASET = "DATASET"
    MODEL = "MODEL"
    THREAT_FEED = "THREAT_FEED"

@dataclass
class MarketplaceListing:
    listing_id: str
    name: str
    listing_type: ListingType
    
    def to_dict(self) -> Dict[str, Any]:
        return {"listing_id": self.listing_id, "name": self.name}