"""Fraud Pattern Service"""
from typing import Any, Dict, List, Optional
from uuid import uuid4
from datetime import datetime
from .models import Pattern, Detection, PatternType, DetectionStatus

class FraudPatternService:
    """Fraud Pattern Detection Service"""
    
    def __init__(self) -> None:
        self.patterns: Dict[str, Pattern] = {}
        self.detections: Dict[str, Detection] = {}
        self._init_default_patterns()
    
    def _init_default_patterns(self) -> None:
        """Initialize default patterns"""
        patterns = [
            Pattern(
                pattern_id="pat-001",
                name="Rapid Succession Transactions",
                pattern_type=PatternType.TRANSACTIONAL,
                description="Multiple transactions in quick succession",
                rules=[{"type": "velocity", "threshold": 10, "window": "1h"}],
                severity="HIGH"
            ),
            Pattern(
                pattern_id="pat-002",
                name="Unusual Geographic Activity",
                pattern_type=PatternType.BEHAVIORAL,
                description="Transactions from unusual locations",
                rules=[{"type": "geo_distance", "threshold": 1000}],
                severity="MEDIUM"
            )
        ]
        for p in patterns:
            self.patterns[p.pattern_id] = p
    
    def create_pattern(
        self,
        name: str,
        pattern_type: str,
        description: str,
        rules: List[Dict[str, Any]],
        severity: str
    ) -> Dict[str, Any]:
        """Create a fraud pattern"""
        pattern = Pattern(
            pattern_id=str(uuid4())[:8],
            name=name,
            pattern_type=PatternType(pattern_type),
            description=description,
            rules=rules,
            severity=severity
        )
        self.patterns[pattern.pattern_id] = pattern
        return pattern.to_dict()
    
    def detect(
        self,
        pattern_id: str,
        entity_id: str,
        data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Detect a pattern match"""
        pattern = self.patterns.get(pattern_id)
        if not pattern:
            raise ValueError(f"Pattern {pattern_id} not found")
        
        # Simple detection logic
        confidence = 0.7
        
        detection = Detection(
            detection_id=str(uuid4())[:8],
            pattern_id=pattern_id,
            entity_id=entity_id,
            status=DetectionStatus.DETECTED,
            confidence=confidence,
            details=data
        )
        self.detections[detection.detection_id] = detection
        return detection.to_dict()
    
    def get_pattern(self, pattern_id: str) -> Optional[Dict[str, Any]]:
        """Get a pattern"""
        pattern = self.patterns.get(pattern_id)
        return pattern.to_dict() if pattern else None
    
    def get_all_patterns(self) -> List[Dict[str, Any]]:
        """Get all patterns"""
        return [p.to_dict() for p in self.patterns.values()]
    
    def get_detections(self, pattern_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get detections"""
        detections = self.detections.values()
        if pattern_id:
            detections = [d for d in detections if d.pattern_id == pattern_id]
        return [d.to_dict() for d in detections]
    
    def update_detection_status(self, detection_id: str, status: str) -> Optional[Dict[str, Any]]:
        """Update detection status"""
        detection = self.detections.get(detection_id)
        if detection:
            detection.status = DetectionStatus(status)
            return detection.to_dict()
        return None
    
    def get_dashboard(self) -> Dict[str, Any]:
        """Get pattern dashboard"""
        status_counts: Dict[str, int] = {}
        for d in self.detections.values():
            status_counts[d.status.value] = status_counts.get(d.status.value, 0) + 1
        
        return {
            "total_patterns": len(self.patterns),
            "total_detections": len(self.detections),
            "detections_by_status": status_counts
        }


_pattern_service: Optional[FraudPatternService] = None

def get_pattern_service() -> FraudPatternService:
    """Get the global service instance"""
    global _pattern_service
    if _pattern_service is None:
        _pattern_service = FraudPatternService()
    return _pattern_service