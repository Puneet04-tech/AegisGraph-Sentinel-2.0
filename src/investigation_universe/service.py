"""Investigation Universe Service"""
from typing import Any, Dict, List, Optional
from uuid import uuid4
from datetime import datetime
from .models import (
    Investigation, Evidence, Hypothesis, Correlation,
    InvestigationStatus, EvidenceType, ConfidenceLevel
)

class InvestigationUniverseService:
    """AI Investigation Universe Service"""
    
    def __init__(self) -> None:
        self.investigations: Dict[str, Investigation] = {}
        self.evidence: Dict[str, Evidence] = {}
        self.hypotheses: Dict[str, Hypothesis] = {}
        self.correlations: Dict[str, Correlation] = {}
    
    def create_investigation(
        self,
        title: str,
        description: str,
        priority: int = 1
    ) -> Dict[str, Any]:
        """Create a new investigation"""
        investigation = Investigation(
            investigation_id=str(uuid4())[:8],
            title=title,
            description=description,
            status=InvestigationStatus.INITIAL,
            priority=priority
        )
        self.investigations[investigation.investigation_id] = investigation
        return investigation.to_dict()
    
    def get_investigation(self, investigation_id: str) -> Optional[Dict[str, Any]]:
        """Get an investigation"""
        investigation = self.investigations.get(investigation_id)
        return investigation.to_dict() if investigation else None
    
    def get_all_investigations(self) -> List[Dict[str, Any]]:
        """Get all investigations"""
        return [i.to_dict() for i in self.investigations.values()]
    
    def update_investigation_status(
        self,
        investigation_id: str,
        status: str
    ) -> Optional[Dict[str, Any]]:
        """Update investigation status"""
        investigation = self.investigations.get(investigation_id)
        if investigation:
            investigation.status = InvestigationStatus(status)
            investigation.updated_at = datetime.utcnow()
            if investigation.status == InvestigationStatus.CLOSED:
                investigation.concluded_at = datetime.utcnow()
            return investigation.to_dict()
        return None
    
    def add_evidence(
        self,
        investigation_id: str,
        evidence_type: str,
        description: str,
        source: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Add evidence to an investigation"""
        evidence = Evidence(
            evidence_id=str(uuid4())[:8],
            investigation_id=investigation_id,
            evidence_type=EvidenceType(evidence_type),
            description=description,
            source=source,
            metadata=metadata or {}
        )
        self.evidence[evidence.evidence_id] = evidence
        
        # Update investigation evidence count
        investigation = self.investigations.get(investigation_id)
        if investigation:
            investigation.evidence_count += 1
            investigation.updated_at = datetime.utcnow()
        
        return evidence.to_dict()
    
    def get_evidence(self, evidence_id: str) -> Optional[Dict[str, Any]]:
        """Get evidence by ID"""
        evidence = self.evidence.get(evidence_id)
        return evidence.to_dict() if evidence else None
    
    def get_investigation_evidence(
        self,
        investigation_id: str
    ) -> List[Dict[str, Any]]:
        """Get all evidence for an investigation"""
        return [e.to_dict() for e in self.evidence.values() 
                if e.investigation_id == investigation_id]
    
    def generate_hypothesis(
        self,
        investigation_id: str,
        description: str,
        confidence: str = "MEDIUM",
        supporting_evidence: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Generate a hypothesis"""
        hypothesis = Hypothesis(
            hypothesis_id=str(uuid4())[:8],
            investigation_id=investigation_id,
            description=description,
            confidence=ConfidenceLevel(confidence),
            supporting_evidence=supporting_evidence or []
        )
        self.hypotheses[hypothesis.hypothesis_id] = hypothesis
        
        # Link to investigation
        investigation = self.investigations.get(investigation_id)
        if investigation:
            investigation.hypotheses.append(hypothesis.hypothesis_id)
        
        return hypothesis.to_dict()
    
    def get_hypothesis(self, hypothesis_id: str) -> Optional[Dict[str, Any]]:
        """Get a hypothesis"""
        hypothesis = self.hypotheses.get(hypothesis_id)
        return hypothesis.to_dict() if hypothesis else None
    
    def verify_hypothesis(self, hypothesis_id: str) -> Optional[Dict[str, Any]]:
        """Verify a hypothesis"""
        hypothesis = self.hypotheses.get(hypothesis_id)
        if hypothesis:
            hypothesis.verified = True
            return hypothesis.to_dict()
        return None
    
    def add_correlation(
        self,
        investigation_id: str,
        entity_type: str,
        entity_id: str,
        related_entities: List[str],
        correlation_type: str,
        strength: float = 0.5
    ) -> Dict[str, Any]:
        """Add entity correlation"""
        correlation = Correlation(
            correlation_id=str(uuid4())[:8],
            investigation_id=investigation_id,
            entity_type=entity_type,
            entity_id=entity_id,
            related_entities=related_entities,
            correlation_type=correlation_type,
            strength=strength
        )
        self.correlations[correlation.correlation_id] = correlation
        return correlation.to_dict()
    
    def get_investigation_correlations(
        self,
        investigation_id: str
    ) -> List[Dict[str, Any]]:
        """Get all correlations for an investigation"""
        return [c.to_dict() for c in self.correlations.values()
                if c.investigation_id == investigation_id]
    
    def generate_narrative(self, investigation_id: str) -> Dict[str, Any]:
        """Generate AI narrative for investigation"""
        investigation = self.investigations.get(investigation_id)
        if not investigation:
            raise ValueError("Investigation not found")
        
        hypotheses = [self.hypotheses.get(h) for h in investigation.hypotheses]
        evidence_list = self.get_investigation_evidence(investigation_id)
        correlations = self.get_investigation_correlations(investigation_id)
        
        narrative = f"Investigation '{investigation.title}' analyzed {len(evidence_list)} " \
                   f"pieces of evidence and generated {len(hypotheses)} hypotheses. " \
                   f"Found {len(correlations)} correlations."
        
        return {
            "investigation_id": investigation_id,
            "narrative": narrative,
            "summary": {
                "evidence_count": len(evidence_list),
                "hypothesis_count": len(hypotheses),
                "correlation_count": len(correlations),
                "verified_hypotheses": sum(1 for h in hypotheses if h and h.verified)
            }
        }
    
    def get_dashboard(self) -> Dict[str, Any]:
        """Get investigation dashboard"""
        status_counts: Dict[str, int] = {}
        for inv in self.investigations.values():
            status_counts[inv.status.value] = status_counts.get(inv.status.value, 0) + 1
        
        return {
            "total_investigations": len(self.investigations),
            "total_evidence": len(self.evidence),
            "total_hypotheses": len(self.hypotheses),
            "total_correlations": len(self.correlations),
            "investigations_by_status": status_counts
        }


# Global service instance
_investigation_service: Optional[InvestigationUniverseService] = None

def get_investigation_service() -> InvestigationUniverseService:
    """Get the global service instance"""
    global _investigation_service
    if _investigation_service is None:
        _investigation_service = InvestigationUniverseService()
    return _investigation_service