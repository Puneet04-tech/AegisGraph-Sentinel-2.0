"""
Policy Mapping Engine for Regulatory Fabric.

Maps controls to regulatory requirements and policies.
"""

from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timezone
import uuid


@dataclass
class MappingSuggestion:
    """Suggestion for a new control-requirement mapping."""
    suggestion_id: str
    regulation_id: str
    requirement_id: str
    suggested_control_id: str
    confidence: float
    justification: str
    alternative_controls: List[str] = field(default_factory=list)


class PolicyMappingEngine:
    """Maps internal controls to regulatory requirements.
    
    Provides intelligent mapping suggestions and maintains
    the control-regulation mapping matrix.
    """

    def __init__(self, store: Any):
        """Initialize the policy mapping engine.
        
        Args:
            store: Compliance store instance
        """
        self.store = store

    def map_control_to_requirement(
        self,
        control_id: str,
        regulation_id: str,
        requirement_id: Optional[str] = None,
        mapping_type: str = "DIRECT",
        justification: str = "",
    ) -> Dict[str, Any]:
        """Create a mapping between a control and a regulation/requirement.
        
        Args:
            control_id: Control ID to map
            regulation_id: Regulation ID
            requirement_id: Optional specific requirement ID
            mapping_type: Type of mapping (DIRECT, PARTIAL, INDIRECT)
            justification: Explanation for the mapping
            
        Returns:
            Created mapping
        """
        # Verify control and regulation exist
        control = self.store.get_control(control_id)
        regulation = self.store.get_regulation(regulation_id)
        
        if not control:
            return {"error": f"Control {control_id} not found"}
        if not regulation:
            return {"error": f"Regulation {regulation_id} not found"}
        
        mapping = {
            "mapping_id": str(uuid.uuid4()),
            "control_id": control_id,
            "regulation_id": regulation_id,
            "requirement_id": requirement_id,
            "mapping_type": mapping_type,
            "justification": justification,
            "confidence": 1.0 if mapping_type == "DIRECT" else 0.7 if mapping_type == "PARTIAL" else 0.5,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "verified": mapping_type == "DIRECT",
        }
        
        self.store.add_control_mapping(mapping)
        return mapping

    def get_mapping_matrix(self, regulation_id: Optional[str] = None) -> Dict[str, Any]:
        """Get the complete control-regulation mapping matrix.
        
        Args:
            regulation_id: Optional regulation to filter by
            
        Returns:
            Mapping matrix with statistics
        """
        if regulation_id:
            regulation = self.store.get_regulation(regulation_id)
            if not regulation:
                return {"error": "Regulation not found"}
            
            controls = self.store.get_controls_for_regulation(regulation_id)
            requirements = regulation.get("requirements", [])
            
            # Build requirement coverage map
            requirement_coverage = {}
            for req in requirements:
                req_id = req.get("id", "")
                mapped_controls = [
                    c for c in controls
                    if c.get("mapping", {}).get("requirement_id") == req_id
                ]
                requirement_coverage[req_id] = {
                    "covered": len(mapped_controls) > 0,
                    "control_count": len(mapped_controls),
                    "controls": [c.get("control_id") for c in mapped_controls],
                }
            
            return {
                "regulation_id": regulation_id,
                "regulation_name": regulation.get("name"),
                "total_requirements": len(requirements),
                "covered_requirements": sum(1 for c in requirement_coverage.values() if c["covered"]),
                "coverage_percentage": sum(1 for c in requirement_coverage.values() if c["covered"]) / len(requirements) * 100 if requirements else 0,
                "requirement_coverage": requirement_coverage,
                "controls": controls,
            }
        
        # Return full matrix
        all_mappings = list(self.store.control_mappings.values())
        all_regulations = list(self.store.regulations.values())
        all_controls = list(self.store.controls.values())
        
        return {
            "total_regulations": len(all_regulations),
            "total_controls": len(all_controls),
            "total_mappings": len(all_mappings),
            "mapping_types": self._count_by_type(all_mappings),
            "coverage_summary": self._calculate_coverage_summary(),
        }

    def _count_by_type(self, mappings: List[Dict]) -> Dict[str, int]:
        """Count mappings by type."""
        counts = {"DIRECT": 0, "PARTIAL": 0, "INDIRECT": 0}
        for m in mappings:
            mt = m.get("mapping_type", "INDIRECT")
            counts[mt] = counts.get(mt, 0) + 1
        return counts

    def _calculate_coverage_summary(self) -> Dict[str, Any]:
        """Calculate coverage summary across all regulations."""
        summary = {}
        for reg in self.store.regulations.values():
            reg_id = reg.get("regulation_id")
            controls = self.store.get_controls_for_regulation(reg_id)
            total_reqs = len(reg.get("requirements", []))
            covered_reqs = len(set(
                c.get("mapping", {}).get("requirement_id")
                for c in controls
                if c.get("mapping", {}).get("requirement_id")
            ))
            summary[reg_id] = {
                "name": reg.get("name"),
                "total_requirements": total_reqs,
                "covered_requirements": covered_reqs,
                "coverage_percentage": (covered_reqs / total_reqs * 100) if total_reqs > 0 else 0,
            }
        return summary

    def suggest_mappings(self, regulation_id: str) -> List[MappingSuggestion]:
        """Suggest potential control-requirement mappings.
        
        Uses keyword matching and semantic analysis to suggest mappings.
        
        Args:
            regulation_id: Regulation to generate suggestions for
            
        Returns:
            List of mapping suggestions
        """
        regulation = self.store.get_regulation(regulation_id)
        if not regulation:
            return []
        
        suggestions = []
        controls = list(self.store.controls.values())
        requirements = regulation.get("requirements", [])
        
        # Get existing mappings
        existing = {
            (m.get("control_id"), m.get("requirement_id"))
            for m in self.store.control_mappings.values()
            if m.get("regulation_id") == regulation_id
        }
        
        for req in requirements:
            req_id = req.get("id", "")
            req_keywords = self._extract_keywords(req.get("description", ""))
            
            for ctrl in controls:
                ctrl_id = ctrl.get("control_id")
                
                # Skip if already mapped
                if (ctrl_id, req_id) in existing:
                    continue
                
                ctrl_keywords = self._extract_keywords(ctrl.get("description", ""))
                similarity = self._calculate_keyword_similarity(req_keywords, ctrl_keywords)
                
                if similarity > 0.3:
                    suggestion = MappingSuggestion(
                        suggestion_id=str(uuid.uuid4()),
                        regulation_id=regulation_id,
                        requirement_id=req_id,
                        suggested_control_id=ctrl_id,
                        confidence=similarity,
                        justification=f"Keyword similarity: {similarity:.2f}",
                        alternative_controls=self._find_alternative_controls(req_keywords, controls, ctrl_id),
                    )
                    suggestions.append(suggestion)
        
        return sorted(suggestions, key=lambda s: s.confidence, reverse=True)

    def _extract_keywords(self, text: str) -> set:
        """Extract keywords from text."""
        if not text:
            return set()
        
        # Simple keyword extraction
        words = text.lower().split()
        # Remove common words
        stopwords = {"the", "a", "an", "and", "or", "but", "in", "on", "at", "to", "for", 
                     "of", "with", "by", "from", "as", "is", "was", "are", "were", "be", "been"}
        return {w for w in words if len(w) > 3 and w not in stopwords}

    def _calculate_keyword_similarity(self, keywords1: set, keywords2: set) -> float:
        """Calculate keyword-based similarity."""
        if not keywords1 or not keywords2:
            return 0.0
        
        intersection = len(keywords1 & keywords2)
        union = len(keywords1 | keywords2)
        
        return intersection / union if union > 0 else 0.0

    def _find_alternative_controls(self, keywords: set, controls: List[Dict], exclude_id: str) -> List[str]:
        """Find alternative controls matching keywords."""
        alternatives = []
        for ctrl in controls:
            if ctrl.get("control_id") == exclude_id:
                continue
            ctrl_keywords = self._extract_keywords(ctrl.get("description", ""))
            similarity = self._calculate_keyword_similarity(keywords, ctrl_keywords)
            if similarity > 0.2:
                alternatives.append(ctrl.get("control_id"))
        return alternatives[:3]

    def verify_mapping_coverage(self, regulation_id: str) -> Dict[str, Any]:
        """Verify mapping coverage for a regulation.
        
        Args:
            regulation_id: Regulation to verify
            
        Returns:
            Coverage verification report
        """
        regulation = self.store.get_regulation(regulation_id)
        if not regulation:
            return {"error": "Regulation not found"}
        
        requirements = regulation.get("requirements", [])
        controls = self.store.get_controls_for_regulation(regulation_id)
        
        coverage_details = []
        gaps = []
        
        for req in requirements:
            req_id = req.get("id", "")
            mapped_controls = [
                c for c in controls
                if c.get("mapping", {}).get("requirement_id") == req_id
            ]
            
            is_covered = len(mapped_controls) > 0
            status = "COMPLIANT" if is_covered else "GAP"
            
            coverage_details.append({
                "requirement_id": req_id,
                "requirement_name": req.get("name", ""),
                "status": status,
                "mapped_controls": [c.get("control_id") for c in mapped_controls],
            })
            
            if not is_covered:
                gaps.append({
                    "requirement_id": req_id,
                    "requirement_name": req.get("name", ""),
                    "description": req.get("description", ""),
                    "severity": req.get("severity", "MEDIUM"),
                })
        
        return {
            "regulation_id": regulation_id,
            "total_requirements": len(requirements),
            "covered_requirements": len([c for c in coverage_details if c["status"] == "COMPLIANT"]),
            "coverage_percentage": len([c for c in coverage_details if c["status"] == "COMPLIANT"]) / len(requirements) * 100 if requirements else 0,
            "gaps": gaps,
            "coverage_details": coverage_details,
        }

    def export_mapping_report(self, regulation_id: str, format: str = "json") -> Dict[str, Any]:
        """Export mapping report for a regulation.
        
        Args:
            regulation_id: Regulation to export
            format: Export format (json, csv)
            
        Returns:
            Export data
        """
        matrix = self.get_mapping_matrix(regulation_id)
        verification = self.verify_mapping_coverage(regulation_id)
        
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "regulation": self.store.get_regulation(regulation_id),
            "mapping_matrix": matrix,
            "verification": verification,
        }


def get_policy_mapper() -> PolicyMappingEngine:
    """Get the global policy mapper instance."""
    from .store import get_compliance_store
    store = get_compliance_store()
    return PolicyMappingEngine(store)