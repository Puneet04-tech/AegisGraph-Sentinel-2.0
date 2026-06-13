"""
Fraud Narrative Generator for AI-powered report generation.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from .models import (
    InvestigationCase,
    EvidenceArtifact,
    FraudNarrative,
    InvestigationTimeline,
)


class FraudNarrativeGenerator:
    """
    Generates AI-powered fraud narratives and investigation reports.

    Handles:
    - Narrative summary generation
    - Timeline reconstruction
    - Finding documentation
    - Report formatting
    """

    async def generate_narrative(
        self,
        case: InvestigationCase,
        evidence: List[EvidenceArtifact],
        findings: List[Dict[str, Any]],
    ) -> FraudNarrative:
        """Generate comprehensive fraud narrative."""
        # Generate narrative sections
        summary = self._generate_summary(case, evidence)
        detailed = self._generate_detailed_narrative(case, evidence, findings)
        timeline_desc = self._generate_timeline_description(case, evidence)
        indicators = self._extract_fraud_indicators(evidence)
        affected = self._extract_affected_entities(case, evidence)
        impact = self._estimate_financial_impact(case, evidence)

        narrative = FraudNarrative(
            narrative_id=str(uuid.uuid4()),
            case_id=case.case_id,
            summary=summary,
            detailed_narrative=detailed,
            key_findings=self._extract_key_findings(findings),
            timeline_description=timeline_desc,
            fraud_indicators=indicators,
            affected_entities=affected,
            financial_impact=impact,
            generated_at=datetime.now(timezone.utc),
            narrative_type="full",
            confidence_score=self._calculate_confidence(evidence, findings),
        )

        return narrative

    async def generate_timeline(
        self,
        case: InvestigationCase,
        evidence: List[EvidenceArtifact],
    ) -> InvestigationTimeline:
        """Generate investigation timeline."""
        events = self._reconstruct_events(evidence)
        sequence = self._build_sequence(events)
        critical_path = self._identify_critical_path(events)
        anomalies = self._detect_timeline_anomalies(events)

        timeline = InvestigationTimeline(
            timeline_id=str(uuid.uuid4()),
            case_id=case.case_id,
            events=events,
            reconstructed_sequence=sequence,
            critical_path=critical_path,
            anomalies_detected=anomalies,
            generated_at=datetime.now(timezone.utc),
        )

        return timeline

    async def generate_executive_summary(
        self,
        case: InvestigationCase,
        narrative: FraudNarrative,
    ) -> str:
        """Generate executive summary."""
        summary = f"Investigation ID: {case.case_id}\n"
        summary += f"Title: {case.title}\n\n"
        summary += f"Risk Level: {case.severity.value.upper()}\n"
        summary += f"Priority: {case.priority.value.upper()}\n\n"
        summary += f"Summary:\n{narrative.summary}\n\n"
        summary += "Key Findings:\n"
        for i, finding in enumerate(narrative.key_findings[:5], 1):
            summary += f"  {i}. {finding}\n"
        summary += "\nRecommended Actions:\n"
        summary += "  - Review evidence within 24 hours\n"
        summary += "  - Determine appropriate action based on risk level\n"
        return summary

    def _generate_summary(
        self,
        case: InvestigationCase,
        evidence: List[EvidenceArtifact],
    ) -> str:
        """Generate narrative summary."""
        summary = f"This investigation was initiated to analyze {len(evidence)} "
        summary += f"pieces of evidence related to {len(case.entity_ids)} entities. "

        if case.patterns_detected:
            summary += f"Analysis revealed {len(case.patterns_detected)} potential "
            summary += "fraud patterns. "

        if case.correlations_found > 0:
            summary += f"{case.correlations_found} entity correlations were "
            summary += "identified. "

        summary += f"The overall risk assessment is {case.severity.value} "
        summary += f"with a confidence score of {case.confidence_score:.0%}."

        return summary

    def _generate_detailed_narrative(
        self,
        case: InvestigationCase,
        evidence: List[EvidenceArtifact],
        findings: List[Dict[str, Any]],
    ) -> str:
        """Generate detailed narrative."""
        narrative = "## Investigation Details\n\n"

        # Background
        narrative += "### Background\n"
        narrative += f"{case.description}\n\n"

        # Evidence Summary
        narrative += "### Evidence Summary\n"
        narrative += f"A total of {len(evidence)} evidence items were collected and analyzed. "
        narrative += "Key evidence types include:\n"
        evidence_types = set(e.evidence_type.value for e in evidence)
        for etype in evidence_types:
            count = sum(1 for e in evidence if e.evidence_type.value == etype)
            narrative += f"- {etype.title()}: {count} items\n"
        narrative += "\n"

        # Findings
        if findings:
            narrative += "### Key Findings\n"
            for i, finding in enumerate(findings[:10], 1):
                desc = finding.get("description", str(finding))
                narrative += f"{i}. {desc}\n"
            narrative += "\n"

        # Patterns
        if case.patterns_detected:
            narrative += "### Detected Patterns\n"
            for pattern in case.patterns_detected:
                narrative += f"- {pattern}\n"
            narrative += "\n"

        return narrative

    def _generate_timeline_description(
        self,
        case: InvestigationCase,
        evidence: List[EvidenceArtifact],
    ) -> str:
        """Generate timeline description."""
        timeline = "## Event Timeline\n\n"

        if case.started_at:
            timeline += f"Investigation started: {case.started_at.strftime('%Y-%m-%d %H:%M')}\n"

        # Sort evidence by time
        sorted_evidence = sorted(
            evidence, key=lambda e: e.collected_at
        )

        if sorted_evidence:
            timeline += f"\nEvidence collected from {sorted_evidence[0].collected_at.strftime('%Y-%m-%d %H:%M')} "
            timeline += f"to {sorted_evidence[-1].collected_at.strftime('%Y-%m-%d %H:%M')}\n"

        if case.completed_at:
            timeline += f"Investigation completed: {case.completed_at.strftime('%Y-%m-%d %H:%M')}\n"

        return timeline

    def _extract_fraud_indicators(
        self,
        evidence: List[EvidenceArtifact],
    ) -> List[str]:
        """Extract fraud indicators from evidence."""
        indicators = []

        for e in evidence:
            content = e.content
            evidence_type = e.evidence_type.value

            if evidence_type == "transaction":
                if content.get("velocity", 0) > 5:
                    indicators.append("High transaction velocity detected")
                if content.get("amount", 0) > 10000:
                    indicators.append("High-value transaction")
                if content.get("unusual_pattern"):
                    indicators.append("Unusual transaction pattern")

            elif evidence_type == "device":
                if content.get("is_new_device"):
                    indicators.append("First-time device usage")
                if content.get("risk_score", 0) > 0.7:
                    indicators.append("High-risk device")

            elif evidence_type == "ip_address":
                if content.get("is_vpn") or content.get("is_proxy"):
                    indicators.append("Anonymous network detected")

        return list(set(indicators))[:10]

    def _extract_affected_entities(
        self,
        case: InvestigationCase,
        evidence: List[EvidenceArtifact],
    ) -> List[str]:
        """Extract affected entity IDs."""
        entities = list(case.entity_ids)
        for e in evidence:
            if hasattr(e, 'entity_id') and e.entity_id not in entities:
                entities.append(e.entity_id)
        return entities[:20]

    def _estimate_financial_impact(
        self,
        case: InvestigationCase,
        evidence: List[EvidenceArtifact],
    ) -> Optional[float]:
        """Estimate financial impact."""
        total = 0.0

        for e in evidence:
            if e.evidence_type.value == "transaction":
                amount = e.content.get("amount", 0)
                total += amount

        return total if total > 0 else None

    def _extract_key_findings(
        self,
        findings: List[Dict[str, Any]],
    ) -> List[str]:
        """Extract key findings as strings."""
        key_findings = []

        for finding in findings[:5]:
            if isinstance(finding, dict):
                desc = finding.get("description", "")
            else:
                desc = str(finding)
            if desc:
                key_findings.append(desc)

        return key_findings

    def _calculate_confidence(
        self,
        evidence: List[EvidenceArtifact],
        findings: List[Dict[str, Any]],
    ) -> float:
        """Calculate narrative confidence."""
        confidence = 0.5

        # More evidence = higher confidence
        if evidence:
            confidence += min(0.3, len(evidence) * 0.03)

        # Verified evidence increases confidence
        verified_count = sum(1 for e in evidence if e.is_verified)
        if evidence:
            verified_ratio = verified_count / len(evidence)
            confidence += verified_ratio * 0.2

        return min(1.0, confidence)

    def _reconstruct_events(
        self,
        evidence: List[EvidenceArtifact],
    ) -> List[Dict[str, Any]]:
        """Reconstruct events from evidence."""
        events = []

        for e in evidence:
            events.append({
                "timestamp": e.collected_at.isoformat(),
                "type": e.evidence_type.value,
                "description": f"Evidence collected: {e.source_system}",
                "importance": "high" if e.relevance_score > 0.8 else "medium",
            })

        return sorted(events, key=lambda x: x["timestamp"])

    def _build_sequence(
        self,
        events: List[Dict[str, Any]],
    ) -> List[str]:
        """Build chronological sequence."""
        return [f"{i + 1}. {e['type']} at {e['timestamp']}" for i, e in enumerate(events)]

    def _identify_critical_path(
        self,
        events: List[Dict[str, Any]],
    ) -> List[str]:
        """Identify critical path events."""
        return [e["type"] for e in events if e.get("importance") == "high"]

    def _detect_timeline_anomalies(
        self,
        events: List[Dict[str, Any]],
    ) -> List[str]:
        """Detect anomalies in timeline."""
        anomalies = []

        if len(events) < 2:
            return anomalies

        # Check for time gaps
        for i in range(1, len(events)):
            t1 = datetime.fromisoformat(events[i - 1]["timestamp"])
            t2 = datetime.fromisoformat(events[i]["timestamp"])
            gap_hours = (t2 - t1).total_seconds() / 3600

            if gap_hours > 24:
                anomalies.append(
                    f"Large time gap ({gap_hours:.1f} hours) between events"
                )

        return anomalies


# Global generator instance
_generator: Optional[FraudNarrativeGenerator] = None


def get_report_generator() -> FraudNarrativeGenerator:
    """Get the report generator instance."""
    global _generator
    if _generator is None:
        _generator = FraudNarrativeGenerator()
    return _generator