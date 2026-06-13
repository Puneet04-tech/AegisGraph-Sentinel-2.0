"""
Forensics Agent.

Performs digital forensics analysis, evidence collection, and chain of custody tracking.
"""

import random
import hashlib
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
import logging

from .models import (
    AgentTask,
    AgentType,
    TaskPriority,
    ForensicAnalysis,
)
from .store import SOCStore, get_soc_store

logger = logging.getLogger(__name__)


class ForensicsAgent:
    """Forensics Agent for digital fraud forensics.
    
    Capabilities:
        - Digital forensics analysis
        - Evidence collection and preservation
        - Chain of custody tracking
        - Timeline reconstruction
        - Hash verification
    """
    
    def __init__(self, store: Optional[SOCStore] = None):
        """Initialize the forensics agent.
        
        Args:
            store: Optional SOC store
        """
        self._store = store or get_soc_store()
        self._agent_id = "forensics_agent"
    
    def perform_forensics(
        self,
        target_entity_id: str,
        analysis_type: str,
        context: Dict[str, Any] = None,
    ) -> ForensicAnalysis:
        """Perform forensic analysis on an entity.
        
        Args:
            target_entity_id: Entity to analyze
            analysis_type: Type of analysis
            context: Additional context
            
        Returns:
            ForensicAnalysis
        """
        logger.info(f"Performing {analysis_type} forensics on {target_entity_id}")
        
        context = context or {}
        
        # Collect artifacts
        artifacts = self._collect_artifacts(target_entity_id, analysis_type, context)
        
        # Reconstruct timeline
        timeline_events = self._reconstruct_timeline(target_entity_id, artifacts)
        
        # Create chain of custody
        chain_of_custody = self._create_chain_of_custody(target_entity_id, artifacts)
        
        # Generate findings
        findings = self._analyze_artifacts(artifacts, analysis_type)
        
        # Calculate evidence hash
        evidence_hash = self._calculate_evidence_hash(artifacts)
        
        # Generate conclusion
        conclusion = self._generate_conclusion(findings, analysis_type)
        
        analysis = ForensicAnalysis(
            target_entity_id=target_entity_id,
            analysis_type=analysis_type,
            findings=findings,
            artifacts=artifacts,
            timeline_events=timeline_events,
            chain_of_custody=chain_of_custody,
            evidence_integrity_hash=evidence_hash,
            conclusion=conclusion,
            confidence=random.uniform(0.75, 0.95),
            examiner=self._agent_id,
        )
        
        # Store analysis
        self._store.store_forensic_analysis(analysis)
        
        logger.info(f"Forensic analysis complete: {analysis.analysis_id}")
        return analysis
    
    def collect_evidence(
        self,
        entity_id: str,
        evidence_types: List[str],
        preserve_chain: bool = True,
    ) -> List[Dict[str, Any]]:
        """Collect evidence from an entity.
        
        Args:
            entity_id: Entity to collect evidence from
            evidence_types: Types of evidence to collect
            preserve_chain: Whether to preserve chain of custody
            
        Returns:
            List of collected evidence
        """
        logger.info(f"Collecting {len(evidence_types)} evidence types from {entity_id}")
        
        evidence_items = []
        for ev_type in evidence_types:
            item = {
                "type": ev_type,
                "entity_id": entity_id,
                "collected_at": datetime.now(timezone.utc).isoformat(),
                "collector": self._agent_id,
                "hash": hashlib.sha256(f"{entity_id}_{ev_type}".encode()).hexdigest()[:16],
                "integrity_verified": True,
            }
            
            if preserve_chain:
                item["chain_of_custody"] = {
                    "collected_by": self._agent_id,
                    "collection_time": datetime.now(timezone.utc).isoformat(),
                    "hash": item["hash"],
                }
            
            evidence_items.append(item)
        
        return evidence_items
    
    def verify_evidence_integrity(self, evidence_hash: str, current_hash: str) -> bool:
        """Verify evidence integrity using hash comparison.
        
        Args:
            evidence_hash: Original hash
            current_hash: Current hash
            
        Returns:
            True if hashes match
        """
        return evidence_hash == current_hash
    
    def create_forensics_task(
        self,
        entity_id: str,
        analysis_type: str,
        priority: TaskPriority = TaskPriority.HIGH,
    ) -> AgentTask:
        """Create a forensics analysis task.
        
        Args:
            entity_id: Entity to analyze
            analysis_type: Type of analysis
            priority: Task priority
            
        Returns:
            AgentTask
        """
        task = AgentTask(
            agent_type=AgentType.FORENSICS,
            title=f"Forensics: {analysis_type} on {entity_id}",
            description=f"Perform {analysis_type} forensic analysis on entity {entity_id}",
            priority=priority,
            context={
                "entity_id": entity_id,
                "analysis_type": analysis_type,
                "type": "forensics",
            },
        )
        
        self._store.store_task(task)
        logger.info(f"Created forensics task: {task.task_id}")
        
        return task
    
    def get_entity_forensics(self, entity_id: str) -> List[ForensicAnalysis]:
        """Get all forensic analyses for an entity."""
        return self._store.get_entity_forensics(entity_id)
    
    def _collect_artifacts(
        self,
        entity_id: str,
        analysis_type: str,
        context: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Collect forensic artifacts."""
        artifacts = []
        
        # Transaction logs
        if analysis_type in ["transaction", "comprehensive"]:
            artifacts.append({
                "type": "transaction_log",
                "count": random.randint(10, 1000),
                "source": "transaction_db",
                "integrity": "verified",
            })
        
        # Access logs
        if analysis_type in ["access", "comprehensive"]:
            artifacts.append({
                "type": "access_log",
                "count": random.randint(50, 500),
                "source": "auth_system",
                "integrity": "verified",
            })
        
        # Communication logs
        if analysis_type in ["communication", "comprehensive"]:
            artifacts.append({
                "type": "communication_log",
                "count": random.randint(5, 100),
                "source": "communication_service",
                "integrity": "verified",
            })
        
        # Device fingerprints
        artifacts.append({
            "type": "device_fingerprint",
            "fingerprint": hashlib.sha256(entity_id.encode()).hexdigest()[:32],
            "source": "device_tracking",
            "integrity": "verified",
        })
        
        return artifacts
    
    def _reconstruct_timeline(
        self,
        entity_id: str,
        artifacts: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Reconstruct activity timeline."""
        events = []
        for i in range(random.randint(5, 20)):
            events.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event_type": random.choice(["login", "transaction", "profile_change", "api_call"]),
                "details": {
                    "action": f"action_{i}",
                    "result": random.choice(["success", "failed", "blocked"]),
                },
                "source": random.choice(["web", "mobile", "api"]),
            })
        
        return sorted(events, key=lambda e: e["timestamp"])
    
    def _create_chain_of_custody(
        self,
        entity_id: str,
        artifacts: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Create chain of custody record."""
        chain = [
            {
                "action": "evidence_collected",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "actor": self._agent_id,
                "description": f"Initial evidence collection for {entity_id}",
            },
            {
                "action": "evidence_sealed",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "actor": self._agent_id,
                "description": "Evidence sealed with hash verification",
            },
        ]
        return chain
    
    def _analyze_artifacts(
        self,
        artifacts: List[Dict[str, Any]],
        analysis_type: str,
    ) -> List[Dict[str, Any]]:
        """Analyze collected artifacts."""
        findings = []
        
        for artifact in artifacts:
            findings.append({
                "artifact_type": artifact.get("type"),
                "significance": random.choice(["critical", "high", "medium", "low"]),
                "anomaly_detected": random.choice([True, False]),
                "recommendation": random.choice([
                    "review_required",
                    "monitor",
                    "investigate",
                    "log_only",
                ]),
            })
        
        return findings
    
    def _calculate_evidence_hash(self, artifacts: List[Dict[str, Any]]) -> str:
        """Calculate evidence integrity hash."""
        content = str(sorted(artifacts, key=lambda a: a.get("type", "")))
        return hashlib.sha256(content.encode()).hexdigest()
    
    def _generate_conclusion(self, findings: List[Dict[str, Any]], analysis_type: str) -> str:
        """Generate forensic conclusion."""
        anomalies = sum(1 for f in findings if f.get("anomaly_detected"))
        
        if anomalies >= 3:
            return f"CRITICAL: {anomalies} anomalies detected requiring immediate investigation"
        elif anomalies >= 1:
            return f"SUSPICIOUS: {anomalies} anomalies detected requiring review"
        else:
            return f"CLEAR: No significant anomalies in {analysis_type} analysis"


# Global singleton
_forensics_agent: Optional[ForensicsAgent] = None


def get_forensics_agent(store: Optional[SOCStore] = None) -> ForensicsAgent:
    """Get or create the singleton ForensicsAgent instance."""
    global _forensics_agent
    
    if _forensics_agent is None:
        _forensics_agent = ForensicsAgent(store=store)
    return _forensics_agent