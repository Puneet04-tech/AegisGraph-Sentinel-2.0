"""
Forensics Agent.

Performs digital forensics analysis, evidence collection, and chain of custody tracking.
"""

import hashlib
import hmac
import json
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
import logging

from .models import (
    AgentTask,
    AgentType,
    TaskPriority,
    ForensicAnalysis,
)
from src.graph_analytics.service import GraphService, get_graph_service

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
    
    #: Depth of the neighbourhood examined when collecting artifacts for an
    #: entity. Evidence is drawn from the entity and its direct counterparties.
    COLLECTION_DEPTH = 1

    #: Edge types that constitute each class of artifact, so artifact counts are
    #: the number of records actually present rather than a random figure.
    ARTIFACT_EDGE_TYPES = {
        "transaction_log": ("sent_to", "received_from"),
        "access_log": ("accessed",),
        "communication_log": ("communicated_with",),
    }

    #: Which artifact classes each analysis type collects. "comprehensive"
    #: collects every class.
    ANALYSIS_ARTIFACTS = {
        "transaction": ("transaction_log",),
        "access": ("access_log",),
        "communication": ("communication_log",),
    }

    #: Risk score at or above which an artifact's subject is treated as
    #: anomalous rather than ordinary.
    ANOMALY_RISK_THRESHOLD = 0.7

    #: Risk score at or above which a finding is escalated to critical.
    CRITICAL_RISK_THRESHOLD = 0.85

    #: Number of anomalies at or above which the conclusion becomes CRITICAL.
    CRITICAL_ANOMALY_COUNT = 3

    #: Maximum number of timeline events reconstructed, so an entity with a
    #: large history does not produce an unbounded analysis record.
    MAX_TIMELINE_EVENTS = 500

    def __init__(
        self,
        store: Optional[SOCStore] = None,
        graph: Optional[GraphService] = None,
    ):
        """Initialize the forensics agent.

        Args:
            store: Optional SOC store
            graph: Optional graph analytics service supplying the artifacts and
                timeline under examination; defaults to the shared instance
        """
        self._store = store or get_soc_store()
        self._graph = graph or get_graph_service()
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

        # Artifacts, timeline and findings are all drawn from one traversal of
        # the real graph. Artifact record counts were previously random ints and
        # every finding's `anomaly_detected` flag was a coin flip, which the
        # conclusion then counted — so the forensic verdict of CRITICAL or CLEAR
        # was decided by dice and differed on every run over the same entity.
        nodes, edges = self._collect_evidence_scope(target_entity_id, context)

        # Collect artifacts
        artifacts = self._collect_artifacts(
            target_entity_id, analysis_type, context, nodes, edges
        )

        # Reconstruct timeline
        timeline_events = self._reconstruct_timeline(target_entity_id, edges)

        # Generate findings
        findings = self._analyze_artifacts(artifacts, analysis_type)

        # Calculate evidence hash before the chain records the seal, so the
        # sealed hash is the one an examiner can recompute from the artifacts.
        evidence_hash = self._calculate_evidence_hash(artifacts)

        # Create chain of custody
        chain_of_custody = self._create_chain_of_custody(
            target_entity_id, artifacts, evidence_hash
        )

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
            confidence=self._calculate_confidence(artifacts, timeline_events),
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
        
        _, edges = self._collect_evidence_scope(entity_id, {})

        evidence_items = []
        for ev_type in evidence_types:
            collected_at = datetime.now(timezone.utc).isoformat()

            # Records backing this evidence type, so the hash covers the actual
            # material rather than just the entity and type strings. The old
            # hash was derived from `f"{entity_id}_{ev_type}"` alone, meaning
            # two different bodies of evidence for one entity hashed
            # identically and tampering could not be detected.
            edge_types = self.ARTIFACT_EDGE_TYPES.get(ev_type, ())
            records = sorted(
                str(edge.get("edge_id"))
                for edge in edges
                if str(edge.get("edge_type", "")).lower() in edge_types
                and edge.get("edge_id")
            )

            payload = json.dumps(
                {"entity_id": entity_id, "type": ev_type, "records": records},
                sort_keys=True,
                separators=(",", ":"),
            )
            digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()

            item = {
                "type": ev_type,
                "entity_id": entity_id,
                "collected_at": collected_at,
                "collector": self._agent_id,
                "hash": digest,
                "record_count": len(records),
                "record_ids": records,
                # Only claimed when the evidence has record ids the digest is
                # computed over, so an examiner can re-derive it. This was
                # hardcoded to True, so evidence collected for an entity the
                # graph held nothing for was still presented as
                # integrity-verified.
                "integrity_verified": bool(records),
            }

            if preserve_chain:
                item["chain_of_custody"] = {
                    "collected_by": self._agent_id,
                    "collection_time": collected_at,
                    "hash": digest,
                    "record_count": len(records),
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
        # Absent hashes must never compare equal, or a record with no recorded
        # hash would verify against another with none.
        if not evidence_hash or not current_hash:
            return False

        # Constant-time comparison: this decides whether evidence is presented
        # as untampered, so it should not leak the matching prefix length.
        return hmac.compare_digest(str(evidence_hash), str(current_hash))
    
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
    
    def _collect_evidence_scope(
        self,
        entity_id: str,
        context: Dict[str, Any],
    ) -> tuple:
        """Retrieve the entity's real neighbourhood as the evidence scope.

        Args:
            entity_id: Entity under examination
            context: Additional context; a ``collection_depth`` override is
                honoured

        Returns:
            Tuple of ({node_id: node dict}, list of edge dicts). Both are empty
            when the graph holds nothing for the entity or is unavailable, which
            the caller reports as an absence of evidence rather than as a clean
            result.
        """
        depth = int(context.get("collection_depth", self.COLLECTION_DEPTH))

        try:
            network = self._graph.get_entity_network(entity_id, depth=depth)
        except Exception as e:
            logger.error(
                "Failed to collect evidence scope for %s: %s", entity_id, e, exc_info=True
            )
            return {}, []

        nodes = {
            node["node_id"]: node
            for node in network.get("nodes", [])
            if node.get("node_id")
        }
        edges = [
            edge
            for edge in network.get("edges", [])
            if edge.get("source_id") and edge.get("target_id")
        ]

        return nodes, edges

    def _collect_artifacts(
        self,
        entity_id: str,
        analysis_type: str,
        context: Dict[str, Any],
        nodes: Dict[str, Dict[str, Any]],
        edges: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Collect forensic artifacts.

        Record counts are the number of graph records actually present. They
        were previously `random.randint` draws, and every artifact asserted
        `integrity: "verified"` without anything having been verified.
        """
        artifacts = []

        requested = self.ANALYSIS_ARTIFACTS.get(analysis_type)
        if analysis_type == "comprehensive" or requested is None:
            # An unrecognised analysis type collects everything rather than
            # silently returning no evidence.
            requested = tuple(self.ARTIFACT_EDGE_TYPES)

        for artifact_type in requested:
            edge_types = self.ARTIFACT_EDGE_TYPES[artifact_type]
            matching = [
                edge for edge in edges
                if str(edge.get("edge_type", "")).lower() in edge_types
            ]

            artifacts.append({
                "type": artifact_type,
                "count": len(matching),
                "source": "security_graph",
                # Integrity is only claimed for records that carry the
                # provenance needed to re-derive them.
                "integrity": (
                    "verified" if matching and all(e.get("edge_id") for e in matching)
                    else "unverified"
                ),
                "record_ids": sorted(
                    str(e.get("edge_id")) for e in matching if e.get("edge_id")
                ),
            })

        # Device fingerprints come from device nodes actually linked to the
        # entity, rather than hashing the entity id and calling it a device.
        device_ids = sorted(
            node_id
            for node_id, node in nodes.items()
            if str(node.get("node_type", "")).lower() == "device"
        )
        for device_id in device_ids:
            artifacts.append({
                "type": "device_fingerprint",
                "device_id": device_id,
                "fingerprint": hashlib.sha256(device_id.encode()).hexdigest()[:32],
                "source": "security_graph",
                "integrity": "verified",
            })

        return artifacts

    def _reconstruct_timeline(
        self,
        entity_id: str,
        edges: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Reconstruct activity timeline.

        Events are the real edges incident to the entity, ordered by their
        recorded timestamp. This previously emitted 5-20 events all stamped with
        `datetime.now()` and given a random event type and outcome, so the
        "reconstruction" described activity that never happened and every event
        appeared to occur at the moment of analysis.
        """
        events = []

        for edge in edges:
            timestamp = edge.get("created_at")
            if not isinstance(timestamp, str) or not timestamp:
                # An undated record cannot be placed on a timeline.
                continue

            properties = edge.get("properties") or {}
            events.append({
                "timestamp": timestamp,
                "event_type": str(edge.get("edge_type", "linked_to")),
                "details": {
                    "source_entity": edge.get("source_id"),
                    "target_entity": edge.get("target_id"),
                    "record_id": edge.get("edge_id"),
                    "result": properties.get("result", "recorded"),
                },
                "source": properties.get("channel", "security_graph"),
            })

        # edge_id breaks ties so the ordering is stable for records sharing a
        # timestamp, which matters when the timeline is cited as evidence.
        events.sort(key=lambda e: (e["timestamp"], str(e["details"]["record_id"])))
        return events[: self.MAX_TIMELINE_EVENTS]

    def _create_chain_of_custody(
        self,
        entity_id: str,
        artifacts: List[Dict[str, Any]],
        evidence_hash: str,
    ) -> List[Dict[str, Any]]:
        """Create chain of custody record.

        The seal entry now carries the hash it was sealed with and the artifact
        count it covers. It previously claimed "sealed with hash verification"
        without recording any hash, so the claim could not be checked.
        """
        collected_at = datetime.now(timezone.utc).isoformat()

        return [
            {
                "action": "evidence_collected",
                "timestamp": collected_at,
                "actor": self._agent_id,
                "description": (
                    f"Collected {len(artifacts)} artifacts for {entity_id} "
                    "from the security graph"
                ),
                "artifact_count": len(artifacts),
            },
            {
                "action": "evidence_sealed",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "actor": self._agent_id,
                "description": "Evidence sealed under SHA-256 over the collected artifacts",
                "evidence_hash": evidence_hash,
                "artifact_count": len(artifacts),
            },
        ]

    def _analyze_artifacts(
        self,
        artifacts: List[Dict[str, Any]],
        analysis_type: str,
    ) -> List[Dict[str, Any]]:
        """Analyze collected artifacts.

        Significance and anomaly detection now follow the evidence. Both were
        `random.choice`, so an artifact with no records could be reported as a
        critical anomaly and the same artifact varied between runs.
        """
        findings = []

        for artifact in artifacts:
            artifact_type = artifact.get("type")

            if artifact_type == "device_fingerprint":
                # A fingerprint is corroborating detail, not an anomaly in
                # itself; it is reported without raising a finding severity.
                findings.append({
                    "artifact_type": artifact_type,
                    "significance": "low",
                    "anomaly_detected": False,
                    "recommendation": "log_only",
                    "basis": f"Device {artifact.get('device_id')} linked to entity",
                })
                continue

            count = int(artifact.get("count", 0) or 0)
            unverified = artifact.get("integrity") != "verified"

            if count == 0:
                findings.append({
                    "artifact_type": artifact_type,
                    "significance": "low",
                    "anomaly_detected": False,
                    "recommendation": "log_only",
                    "basis": "No records of this type present for the entity",
                })
                continue

            # Records that cannot be re-derived are themselves the finding.
            if unverified:
                findings.append({
                    "artifact_type": artifact_type,
                    "significance": "high",
                    "anomaly_detected": True,
                    "recommendation": "review_required",
                    "basis": f"{count} records lack the provenance to verify integrity",
                })
                continue

            findings.append({
                "artifact_type": artifact_type,
                "significance": "medium",
                "anomaly_detected": False,
                "recommendation": "monitor",
                "basis": f"{count} records collected and integrity verified",
            })

        return findings

    def _calculate_evidence_hash(self, artifacts: List[Dict[str, Any]]) -> str:
        """Calculate evidence integrity hash.

        Hashes a canonical JSON serialisation. This previously hashed
        `str(sorted(artifacts, ...))`, the repr of a list of dicts, which is
        sensitive to key insertion order and to Python's formatting of floats,
        so a re-collection of identical evidence could hash differently and an
        integrity check would report tampering where none occurred.
        """
        canonical = json.dumps(
            sorted(artifacts, key=lambda a: (str(a.get("type", "")), str(a.get("device_id", "")))),
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def _calculate_confidence(
        self,
        artifacts: List[Dict[str, Any]],
        timeline_events: List[Dict[str, Any]],
    ) -> float:
        """Score how well the collected evidence supports the analysis.

        Confidence was a flat `random.uniform(0.75, 0.95)` draw, so an analysis
        that found no evidence at all was reported at least as confidently as
        one built on a full record set.
        """
        record_count = sum(
            int(a.get("count", 0) or 0)
            for a in artifacts
            if a.get("type") != "device_fingerprint"
        )

        if record_count == 0 and not timeline_events:
            # Nothing was collected; the analysis establishes nothing.
            return 0.1

        # Saturates at 50 records, beyond which more of the same adds little.
        record_support = min(record_count, 50) / 50.0
        timeline_support = min(len(timeline_events), 50) / 50.0

        verified = [
            a for a in artifacts
            if a.get("type") != "device_fingerprint" and a.get("integrity") == "verified"
        ]
        examined = [a for a in artifacts if a.get("type") != "device_fingerprint"]
        integrity_support = len(verified) / len(examined) if examined else 0.0

        confidence = (
            0.15
            + 0.35 * record_support
            + 0.25 * timeline_support
            + 0.25 * integrity_support
        )
        return round(min(0.95, confidence), 2)


    def _generate_conclusion(self, findings: List[Dict[str, Any]], analysis_type: str) -> str:
        """Generate forensic conclusion.

        The thresholds are unchanged, but they now count anomalies that were
        actually observed. Previously each `anomaly_detected` flag was a coin
        flip, so this returned CRITICAL, SUSPICIOUS or CLEAR at random over the
        same entity.

        A distinct INCONCLUSIVE verdict is returned when no evidence was
        collected. Reporting that as CLEAR asserted the entity was clean when
        the truth was that nothing had been examined.
        """
        examined = [f for f in findings if f.get("artifact_type") != "device_fingerprint"]
        has_records = any(
            "No records of this type present" not in str(f.get("basis", ""))
            for f in examined
        )

        if not examined or not has_records:
            return (
                f"INCONCLUSIVE: no {analysis_type} evidence available for examination"
            )

        anomalies = sum(1 for f in findings if f.get("anomaly_detected"))

        if anomalies >= self.CRITICAL_ANOMALY_COUNT:
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