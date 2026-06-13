"""
Data Lineage Service - Core business logic
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .models import (
    DataRecord,
    LineageNode,
    LineageEdge,
    ProvenanceChain,
    ImpactAnalysis,
    DependencyGraph,
    SourceAttribution,
    TraceabilityRecord,
    LineageStats,
    LineageQuery,
    RecordType,
    ImpactLevel,
)
from .store import get_lineage_store, LineageStore


class LineageService:
    """
    Core service for data lineage and provenance operations.
    Provides tracking, tracing, and analysis of data records.
    """

    def __init__(self, store: Optional[LineageStore] = None):
        self._store = store or get_lineage_store()
        self._lock = threading.RLock()

    def create_record(
        self,
        record_type: RecordType,
        data: Dict[str, Any],
        source: Optional[SourceAttribution] = None,
        created_by: str = "system",
        tags: Optional[List[str]] = None,
    ) -> DataRecord:
        """Create a new data record with lineage tracking."""
        with self._lock:
            record = DataRecord(
                record_type=record_type,
                data=data,
                source=source,
                created_by=created_by,
                tags=tags or [],
            )

            # Create initial lineage node
            root_node = LineageNode(
                record_id=record.record_id,
                record_type=record_type,
                label=f"Created {record_type.value}",
                is_root=True,
                tags=record.tags,
            )
            record.lineage_nodes.append(root_node)

            # Store the record and node
            self._store.store_record(record)
            self._store.store_node(root_node)

            # Create traceability record
            trace = TraceabilityRecord(
                record_id=record.record_id,
                action="create",
                actor=created_by,
                details={"record_type": record_type.value},
                new_state="created",
            )
            record.traceability_records.append(trace)

            return record

    def link_records(
        self,
        parent_id: str,
        child_id: str,
        relationship_type: str,
        impact_level: ImpactLevel = ImpactLevel.MEDIUM,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Link two records with a lineage relationship."""
        with self._lock:
            parent = self._store.get_record(parent_id)
            child = self._store.get_record(child_id)

            if not parent or not child:
                return False

            # Create lineage nodes if they don't exist
            parent_node = LineageNode(
                record_id=parent_id,
                record_type=parent.record_type,
                label=f"Parent of {child_id}",
            )
            child_node = LineageNode(
                record_id=child_id,
                record_type=child.record_type,
                label=f"Child of {parent_id}",
            )

            self._store.store_node(parent_node)
            self._store.store_node(child_node)

            # Create edge
            edge = LineageEdge(
                source_node_id=parent_node.node_id,
                target_node_id=child_node.node_id,
                relationship_type=relationship_type,
                impact_level=impact_level,
                metadata=metadata or {},
            )
            self._store.store_edge(edge)

            # Update provenance chain
            child.provenance_chain.append(parent_id)
            child.lineage_nodes.append(child_node)
            self._store.store_record(child)

            # Update traceability
            trace = TraceabilityRecord(
                record_id=child_id,
                action="link",
                actor="system",
                details={
                    "parent_id": parent_id,
                    "relationship_type": relationship_type,
                },
                previous_state="unlinked",
                new_state="linked",
            )
            child.traceability_records.append(trace)
            self._store.store_record(child)

            return True

    def get_provenance_chain(self, record_id: str, max_depth: int = 10) -> Optional[ProvenanceChain]:
        """Get the complete provenance chain for a record."""
        with self._lock:
            record = self._store.get_record(record_id)
            if not record:
                return None

            chain = ProvenanceChain(root_record_id=record_id)
            visited = set()
            records_to_visit = [(record, 0)]

            while records_to_visit:
                current, depth = records_to_visit.pop(0)
                if current.record_id in visited or depth > max_depth:
                    continue

                visited.add(current.record_id)
                chain.records.append(current)
                chain.total_depth = max(chain.total_depth, depth)

                # Find parent records
                for parent_id in current.provenance_chain:
                    parent = self._store.get_record(parent_id)
                    if parent and parent_id not in visited:
                        records_to_visit.append((parent, depth + 1))

            chain.total_records = len(chain.records)
            chain.chain_integrity = self._calculate_chain_integrity(chain)

            self._store.store_provenance_chain(chain)
            return chain

    def _calculate_chain_integrity(self, chain: ProvenanceChain) -> float:
        """Calculate the integrity score of a provenance chain."""
        if not chain.records:
            return 0.0

        # Check for gaps in the chain
        expected_count = chain.total_depth + 1
        actual_count = len(chain.records)

        if actual_count >= expected_count:
            return 1.0

        return actual_count / expected_count if expected_count > 0 else 1.0

    def build_dependency_graph(
        self,
        record_id: str,
        max_depth: int = 10,
        direction: str = "downstream",
    ) -> Optional[DependencyGraph]:
        """Build a dependency graph starting from a record."""
        with self._lock:
            record = self._store.get_record(record_id)
            if not record:
                return None

            graph = DependencyGraph(root_record_id=record_id)
            visited = set()
            records_to_visit = [(record, 0)]

            while records_to_visit:
                current, depth = records_to_visit.pop(0)
                if current.record_id in visited or depth > max_depth:
                    continue

                visited.add(current.record_id)

                # Create node
                node = LineageNode(
                    record_id=current.record_id,
                    record_type=current.record_type,
                    label=f"{current.record_type.value}: {current.record_id[:8]}",
                    metadata=current.data,
                    is_root=(depth == 0),
                    tags=current.tags,
                )
                graph.nodes.append(node)

                # Find related records
                related_ids = []
                if direction == "downstream":
                    # Find children (records that have this as parent)
                    for rec in self._store._records.values():
                        if current.record_id in rec.provenance_chain:
                            related_ids.append(rec.record_id)
                else:
                    # Find parents
                    related_ids = current.provenance_chain

                for related_id in related_ids:
                    if related_id not in visited:
                        related = self._store.get_record(related_id)
                        if related:
                            records_to_visit.append((related, depth + 1))

                            # Create edge
                            edge = LineageEdge(
                                source_node_id=node.node_id,
                                target_node_id=related_id,
                                relationship_type="depends_on" if direction == "downstream" else "derived_from",
                            )
                            graph.edges.append(edge)

            graph.depth = max(0, len(graph.nodes) - 1)
            graph.total_records = len(graph.nodes)

            self._store.store_dependency_graph(graph)
            return graph

    def analyze_impact(self, record_id: str, max_depth: int = 10) -> Optional[ImpactAnalysis]:
        """Analyze the impact of a data record."""
        with self._lock:
            record = self._store.get_record(record_id)
            if not record:
                return None

            analysis = ImpactAnalysis(record_id=record_id)
            visited = set()
            records_to_visit = [(record, 0)]

            while records_to_visit:
                current, depth = records_to_visit.pop(0)
                if current.record_id in visited or depth > max_depth:
                    continue

                visited.add(current.record_id)
                analysis.impacted_records.append(current.record_id)

                # Extract entity IDs from data
                if "entity_id" in current.data:
                    analysis.impacted_entities.append(current.data["entity_id"])

                # Find downstream records
                for rec in self._store._records.values():
                    if current.record_id in rec.provenance_chain and rec.record_id not in visited:
                        records_to_visit.append((rec, depth + 1))
                        if "entity_id" in rec.data:
                            analysis.impacted_entities.append(rec.data["entity_id"])

            # Calculate impact score
            analysis.risk_score = self._calculate_impact_score(analysis, record)
            analysis.impact_level = self._determine_impact_level(analysis.risk_score)

            self._store.store_impact_analysis(analysis)
            return analysis

    def _calculate_impact_score(self, analysis: ImpactAnalysis, record: DataRecord) -> float:
        """Calculate impact score based on affected records and entities."""
        base_score = len(analysis.impacted_records) * 0.1
        entity_score = len(set(analysis.impacted_entities)) * 0.05

        # Higher risk for certain record types
        type_weights = {
            RecordType.SECURITY_DECISION: 0.3,
            RecordType.COMPLIANCE_EVENT: 0.25,
            RecordType.FRAUD_SIGNAL: 0.2,
            RecordType.RISK_ASSESSMENT: 0.15,
            RecordType.THREAT_INDICATOR: 0.1,
        }

        type_score = type_weights.get(record.record_type, 0.05)
        return min(1.0, base_score + entity_score + type_score)

    def _determine_impact_level(self, score: float) -> ImpactLevel:
        """Determine impact level from score."""
        if score >= 0.8:
            return ImpactLevel.CRITICAL
        elif score >= 0.6:
            return ImpactLevel.HIGH
        elif score >= 0.4:
            return ImpactLevel.MEDIUM
        elif score >= 0.2:
            return ImpactLevel.LOW
        return ImpactLevel.NEGLIGIBLE

    def verify_provenance(self, record_id: str) -> bool:
        """Verify the provenance chain integrity for a record."""
        with self._lock:
            chain = self.get_provenance_chain(record_id)
            if not chain:
                return False
            return chain.chain_integrity >= 0.9

    def search_records(self, query: LineageQuery) -> List[DataRecord]:
        """Search records based on query parameters."""
        return self._store.query_records(query)

    def get_lineage_stats(self) -> LineageStats:
        """Get lineage system statistics."""
        return self._store.get_stats()

    def get_record_history(self, record_id: str) -> List[TraceabilityRecord]:
        """Get the complete traceability history for a record."""
        record = self._store.get_record(record_id)
        if not record:
            return []
        return sorted(record.traceability_records, key=lambda x: x.timestamp)

    def export_lineage_report(
        self,
        record_id: str,
        include_graph: bool = True,
        include_impact: bool = True,
    ) -> Dict[str, Any]:
        """Export a comprehensive lineage report for a record."""
        with self._lock:
            record = self._store.get_record(record_id)
            if not record:
                return {"error": "Record not found"}

            report = {
                "record": record.to_dict(),
                "provenance_chain": None,
                "dependency_graph": None,
                "impact_analysis": None,
                "statistics": self.get_lineage_stats().to_dict(),
                "generated_at": datetime.now(timezone.utc).isoformat(),
            }

            if include_graph:
                graph = self.build_dependency_graph(record_id)
                if graph:
                    report["dependency_graph"] = graph.to_dict()

            if include_impact:
                impact = self.analyze_impact(record_id)
                if impact:
                    report["impact_analysis"] = impact.to_dict()

            return report


# Singleton instance
_lineage_service: Optional[LineageService] = None
_service_lock = threading.Lock()


def get_lineage_service() -> LineageService:
    """Get the singleton LineageService instance."""
    global _lineage_service
    with _service_lock:
        if _lineage_service is None:
            _lineage_service = LineageService()
        return _lineage_service


def reset_lineage_service() -> None:
    """Reset the singleton service (for testing)."""
    global _lineage_service
    with _service_lock:
        _lineage_service = None
