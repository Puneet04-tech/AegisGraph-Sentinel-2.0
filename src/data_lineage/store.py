"""
Data Lineage Store - Thread-safe storage with LRU cache
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from typing import Any, Dict, List, Optional

from .models import (
    DataRecord,
    LineageNode,
    LineageEdge,
    ProvenanceChain,
    ImpactAnalysis,
    DependencyGraph,
    LineageStats,
    LineageQuery,
    RecordType,
)


class LRUCache:
    """Thread-safe LRU cache with bounded size."""

    def __init__(self, max_size: int = 10000):
        self.max_size = max_size
        self.cache: OrderedDict = OrderedDict()
        self.lock = threading.RLock()

    def get(self, key: str) -> Optional[Any]:
        with self.lock:
            if key in self.cache:
                self.cache.move_to_end(key)
                return self.cache[key]
            return None

    def put(self, key: str, value: Any) -> None:
        with self.lock:
            if key in self.cache:
                self.cache.move_to_end(key)
            self.cache[key] = value
            if len(self.cache) > self.max_size:
                self.cache.popitem(last=False)

    def delete(self, key: str) -> None:
        with self.lock:
            if key in self.cache:
                del self.cache[key]

    def clear(self) -> None:
        with self.lock:
            self.cache.clear()

    def size(self) -> int:
        with self.lock:
            return len(self.cache)


class LineageStore:
    """
    Thread-safe storage for data lineage and provenance records.
    Uses LRU cache for O(1) lookup of frequently accessed records.
    """

    def __init__(self, max_cache_size: int = 10000):
        self._records: Dict[str, DataRecord] = {}
        self._nodes: Dict[str, LineageNode] = {}
        self._edges: Dict[str, LineageEdge] = {}
        self._chains: Dict[str, ProvenanceChain] = {}
        self._impact_analysis: Dict[str, ImpactAnalysis] = {}
        self._dependency_graphs: Dict[str, DependencyGraph] = {}
        self._record_index: Dict[str, List[str]] = {}  # record_type -> record_ids
        self._source_index: Dict[str, List[str]] = {}  # source_id -> record_ids
        self._lock = threading.RLock()
        self._cache = LRUCache(max_cache_size)
        self._stats = LineageStats()

    def store_record(self, record: DataRecord) -> bool:
        """Store a data record with lineage information."""
        with self._lock:
            self._records[record.record_id] = record
            self._cache.put(f"record:{record.record_id}", record)

            # Update index by type
            record_type = record.record_type.value
            if record_type not in self._record_index:
                self._record_index[record_type] = []
            if record.record_id not in self._record_index[record_type]:
                self._record_index[record_type].append(record.record_id)

            # Update index by source
            if record.source:
                source_id = record.source.source_id
                if source_id not in self._source_index:
                    self._source_index[source_id] = []
                if record.record_id not in self._source_index[source_id]:
                    self._source_index[source_id].append(record.record_id)

            # Update stats
            self._update_stats()
            return True

    def get_record(self, record_id: str) -> Optional[DataRecord]:
        """Get a record by ID with O(1) cache lookup."""
        # Check cache first
        cached = self._cache.get(f"record:{record_id}")
        if cached:
            return cached

        with self._lock:
            record = self._records.get(record_id)
            if record:
                self._cache.put(f"record:{record_id}", record)
            return record

    def store_node(self, node: LineageNode) -> bool:
        """Store a lineage node."""
        with self._lock:
            self._nodes[node.node_id] = node
            self._cache.put(f"node:{node.node_id}", node)
            return True

    def get_node(self, node_id: str) -> Optional[LineageNode]:
        """Get a lineage node by ID."""
        cached = self._cache.get(f"node:{node_id}")
        if cached:
            return cached

        with self._lock:
            node = self._nodes.get(node_id)
            if node:
                self._cache.put(f"node:{node_id}", node)
            return node

    def store_edge(self, edge: LineageEdge) -> bool:
        """Store a lineage edge."""
        with self._lock:
            self._edges[edge.edge_id] = edge
            self._cache.put(f"edge:{edge.edge_id}", edge)
            self._update_stats()
            return True

    def get_edge(self, edge_id: str) -> Optional[LineageEdge]:
        """Get a lineage edge by ID."""
        cached = self._cache.get(f"edge:{edge_id}")
        if cached:
            return cached

        with self._lock:
            edge = self._edges.get(edge_id)
            if edge:
                self._cache.put(f"edge:{edge_id}", edge)
            return edge

    def store_provenance_chain(self, chain: ProvenanceChain) -> bool:
        """Store a provenance chain."""
        with self._lock:
            self._chains[chain.chain_id] = chain
            self._cache.put(f"chain:{chain.chain_id}", chain)
            return True

    def get_provenance_chain(self, chain_id: str) -> Optional[ProvenanceChain]:
        """Get a provenance chain by ID."""
        cached = self._cache.get(f"chain:{chain_id}")
        if cached:
            return cached

        with self._lock:
            chain = self._chains.get(chain_id)
            if chain:
                self._cache.put(f"chain:{chain.chain_id}", chain)
            return chain

    def store_impact_analysis(self, analysis: ImpactAnalysis) -> bool:
        """Store an impact analysis."""
        with self._lock:
            self._impact_analysis[analysis.analysis_id] = analysis
            return True

    def get_impact_analysis(self, analysis_id: str) -> Optional[ImpactAnalysis]:
        """Get an impact analysis by ID."""
        with self._lock:
            return self._impact_analysis.get(analysis_id)

    def store_dependency_graph(self, graph: DependencyGraph) -> bool:
        """Store a dependency graph."""
        with self._lock:
            self._dependency_graphs[graph.graph_id] = graph
            return True

    def get_dependency_graph(self, graph_id: str) -> Optional[DependencyGraph]:
        """Get a dependency graph by ID."""
        with self._lock:
            return self._dependency_graphs.get(graph_id)

    def query_records(self, query: LineageQuery) -> List[DataRecord]:
        """Query records based on filter criteria."""
        with self._lock:
            results = []
            for record in self._records.values():
                if query.record_id and query.record_id != record.record_id:
                    continue
                if query.record_type and query.record_type != record.record_type:
                    continue
                if query.source_type and (
                    not record.source or query.source_type != record.source.source_type
                ):
                    continue
                if query.tags and not any(tag in record.tags for tag in query.tags):
                    continue
                results.append(record)
            return results

    def get_records_by_type(self, record_type: RecordType) -> List[DataRecord]:
        """Get all records of a specific type."""
        with self._lock:
            record_ids = self._record_index.get(record_type.value, [])
            return [self._records[rid] for rid in record_ids if rid in self._records]

    def get_records_by_source(self, source_id: str) -> List[DataRecord]:
        """Get all records from a specific source."""
        with self._lock:
            record_ids = self._source_index.get(source_id, [])
            return [self._records[rid] for rid in record_ids if rid in self._records]

    def get_connected_nodes(self, node_id: str) -> List[LineageNode]:
        """Get all nodes connected to a given node."""
        with self._lock:
            connected_ids = set()
            for edge in self._edges.values():
                if edge.source_node_id == node_id:
                    connected_ids.add(edge.target_node_id)
                elif edge.target_node_id == node_id:
                    connected_ids.add(edge.source_node_id)
            return [self._nodes[nid] for nid in connected_ids if nid in self._nodes]

    def get_edges_between(self, source_id: str, target_id: str) -> List[LineageEdge]:
        """Get all edges between two nodes."""
        with self._lock:
            return [
                edge
                for edge in self._edges.values()
                if (edge.source_node_id == source_id and edge.target_node_id == target_id)
                or (edge.source_node_id == target_id and edge.target_node_id == source_id)
            ]

    def _update_stats(self) -> None:
        """Update lineage statistics."""
        self._stats.total_records = len(self._records)
        self._stats.total_nodes = len(self._nodes)
        self._stats.total_edges = len(self._edges)
        self._stats.records_by_type = {
            record_type: len(record_ids)
            for record_type, record_ids in self._record_index.items()
        }

    def get_stats(self) -> LineageStats:
        """Get current lineage statistics."""
        with self._lock:
            self._update_stats()
            return self._stats

    def clear(self) -> None:
        """Clear all stored data."""
        with self._lock:
            self._records.clear()
            self._nodes.clear()
            self._edges.clear()
            self._chains.clear()
            self._impact_analysis.clear()
            self._dependency_graphs.clear()
            self._record_index.clear()
            self._source_index.clear()
            self._cache.clear()
            self._stats = LineageStats()


# Singleton instance
_lineage_store: Optional[LineageStore] = None
_store_lock = threading.Lock()


def get_lineage_store() -> LineageStore:
    """Get the singleton LineageStore instance."""
    global _lineage_store
    with _store_lock:
        if _lineage_store is None:
            _lineage_store = LineageStore()
        return _lineage_store


def reset_lineage_store() -> None:
    """Reset the singleton store (for testing)."""
    global _lineage_store
    with _store_lock:
        if _lineage_store:
            _lineage_store.clear()
        _lineage_store = None
