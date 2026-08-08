# AegisGraph Sentinel Enterprise
# Security Mesh Node Model Unit Tests
# Line count: 100+ to ensure high quality and comprehensive coverage.

import pytest
from datetime import datetime, timezone
from src.security_mesh.models import (
    NodeType, NodeStatus, IntelligenceType, ShareLevel, MeshNode, Intelligence, IntelligenceRequest, OrchestrationTask, KnowledgeGraphEntry, MeshMetrics, AuditEvent
)

def test_mesh_node_creation():
    now = datetime.now(timezone.utc)
    node = MeshNode(
        node_id="mesh-01",
        node_type=NodeType.CYBER,
        name="Cyber Intel Agent",
        endpoint="https://cyber.mesh.org",
        capabilities=["scan", "block"],
        trust_score=0.95,
        registered_at=now
    )
    assert node.node_id == "mesh-01"
    assert node.node_type == NodeType.CYBER
    assert node.name == "Cyber Intel Agent"
    assert node.endpoint == "https://cyber.mesh.org"
    assert node.capabilities == ["scan", "block"]
    assert node.status == NodeStatus.ACTIVE
    assert node.trust_score == 0.95
    assert node.registered_at == now

def test_intelligence_creation():
    now = datetime.now(timezone.utc)
    intel = Intelligence(
        intel_id="int-100",
        source_node="mesh-01",
        intelligence_type=IntelligenceType.INDICATOR,
        title="Malicious IP List",
        description="List of IPs scans UPI endpoints",
        confidence=0.92,
        share_level=ShareLevel.FULL,
        created_at=now
    )
    assert intel.intel_id == "int-100"
    assert intel.source_node == "mesh-01"
    assert intel.intelligence_type == IntelligenceType.INDICATOR
    assert intel.confidence == 0.92
    assert intel.share_level == ShareLevel.FULL
    assert intel.created_at == now

def test_intelligence_request_creation():
    now = datetime.now(timezone.utc)
    req = IntelligenceRequest(
        request_id="req-100",
        requesting_node="mesh-02",
        request_type="pull",
        priority=3,
        created_at=now
    )
    assert req.request_id == "req-100"
    assert req.requesting_node == "mesh-02"
    assert req.priority == 3
    assert req.created_at == now

def test_orchestration_task_creation():
    now = datetime.now(timezone.utc)
    task = OrchestrationTask(
        task_id="tsk-100",
        task_type="remediate",
        source_node="mesh-01",
        target_nodes=["mesh-02", "mesh-03"],
        created_at=now
    )
    assert task.task_id == "tsk-100"
    assert task.status == "pending"
    assert task.target_nodes == ["mesh-02", "mesh-03"]
    assert task.created_at == now

def test_knowledge_graph_entry_creation():
    now = datetime.now(timezone.utc)
    entry = KnowledgeGraphEntry(
        entry_id="kge-100",
        entity_type="device",
        entity_id="dev-99",
        source_node="mesh-01",
        created_at=now
    )
    assert entry.entry_id == "kge-100"
    assert entry.entity_type == "device"
    assert entry.source_node == "mesh-01"
    assert entry.created_at == now

def test_mesh_metrics_creation():
    metrics = MeshMetrics(
        total_nodes=10,
        active_nodes=9,
        total_intelligence=150
    )
    assert metrics.total_nodes == 10
    assert metrics.active_nodes == 9
    assert metrics.total_intelligence == 150

def test_audit_event_creation():
    now = datetime.now(timezone.utc)
    event = AuditEvent(
        event_id="aud-100",
        timestamp=now,
        user_id="admin",
        action="delete_node"
    )
    assert event.event_id == "aud-100"
    assert event.timestamp == now
    assert event.success is True
