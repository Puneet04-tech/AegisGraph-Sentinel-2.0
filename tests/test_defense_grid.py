"""
Unit tests for Autonomous Enterprise Defense Grid.
"""

import pytest
from datetime import datetime, timezone
from src.defense_grid import (
    get_defense_store,
    get_defense_controller,
    get_self_healing_engine,
    DefensePolicy,
    MitigationAction,
    ContainmentAction,
    DefenseEvent,
    GridNode,
)


class TestDefenseStore:
    """Tests for DefenseStore."""

    def setup_method(self):
        """Set up test fixtures."""
        self.store = get_defense_store()
        # Clear store for clean tests
        self.store.policies.clear()
        self.store.mitigation_actions.clear()
        self.store.containment_actions.clear()
        self.store.defense_events.clear()
        self.store.grid_nodes.clear()

    def test_add_policy(self):
        """Test adding a defense policy."""
        policy = {
            "name": "Block Suspicious IPs",
            "type": "PREVENTION",
            "description": "Block IPs with suspicious activity",
            "priority": "HIGH",
            "enabled": True,
            "conditions": {"threat_score_gte": 0.8},
            "actions": [{"type": "BLOCK_IP"}],
        }
        policy_id = self.store.add_policy(policy)
        assert policy_id is not None
        
        retrieved = self.store.get_policy(policy_id)
        assert retrieved is not None
        assert retrieved["name"] == "Block Suspicious IPs"

    def test_list_policies(self):
        """Test listing policies."""
        self.store.add_policy({
            "name": "Policy 1",
            "type": "PREVENTION",
            "enabled": True,
        })
        self.store.add_policy({
            "name": "Policy 2",
            "type": "DETECTION",
            "enabled": False,
        })
        
        policies = self.store.list_policies()
        assert len(policies) >= 2
        
        enabled = self.store.list_policies(enabled=True)
        assert all(p.get("enabled", False) for p in enabled)

    def test_add_mitigation_action(self):
        """Test adding a mitigation action."""
        action = {
            "name": "Reset Account",
            "action_type": "RESET_ACCOUNT",
            "target_entity": "user_123",
            "target_entity_type": "USER",
            "status": "PENDING",
            "initiated_by": "SYSTEM",
        }
        action_id = self.store.add_mitigation_action(action)
        assert action_id is not None

    def test_add_containment_action(self):
        """Test adding a containment action."""
        action = {
            "containment_type": "NETWORK_ISOLATE",
            "target_entity": "server_456",
            "target_entity_type": "SERVER",
            "duration_seconds": 3600,
            "status": "IN_PROGRESS",
            "initiated_by": "SYSTEM",
        }
        action_id = self.store.add_containment_action(action)
        assert action_id is not None
        
        # Verify we can list active containments
        active = self.store.list_containment_actions(active_only=True)
        assert len(active) >= 1

    def test_add_defense_event(self):
        """Test adding a defense event."""
        event = {
            "event_type": "THREAT_DETECTED",
            "severity": "HIGH",
            "source": "SIEM",
            "description": "Suspicious login detected",
            "affected_entities": [{"entity_id": "user_123", "type": "USER"}],
        }
        event_id = self.store.add_defense_event(event)
        assert event_id is not None

    def test_add_grid_node(self):
        """Test adding a grid node."""
        node = {
            "name": "Defense Node 1",
            "node_type": "SENSOR",
            "capabilities": ["DETECTION", "PREVENTION"],
            "status": "ACTIVE",
            "health_score": 100.0,
            "region": "us-east-1",
        }
        node_id = self.store.add_grid_node(node)
        assert node_id is not None

    def test_get_defense_stats(self):
        """Test getting defense statistics."""
        self.store.add_policy({
            "name": "Test Policy",
            "type": "PREVENTION",
            "enabled": True,
        })
        
        stats = self.store.get_defense_stats()
        assert "total_policies" in stats
        assert "enabled_policies" in stats
        assert "active_nodes" in stats  # Changed from active_grid_nodes


class TestDefenseController:
    """Tests for DefenseGridController."""

    def setup_method(self):
        """Set up test fixtures."""
        self.store = get_defense_store()
        self.store.defense_events.clear()
        self.store.containment_actions.clear()
        self.controller = get_defense_controller()

    def test_process_threat(self):
        """Test processing a threat."""
        threat_data = {
            "type": "MALWARE_DETECTION",
            "severity": "HIGH",
            "source": "EDR",
            "affected_entities": ["workstation_001"],
        }
        
        result = self.controller.process_threat(threat_data)
        assert result is not None
        assert "threat_id" in result
        assert "response_id" in result
        assert "actions" in result

    def test_initiate_containment(self):
        """Test initiating containment."""
        result = self.controller._initiate_containment(
            entity_id="server_001",
            containment_type="NETWORK_ISOLATE",
            reason="Malware detected",
        )
        assert result is not None
        assert result["status"] == "IN_PROGRESS"

    def test_release_containment(self):
        """Test releasing containment."""
        # First create a containment
        result = self.controller._initiate_containment(
            entity_id="server_002",
            containment_type="ACCOUNT_LOCK",
            reason="Suspicious activity",
        )
        action_id = result["action_id"]
        
        # Then release it
        release_result = self.controller.release_containment(action_id)
        assert release_result is not None
        assert release_result["status"] == "RELEASED"

    def test_get_grid_status(self):
        """Test getting grid status."""
        status = self.controller.get_grid_status()
        assert "grid_status" in status
        assert "total_nodes" in status
        assert "active_nodes" in status


class TestSelfHealingEngine:
    """Tests for SelfHealingEngine."""

    def setup_method(self):
        """Set up test fixtures."""
        self.store = get_defense_store()
        self.controller = get_defense_controller()
        self.healing = get_self_healing_engine()

    def test_diagnose_issue(self):
        """Test diagnosing an issue."""
        result = self.healing.diagnose_issue(
            entity_id="workstation_001",
            entity_type="WORKSTATION",
        )
        assert result is not None
        assert "entity_id" in result
        assert "issues_found" in result
        assert "health_score" in result

    def test_heal_entity_auto(self):
        """Test auto healing an entity."""
        result = self.healing.heal_entity(
            entity_id="workstation_002",
            entity_type="WORKSTATION",
            healing_type="AUTO",
        )
        assert result is not None
        assert hasattr(result, "action_id")
        assert hasattr(result, "status")

    def test_heal_entity_soft(self):
        """Test soft healing an entity."""
        result = self.healing.heal_entity(
            entity_id="workstation_003",
            entity_type="WORKSTATION",
            healing_type="SOFT",
        )
        assert result is not None
        assert result.action_type == "SOFT"

    def test_get_healing_stats(self):
        """Test getting healing statistics."""
        # First perform some healing
        self.healing.heal_entity(
            entity_id="workstation_test",
            entity_type="WORKSTATION",
            healing_type="AUTO",
        )
        
        stats = self.healing.get_healing_stats()
        assert "total_healing_actions" in stats
        assert stats["total_healing_actions"] >= 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])