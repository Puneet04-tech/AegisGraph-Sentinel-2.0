"""
Unit tests for Cyber-Fraud Warfare Intelligence Platform.
"""

import pytest
from datetime import datetime, timezone
from src.cyber_fraud_warfare import (
    get_warfare_store,
    get_threat_actor_engine,
    get_attribution_engine,
    get_strategic_dashboard,
    get_threat_knowledge_graph,
    ThreatActorType,
    ThreatActorSponsor,
    CampaignStatus,
    ThreatActor,
    Campaign,
    AttackPattern,
)


class TestWarfareStore:
    """Tests for WarfareStore."""

    def setup_method(self):
        """Set up test fixtures."""
        self.store = get_warfare_store()
        # Clear store for clean tests
        self.store.threat_actors.clear()
        self.store.campaigns.clear()
        self.store.attack_patterns.clear()

    def test_add_threat_actor(self):
        """Test adding a threat actor."""
        actor = {
            "name": "APT29",
            "type": "NATION_STATE",
            "sponsor": "STATE_SPONSORED",
            "country": "Russia",
            "description": "Cozy Bear threat actor",
            "capabilities": ["Espionage", "Data theft"],
            "primary_targets": ["Government", "Defense"],
            "threat_level": "CRITICAL",
        }
        actor_id = self.store.add_threat_actor(actor)
        assert actor_id is not None
        
        retrieved = self.store.get_threat_actor(actor_id)
        assert retrieved is not None
        assert retrieved["name"] == "APT29"

    def test_list_threat_actors(self):
        """Test listing threat actors."""
        self.store.add_threat_actor({
            "name": "Actor 1",
            "type": "CYBERCRIME_ORG",
        })
        self.store.add_threat_actor({
            "name": "Actor 2",
            "type": "NATION_STATE",
        })
        
        actors = self.store.list_threat_actors()
        assert len(actors) >= 2
        
        nation_state = self.store.list_threat_actors(actor_type="NATION_STATE")
        assert len(nation_state) >= 1

    def test_add_campaign(self):
        """Test adding a campaign."""
        campaign = {
            "name": "Operation Aurora",
            "description": "Advanced persistent threat campaign",
            "status": "ACTIVE",
            "target_sectors": ["Technology", "Finance"],
            "attack_types": ["Spear phishing", "Zero-day exploits"],
        }
        campaign_id = self.store.add_campaign(campaign)
        assert campaign_id is not None
        
        retrieved = self.store.get_campaign(campaign_id)
        assert retrieved is not None
        assert retrieved["name"] == "Operation Aurora"

    def test_list_campaigns(self):
        """Test listing campaigns."""
        self.store.add_campaign({
            "name": "Campaign 1",
            "status": "ACTIVE",
            "target_sectors": ["Finance"],
        })
        self.store.add_campaign({
            "name": "Campaign 2",
            "status": "DORMANT",
            "target_sectors": ["Healthcare"],
        })
        
        campaigns = self.store.list_campaigns()
        assert len(campaigns) >= 2
        
        active = self.store.list_campaigns(status="ACTIVE")
        assert len(active) >= 1

    def test_get_warfare_stats(self):
        """Test getting warfare statistics."""
        self.store.add_threat_actor({
            "name": "Test Actor",
            "type": "NATION_STATE",
            "threat_level": "HIGH",
        })
        
        self.store.add_campaign({
            "name": "Test Campaign",
            "status": "ACTIVE",
        })
        
        stats = self.store.get_warfare_stats()
        assert "total_threat_actors" in stats
        assert "total_campaigns" in stats
        assert "active_campaigns" in stats


class TestThreatActorEngine:
    """Tests for ThreatActorIntelligenceEngine."""

    def setup_method(self):
        """Set up test fixtures."""
        self.store = get_warfare_store()
        self.store.threat_actors.clear()
        self.engine = get_threat_actor_engine()

    def test_analyze_actor(self):
        """Test actor analysis."""
        actor_id = self.store.add_threat_actor({
            "name": "Test Actor",
            "type": "NATION_STATE",
            "sponsor": "STATE_SPONSORED",
            "confirmed_attacks": 10,
            "suspected_attacks": 5,
        })
        
        analysis = self.engine.analyze_actor(actor_id)
        assert analysis is not None
        assert analysis.actor_id == actor_id
        assert hasattr(analysis, "threat_score")
        assert hasattr(analysis, "activity_level")

    def test_identify_related_actors(self):
        """Test finding related actors."""
        actor1_id = self.store.add_threat_actor({
            "name": "Actor 1",
            "type": "NATION_STATE",
        })
        actor2_id = self.store.add_threat_actor({
            "name": "Actor 2",
            "type": "NATION_STATE",
        })
        
        # Link actors
        actor1 = self.store.get_threat_actor(actor1_id)
        actor1["associated_actor_ids"] = [actor2_id]
        
        related = self.engine.identify_related_actors(actor1_id)
        assert len(related) >= 1


class TestAttributionEngine:
    """Tests for CampaignAttributionEngine."""

    def setup_method(self):
        """Set up test fixtures."""
        self.store = get_warfare_store()
        self.store.campaigns.clear()
        self.store.threat_actors.clear()
        self.engine = get_attribution_engine()

    def test_attribute_campaign(self):
        """Test campaign attribution."""
        actor_id = self.store.add_threat_actor({
            "name": "Test Actor",
            "type": "CYBERCRIME_ORG",
            "ttps": [{"id": "T1566"}],
        })
        
        campaign_id = self.store.add_campaign({
            "name": "Test Campaign",
            "status": "ACTIVE",
            "ttps": ["T1566"],
            "target_sectors": ["Finance"],
        })
        
        result = self.engine.attribute_campaign(campaign_id)
        assert result is not None
        assert hasattr(result, "confidence")


class TestStrategicDashboard:
    """Tests for StrategicThreatDashboard."""

    def setup_method(self):
        """Set up test fixtures."""
        self.dashboard = get_strategic_dashboard()

    def test_generate_dashboard(self):
        """Test dashboard generation."""
        dashboard = self.dashboard.generate_dashboard()
        assert dashboard is not None
        assert "threat_actor_summary" in dashboard
        assert "campaign_summary" in dashboard
        assert "risk_summary" in dashboard

    def test_generate_executive_brief(self):
        """Test executive brief generation."""
        brief = self.dashboard.generate_executive_brief()
        assert brief is not None
        assert "brief_id" in brief
        assert "key_findings" in brief


class TestThreatKnowledgeGraph:
    """Tests for ThreatKnowledgeGraph."""

    def setup_method(self):
        """Set up test fixtures."""
        self.store = get_warfare_store()
        self.store.threat_actors.clear()
        self.store.campaigns.clear()
        self.graph = get_threat_knowledge_graph()

    def test_build_graph(self):
        """Test graph building."""
        actor_id = self.store.add_threat_actor({
            "name": "Test Actor",
            "type": "NATION_STATE",
        })
        
        stats = self.graph.build_graph()
        assert "nodes_created" in stats
        assert "edges_created" in stats

    def test_get_graph_stats(self):
        """Test getting graph statistics."""
        self.graph.build_graph()
        stats = self.graph.get_graph_stats()
        assert "total_nodes" in stats
        assert "total_edges" in stats


if __name__ == "__main__":
    pytest.main([__file__, "-v"])