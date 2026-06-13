"""
Tests for Campaign Attribution Platform
"""

import pytest
import threading
import time

from src.campaign_attribution.models import (
    ThreatActor,
    Campaign,
    Attribution,
    Infrastructure,
    ActorType,
    CampaignStatus,
    ConfidenceLevel,
    InfrastructureType,
)
from src.campaign_attribution.store import get_campaign_store, reset_campaign_store
from src.campaign_attribution.service import get_campaign_service, reset_campaign_service


class TestCampaignModels:
    """Tests for campaign attribution models."""

    def test_create_campaign(self):
        """Test creating a campaign."""
        campaign = Campaign(
            name="Operation Fraud Strike",
            description="Multi-vector fraud campaign",
            target_sectors=["banking", "retail"],
            target_geographies=["US", "EU"],
        )
        assert campaign.campaign_id is not None
        assert campaign.name == "Operation Fraud Strike"
        assert campaign.status == CampaignStatus.UNKNOWN
        assert len(campaign.target_sectors) == 2

    def test_create_threat_actor(self):
        """Test creating a threat actor."""
        actor = ThreatActor(
            name="DarkMoney Gang",
            actor_type=ActorType.ORGANIZED_CRIME,
            motivation=["financial"],
            capabilities=["phishing", "money_mules"],
        )
        assert actor.actor_id is not None
        assert actor.name == "DarkMoney Gang"
        assert actor.actor_type == ActorType.ORGANIZED_CRIME
        assert len(actor.capabilities) == 2

    def test_create_attribution(self):
        """Test creating an attribution."""
        attribution = Attribution(
            campaign_id="camp_001",
            actor_id="actor_001",
            confidence=ConfidenceLevel.HIGH,
            evidence=["shared_infrastructure", "similar_tactics"],
            attribution_method="forensic_analysis",
        )
        assert attribution.attribution_id is not None
        assert attribution.confidence == ConfidenceLevel.HIGH
        assert len(attribution.evidence) == 2

    def test_create_infrastructure(self):
        """Test creating infrastructure."""
        infra = Infrastructure(
            ip_addresses=["192.168.1.1", "10.0.0.1"],
            domains=["evil.com", "malware.net"],
            infrastructure_type=InfrastructureType.COMMAND_CONTROL,
        )
        assert infra.infrastructure_id is not None
        assert len(infra.ip_addresses) == 2
        assert infra.infrastructure_type == InfrastructureType.COMMAND_CONTROL


class TestCampaignStore:
    """Tests for campaign store."""

    def setup_method(self):
        """Reset store before each test."""
        reset_campaign_store()

    def test_store_and_retrieve_campaign(self):
        """Test storing and retrieving a campaign."""
        store = get_campaign_store()
        campaign = Campaign(
            name="Test Campaign",
            description="Test description",
        )
        store.store_campaign(campaign)

        retrieved = store.get_campaign(campaign.campaign_id)
        assert retrieved is not None
        assert retrieved.name == "Test Campaign"

    def test_store_and_retrieve_actor(self):
        """Test storing and retrieving an actor."""
        store = get_campaign_store()
        actor = ThreatActor(
            name="Test Actor",
            actor_type=ActorType.NATION_STATE,
        )
        store.store_actor(actor)

        retrieved = store.get_actor(actor.actor_id)
        assert retrieved is not None
        assert retrieved.name == "Test Actor"

    def test_campaign_index_by_status(self):
        """Test campaigns are indexed by status."""
        store = get_campaign_store()
        active = Campaign(name="Active", status=CampaignStatus.ACTIVE)
        dormant = Campaign(name="Dormant", status=CampaignStatus.DORMANT)
        store.store_campaign(active)
        store.store_campaign(dormant)

        active_campaigns = store.get_campaigns_by_status(CampaignStatus.ACTIVE)
        assert len(active_campaigns) == 1
        assert active_campaigns[0].name == "Active"

    def test_actor_index_by_type(self):
        """Test actors are indexed by type."""
        store = get_campaign_store()
        actor1 = ThreatActor(name="Actor1", actor_type=ActorType.NATION_STATE)
        actor2 = ThreatActor(name="Actor2", actor_type=ActorType.ORGANIZED_CRIME)
        store.store_actor(actor1)
        store.store_actor(actor2)

        actors = store.get_actors_by_type(ActorType.NATION_STATE)
        assert len(actors) == 1
        assert actors[0].name == "Actor1"

    def test_link_campaign_to_actor(self):
        """Test linking campaign to actor."""
        store = get_campaign_store()
        campaign = Campaign(name="Campaign")
        actor = ThreatActor(name="Actor", actor_type=ActorType.ORGANIZED_CRIME)
        store.store_campaign(campaign)
        store.store_actor(actor)

        success = store.link_campaign_to_actor(campaign.campaign_id, actor.actor_id)
        assert success is True

        updated_campaign = store.get_campaign(campaign.campaign_id)
        assert actor.actor_id in updated_campaign.attributed_actors

        updated_actor = store.get_actor(actor.actor_id)
        assert campaign.campaign_id in updated_actor.linked_campaigns

    def test_get_active_campaigns(self):
        """Test getting active campaigns."""
        store = get_campaign_store()
        active = Campaign(name="Active", status=CampaignStatus.ACTIVE)
        dormant = Campaign(name="Dormant", status=CampaignStatus.DORMANT)
        store.store_campaign(active)
        store.store_campaign(dormant)

        active_campaigns = store.get_active_campaigns()
        assert len(active_campaigns) == 1

    def test_get_stats(self):
        """Test getting statistics."""
        store = get_campaign_store()
        campaign = Campaign(name="Test", status=CampaignStatus.ACTIVE)
        store.store_campaign(campaign)

        stats = store.get_stats()
        assert stats.total_campaigns == 1
        assert stats.active_campaigns == 1


class TestCampaignService:
    """Tests for campaign service."""

    def setup_method(self):
        """Reset service before each test."""
        reset_campaign_store()
        reset_campaign_service()

    def test_create_campaign(self):
        """Test creating a campaign through service."""
        service = get_campaign_service()
        campaign = service.create_campaign(
            name="New Campaign",
            description="Test",
            target_sectors=["finance"],
            attack_vectors=["phishing"],
        )

        assert campaign.campaign_id is not None
        assert campaign.name == "New Campaign"
        assert campaign.status == CampaignStatus.ACTIVE

    def test_create_actor(self):
        """Test creating an actor through service."""
        service = get_campaign_service()
        actor = service.create_actor(
            name="Test Actor",
            actor_type=ActorType.HACKTIVIST,
            capabilities=["DDoS", "defacement"],
        )

        assert actor.actor_id is not None
        assert actor.name == "Test Actor"
        assert actor.actor_type == ActorType.HACKTIVIST

    def test_attribute_campaign(self):
        """Test attributing a campaign to an actor."""
        service = get_campaign_service()

        campaign = service.create_campaign(name="Fraud Campaign")
        actor = service.create_actor(name="Fraud Gang", actor_type=ActorType.ORGANIZED_CRIME)

        attribution = service.attribute_campaign(
            campaign_id=campaign.campaign_id,
            actor_id=actor.actor_id,
            confidence=ConfidenceLevel.HIGH,
            evidence=["shared_ip", "similar_technique"],
        )

        assert attribution is not None
        assert attribution.confidence == ConfidenceLevel.HIGH

        updated_campaign = service._store.get_campaign(campaign.campaign_id)
        assert actor.actor_id in updated_campaign.attributed_actors

    def test_discover_campaign_by_indicators(self):
        """Test discovering campaigns by indicators."""
        service = get_campaign_service()

        campaign = Campaign(
            name="Discovered Campaign",
            linked_indicators=["evil.com", "malware.exe"],
        )
        service._store.store_campaign(campaign)

        results = service.discover_campaign(["evil.com", "innocent.com"])
        assert len(results) == 1
        assert results[0].name == "Discovered Campaign"

    def test_correlate_campaigns(self):
        """Test correlating multiple campaigns."""
        service = get_campaign_service()

        camp1 = Campaign(
            name="Campaign 1",
            target_sectors=["banking"],
            target_geographies=["US"],
            linked_infrastructure=["infra_1"],
        )
        camp2 = Campaign(
            name="Campaign 2",
            target_sectors=["banking", "retail"],
            target_geographies=["US", "EU"],
            linked_infrastructure=["infra_1", "infra_2"],
        )
        service._store.store_campaign(camp1)
        service._store.store_campaign(camp2)

        correlation = service.correlate_campaigns([camp1.campaign_id, camp2.campaign_id])

        assert "banking" in correlation["common_sectors"]
        assert "US" in correlation["common_geographies"]
        assert "infra_1" in correlation["common_infrastructure"]

    def test_generate_threat_profile(self):
        """Test generating a threat profile."""
        service = get_campaign_service()

        campaign = service.create_campaign(name="High Risk Campaign")
        profile = service.generate_threat_profile("campaign", campaign.campaign_id)

        assert profile is not None
        assert profile.entity_type == "campaign"
        assert profile.name == "High Risk Campaign"
        assert profile.risk_score >= 0

    def test_assess_risk(self):
        """Test risk assessment."""
        service = get_campaign_service()

        campaign = Campaign(
            name="High Risk",
            victim_count=100,
            estimated_damage=500000,
        )
        service._store.store_campaign(campaign)

        assessment = service.assess_risk("campaign", campaign.campaign_id)

        assert assessment is not None
        assert assessment.risk_score > 0
        assert len(assessment.recommendations) > 0

    def test_search_campaigns(self):
        """Test searching campaigns."""
        service = get_campaign_service()

        service.create_campaign(name="Banking Attack", target_sectors=["banking"])
        service.create_campaign(name="Retail Attack", target_sectors=["retail"])
        service.create_campaign(name="Global Attack", target_sectors=["banking", "retail"])

        results = service.search_campaigns(sector="banking")
        assert len(results) == 2

    def test_search_actors(self):
        """Test searching actors."""
        service = get_campaign_service()

        service.create_actor(name="State Actor", actor_type=ActorType.NATION_STATE)
        service.create_actor(name="Crime Actor", actor_type=ActorType.ORGANIZED_CRIME)

        results = service.search_actors(actor_type=ActorType.NATION_STATE)
        assert len(results) == 1


class TestCampaignThreadSafety:
    """Tests for thread safety."""

    def setup_method(self):
        """Reset store before each test."""
        reset_campaign_store()

    def test_concurrent_writes(self):
        """Test concurrent write operations."""
        store = get_campaign_store()
        errors = []

        def write_campaigns(count):
            try:
                for i in range(count):
                    campaign = Campaign(
                        name=f"Campaign {i}",
                        status=CampaignStatus.ACTIVE,
                    )
                    store.store_campaign(campaign)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=write_campaigns, args=(10,)) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        stats = store.get_stats()
        assert stats.total_campaigns == 50

    def test_concurrent_reads(self):
        """Test concurrent read operations."""
        store = get_campaign_store()

        campaign = Campaign(name="Test", status=CampaignStatus.ACTIVE)
        store.store_campaign(campaign)

        results = []

        def read_campaigns():
            for _ in range(100):
                result = store.get_campaign(campaign.campaign_id)
                results.append(result)

        threads = [threading.Thread(target=read_campaigns) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(results) == 500


class TestCampaignIntegration:
    """Integration tests for campaign attribution."""

    def setup_method(self):
        """Reset service before each test."""
        reset_campaign_store()
        reset_campaign_service()

    def test_full_attribution_workflow(self):
        """Test complete campaign attribution workflow."""
        service = get_campaign_service()

        # Create actor
        actor = service.create_actor(
            name="Fraud Syndicate",
            actor_type=ActorType.ORGANIZED_CRIME,
            motivation=["financial"],
            capabilities=["phishing", "mule_accounts"],
        )

        # Create campaigns
        campaign1 = service.create_campaign(
            name="Banking Phishing Wave",
            target_sectors=["banking"],
            attack_vectors=["phishing"],
        )
        campaign2 = service.create_campaign(
            name="Retail Credential Theft",
            target_sectors=["retail"],
            attack_vectors=["credential_stealing"],
        )

        # Attribute campaigns
        service.attribute_campaign(
            campaign1.campaign_id,
            actor.actor_id,
            ConfidenceLevel.HIGH,
            ["shared_infrastructure", "similar_templates"],
        )
        service.attribute_campaign(
            campaign2.campaign_id,
            actor.actor_id,
            ConfidenceLevel.MEDIUM,
            ["overlapping_mule_accounts"],
        )

        # Generate profiles
        actor_profile = service.generate_threat_profile("actor", actor.actor_id)
        assert actor_profile is not None
        assert actor_profile.risk_score > 0

        # Perform risk assessment
        assessment = service.assess_risk("actor", actor.actor_id)
        assert assessment is not None
        assert assessment.risk_score > 0
        assert len(assessment.recommendations) > 0

        # Check stats
        stats = service.get_campaign_statistics()
        assert stats.total_campaigns == 2
        assert stats.total_actors == 1
        assert stats.attributed_campaigns == 2


class TestCampaignPerformance:
    """Performance tests for campaign system."""

    def setup_method(self):
        """Reset store before each test."""
        reset_campaign_store()

    def test_bulk_insert_performance(self):
        """Test bulk insert performance."""
        store = get_campaign_store()

        start = time.time()
        for i in range(1000):
            campaign = Campaign(
                name=f"Campaign {i}",
                status=CampaignStatus.ACTIVE,
            )
            store.store_campaign(campaign)
        elapsed = time.time() - start

        assert elapsed < 5.0
        assert store.get_stats().total_campaigns == 1000

    def test_o1_lookup_performance(self):
        """Test O(1) lookup performance."""
        store = get_campaign_store()
        campaign = Campaign(name="Test", status=CampaignStatus.ACTIVE)
        store.store_campaign(campaign)

        start = time.time()
        for _ in range(10000):
            result = store.get_campaign(campaign.campaign_id)
            assert result is not None
        elapsed = time.time() - start

        assert elapsed < 1.0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
