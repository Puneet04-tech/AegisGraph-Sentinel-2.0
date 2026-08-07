"""Unit tests for the intelligence marketplace catalog.

Covers ``src.intelligence_marketplace``: ``Catalog`` and the
``IntelligenceAsset`` / ``Subscription`` / ``Publisher`` models.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from src.intelligence_marketplace.catalog import Catalog
from src.intelligence_marketplace.marketplace_models import (
    AssetStatus,
    AssetType,
    IntelligenceAsset,
    Publisher,
    Subscription,
    SubscriptionStatus,
)


@pytest.fixture
def catalog() -> Catalog:
    return Catalog()


def _asset(
    asset_id="a1",
    name="Fraud Ruleset",
    description="Rules for fraud detection",
    asset_type=AssetType.FRAUD_DETECTOR,
    publisher_id="p1",
    version="1.0",
    status=AssetStatus.PUBLISHED,
    tags=None,
    downloads=0,
) -> IntelligenceAsset:
    return IntelligenceAsset(
        asset_id=asset_id,
        name=name,
        description=description,
        asset_type=asset_type,
        publisher_id=publisher_id,
        version=version,
        status=status,
        tags=tags or [],
        downloads=downloads,
    )


def _publisher(publisher_id="p1", name="Acme Intel", verified=False) -> Publisher:
    return Publisher(publisher_id=publisher_id, name=name, description="d", verified=verified)


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class TestModels:
    def test_enum_values(self):
        assert AssetType.THREAT_FEED.value == "THREAT_FEED"
        assert AssetStatus.CERTIFIED.value == "CERTIFIED"
        assert SubscriptionStatus.ACTIVE.value == "ACTIVE"

    def test_asset_to_dict(self):
        asset = _asset(tags=["fraud"], downloads=5)
        asset.metadata = {"source": "osint"}
        data = asset.to_dict()
        assert data["asset_type"] == "FRAUD_DETECTOR"
        assert data["status"] == "PUBLISHED"
        assert data["downloads"] == 5
        assert data["metadata"] == {"source": "osint"}

    def test_subscription_to_dict(self):
        sub = Subscription(
            subscription_id="s1", asset_id="a1", subscriber_id="u1",
            status=SubscriptionStatus.ACTIVE,
            start_date=datetime(2026, 1, 1, tzinfo=timezone.utc),
            end_date=datetime(2026, 2, 1, tzinfo=timezone.utc),
            price_paid=99.5,
        )
        data = sub.to_dict()
        assert data["status"] == "ACTIVE"
        assert data["price_paid"] == 99.5

    def test_publisher_to_dict(self):
        pub = _publisher(verified=True)
        pub.total_assets = 3
        data = pub.to_dict()
        assert data["verified"] is True
        assert data["total_assets"] == 3


# ---------------------------------------------------------------------------
# Catalog
# ---------------------------------------------------------------------------


class TestCatalog:
    def test_add_and_get_asset(self, catalog):
        asset = _asset()
        catalog.add_publisher(_publisher())

        assert catalog.add_asset(asset) == "a1"
        assert catalog.get_asset("a1") is asset
        assert catalog.get_asset("missing") is None

    def test_add_asset_updates_publisher_stats(self, catalog):
        pub = _publisher()
        catalog.add_publisher(pub)
        catalog.add_asset(_asset())

        assert pub.total_assets == 1

    def test_publish_asset(self, catalog):
        catalog.add_publisher(_publisher())

        asset = catalog.publish_asset(
            "New Feed", "desc", "THREAT_FEED", "p1", "2.0", tags=["feeds"]
        )

        assert asset.status == AssetStatus.PUBLISHED
        assert asset.asset_type == AssetType.THREAT_FEED
        assert catalog.get_asset(asset.asset_id) is asset

    def test_search_by_query(self, catalog):
        catalog.add_asset(_asset(name="Fraud Ruleset"))
        catalog.add_asset(_asset(asset_id="a2", name="Ransomware Feed", asset_type=AssetType.THREAT_FEED, description="New ransomware campaign feeds"))

        assert len(catalog.search_assets(query="fraud")) == 1
        assert len(catalog.search_assets(query="threat")) == 0

    def test_search_by_type_and_status(self, catalog):
        catalog.add_asset(_asset())
        catalog.add_asset(_asset(asset_id="a2", asset_type=AssetType.THREAT_FEED, status=AssetStatus.DRAFT))

        assert len(catalog.search_assets(asset_type="FRAUD_DETECTOR")) == 1
        assert len(catalog.search_assets(status="DRAFT")) == 1

    def test_search_by_tags_and_download_ranking(self, catalog):
        catalog.add_asset(_asset(asset_id="a1", tags=["crimeware"], downloads=5))
        catalog.add_asset(_asset(asset_id="a2", tags=["crimeware"], downloads=50))
        catalog.add_asset(_asset(asset_id="a3", tags=["phishing"]))

        results = catalog.search_assets(tags=["crimeware"])
        assert [a.asset_id for a in results] == ["a2", "a1"]  # downloads desc

    def test_subscribe(self, catalog):
        catalog.add_publisher(_publisher())
        catalog.add_asset(_asset())

        subscription = catalog.subscribe("a1", "user-1", duration_days=30, price=49.0)

        assert subscription.status == SubscriptionStatus.ACTIVE
        assert subscription.subscriber_id == "user-1"
        assert (subscription.end_date - subscription.start_date).days == 30
        assert catalog.get_asset("a1").downloads == 1

    def test_subscribe_missing_asset(self, catalog):
        assert catalog.subscribe("missing", "user-1") is None

    def test_subscribe_updates_publisher_subscribers(self, catalog):
        pub = _publisher()
        catalog.add_publisher(pub)
        catalog.add_asset(_asset())

        catalog.subscribe("a1", "user-1")
        catalog.subscribe("a1", "user-2")

        assert pub.total_subscribers == 2

    def test_asset_and_user_subscriptions(self, catalog):
        catalog.add_asset(_asset())
        catalog.subscribe("a1", "user-1")
        catalog.subscribe("a1", "user-2")

        assert len(catalog.get_asset_subscriptions("a1")) == 2
        assert len(catalog.get_asset_subscriptions("missing")) == 0
        assert len(catalog.get_user_subscriptions("user-1")) == 1
        assert len(catalog.get_user_subscriptions("nobody")) == 0

    def test_publishers_and_top_ranking(self, catalog):
        p1 = _publisher("p1", "One")
        p2 = _publisher("p2", "Two")
        catalog.add_publisher(p1)
        catalog.add_publisher(p2)
        catalog.add_asset(_asset(publisher_id="p1"))
        catalog.add_asset(_asset(asset_id="a2", publisher_id="p1"))
        catalog.add_asset(_asset(asset_id="a3", publisher_id="p2"))

        assert catalog.get_publisher("p1") is p1
        assert catalog.get_publisher("missing") is None
        top = catalog.get_top_publishers(limit=1)
        assert top == [p1]

    def test_catalog_stats(self, catalog):
        catalog.add_asset(_asset())
        catalog.add_asset(_asset(asset_id="a2", asset_type=AssetType.THREAT_FEED, status=AssetStatus.DRAFT))
        catalog.subscribe("a1", "user-1")

        stats = catalog.get_catalog_stats()
        assert stats["total_assets"] == 2
        assert stats["total_subscriptions"] == 1
        assert stats["total_publishers"] == 0
        assert stats["by_type"]["FRAUD_DETECTOR"] == 1
        assert stats["by_status"]["DRAFT"] == 1
        assert stats["total_downloads"] == 1
