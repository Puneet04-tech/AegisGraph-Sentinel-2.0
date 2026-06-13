"""
Tests for Global Threat Forecasting Platform
"""

import pytest
from datetime import datetime, timezone

from src.threat_forecasting.models import (
    ThreatForecast,
    CampaignPrediction,
    TrendAnalysis,
)
from src.threat_forecasting.store import get_forecasting_store, reset_forecasting_store
from src.threat_forecasting.service import ThreatForecastingService


class TestForecastingModels:
    """Tests for forecasting models."""

    def test_create_forecast(self):
        """Test creating a forecast."""
        forecast = ThreatForecast(
            threat_type="ransomware",
            description="Predicted ransomware surge",
            predicted_impact="HIGH",
            confidence=0.85,
        )
        assert forecast.threat_type == "ransomware"
        assert forecast.confidence == 0.85

    def test_create_campaign_prediction(self):
        """Test creating a campaign prediction."""
        campaign = CampaignPrediction(
            campaign_name="Operation Storm",
            attack_vector="phishing",
            expected_scale="LARGE",
            predicted_start=datetime.now(timezone.utc),
        )
        assert campaign.attack_vector == "phishing"

    def test_create_trend_analysis(self):
        """Test creating a trend analysis."""
        trend = TrendAnalysis(
            metric_name="fraud_rate",
            trend_direction="UP",
            change_percentage=15.5,
        )
        assert trend.trend_direction == "UP"


class TestForecastingStore:
    """Tests for forecasting store."""

    def setup_method(self):
        """Set up test store."""
        reset_forecasting_store()
        self.store = get_forecasting_store()

    def test_store_forecast(self):
        """Test storing a forecast."""
        forecast = ThreatForecast(
            threat_type="test",
            description="Test",
            predicted_impact="LOW",
        )
        self.store.store_forecast(forecast)
        retrieved = self.store.get_forecast(forecast.forecast_id)
        assert retrieved is not None

    def test_store_campaign(self):
        """Test storing a campaign."""
        campaign = CampaignPrediction(
            campaign_name="Test",
            attack_vector="test",
            expected_scale="SMALL",
            predicted_start=datetime.now(timezone.utc),
        )
        self.store.store_campaign(campaign)
        retrieved = self.store.get_campaign(campaign.prediction_id)
        assert retrieved is not None


class TestForecastingService:
    """Tests for forecasting service."""

    def setup_method(self):
        """Set up test service."""
        reset_forecasting_store()
        self.service = ThreatForecastingService()

    def test_create_forecast(self):
        """Test creating a forecast."""
        forecast = self.service.create_forecast(
            threat_type="phishing",
            description="Phishing campaign predicted",
            predicted_impact="MEDIUM",
            confidence=0.8,
        )
        assert forecast.forecast_id is not None

    def test_predict_campaign(self):
        """Test predicting a campaign."""
        campaign = self.service.predict_campaign(
            campaign_name="Campaign Alpha",
            attack_vector="malware",
            expected_scale="MEDIUM",
            predicted_start=datetime.now(timezone.utc),
        )
        assert campaign.prediction_id is not None

    def test_analyze_trend(self):
        """Test analyzing a trend."""
        trend = self.service.analyze_trend(
            metric_name="attack_frequency",
            trend_direction="UP",
            change_percentage=20.0,
        )
        assert trend.trend_id is not None

    def test_estimate_impact(self):
        """Test estimating impact."""
        impact = self.service.estimate_impact(
            threat_type="fraud",
            estimated_loss_min=100000,
            estimated_loss_max=500000,
        )
        assert impact.impact_id is not None

    def test_predict_attack(self):
        """Test predicting an attack."""
        attack = self.service.predict_attack(
            attack_type="DDoS",
            precursor_indicators=["unusual_traffic", "port_scan"],
        )
        assert attack.prediction_id is not None

    def test_create_risk_forecast(self):
        """Test creating a risk forecast."""
        risk = self.service.create_risk_forecast(
            risk_category="operational",
            risk_level="HIGH",
            forecast_value=0.85,
            confidence=0.9,
        )
        assert risk.forecast_id is not None

    def test_get_metrics(self):
        """Test getting metrics."""
        self.service.create_forecast(
            threat_type="test",
            description="Test",
            predicted_impact="LOW",
        )
        metrics = self.service.get_metrics()
        assert metrics.total_forecasts >= 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
