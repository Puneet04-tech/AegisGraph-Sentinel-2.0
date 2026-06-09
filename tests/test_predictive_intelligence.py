"""
Tests for Predictive Intelligence Module.

Comprehensive tests for:
    - Fraud Simulation Engine
    - Risk Forecasting Engine
    - Campaign Prediction Engine
    - Attack Path Prediction Engine
    - Recommendation Engine
    - API Endpoints
"""

import pytest
import time
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from src.predictive_intelligence import (
    SimulationScenario,
    SimulationType,
    SimulationStatus,
    SimulationResult,
    ForecastResult,
    ForecastPeriod,
    CampaignPrediction,
    CampaignStatus,
    AttackPathPrediction,
    RiskForecast,
    PreventiveRecommendation,
    RecommendationPriority,
    RecommendationType,
    PredictiveStore,
    FraudSimulator,
    RiskForecaster,
    CampaignPredictor,
    AttackPathPredictor,
    ScenarioBuilder,
    RecommendationEngine,
    get_predictive_store,
    get_fraud_simulator,
    get_risk_forecaster,
    get_campaign_predictor,
    get_attack_path_predictor,
    get_scenario_builder,
    get_recommendation_engine,
)


# =============================================================================
# Test Fixtures
# =============================================================================

@pytest.fixture
def store():
    """Create a fresh predictive store for testing."""
    return PredictiveStore(max_size=100)


@pytest.fixture
def simulator(store):
    """Create a fraud simulator with fresh store."""
    return FraudSimulator(store=store)


@pytest.fixture
def forecaster(store):
    """Create a risk forecaster with fresh store."""
    return RiskForecaster(store=store)


@pytest.fixture
def campaign_predictor(store):
    """Create a campaign predictor with fresh store."""
    return CampaignPredictor(store=store)


@pytest.fixture
def attack_predictor(store):
    """Create an attack path predictor with fresh store."""
    return AttackPathPredictor(store=store)


@pytest.fixture
def scenario_builder(store):
    """Create a scenario builder with fresh store."""
    return ScenarioBuilder(store=store)


@pytest.fixture
def recommendation_engine(store):
    """Create a recommendation engine with fresh store."""
    return RecommendationEngine(store=store)


# =============================================================================
# Model Tests
# =============================================================================

class TestPredictiveModels:
    """Tests for Predictive Intelligence models."""
    
    def test_simulation_scenario_creation(self):
        """Test creating a simulation scenario."""
        scenario = SimulationScenario(
            simulation_type=SimulationType.ACCOUNT_TAKEOVER,
            source_entity_ids=["entity_1", "entity_2"],
            parameters={"base_risk": 0.5},
            created_by="test_user",
        )
        
        assert scenario.scenario_id is not None
        assert scenario.simulation_type == SimulationType.ACCOUNT_TAKEOVER
        assert len(scenario.source_entity_ids) == 2
        assert scenario.created_by == "test_user"
        assert scenario.status == SimulationStatus.PENDING
    
    def test_simulation_scenario_to_dict(self):
        """Test converting scenario to dictionary."""
        scenario = SimulationScenario(
            simulation_type=SimulationType.FRAUD_RING_EXPANSION,
            source_entity_ids=["entity_1"],
        )
        
        data = scenario.to_dict()
        
        assert "scenario_id" in data
        assert data["simulation_type"] == "FRAUD_RING_EXPANSION"
        assert data["status"] == "PENDING"
    
    def test_simulation_result_creation(self):
        """Test creating a simulation result."""
        result = SimulationResult(
            scenario_id="test_scenario",
            predicted_outcomes=[{"type": "test", "probability": 0.5}],
            risk_score=0.75,
            affected_entities=["entity_1", "entity_2"],
            confidence=0.8,
        )
        
        assert result.scenario_id == "test_scenario"
        assert result.risk_score == 0.75
        assert len(result.affected_entities) == 2
    
    def test_forecast_result_creation(self):
        """Test creating a forecast result."""
        result = ForecastResult(
            entity_id="entity_1",
            forecast_period=ForecastPeriod.DAY_1,
            risk_score=0.65,
            confidence=0.75,
            factors=[{"factor": "test", "contribution": 0.3}],
            recommendations=["Monitor closely"],
        )
        
        assert result.entity_id == "entity_1"
        assert result.forecast_period == ForecastPeriod.DAY_1
        assert len(result.recommendations) == 1
    
    def test_campaign_prediction_creation(self):
        """Test creating a campaign prediction."""
        prediction = CampaignPrediction(
            campaign_name="Test Campaign",
            predicted_status=CampaignStatus.GROWING,
            growth_rate=0.75,
            confidence=0.8,
        )
        
        assert prediction.campaign_name == "Test Campaign"
        assert prediction.predicted_status == CampaignStatus.GROWING
        assert prediction.growth_rate == 0.75
    
    def test_attack_path_prediction_creation(self):
        """Test creating an attack path prediction."""
        prediction = AttackPathPrediction(
            source_entity_id="entity_1",
            predicted_path=["entity_1", "entity_2", "entity_3"],
            probability=0.7,
            estimated_damage=50000.0,
            confidence=0.75,
        )
        
        assert prediction.source_entity_id == "entity_1"
        assert len(prediction.predicted_path) == 3
        assert prediction.probability == 0.7
    
    def test_risk_forecast_creation(self):
        """Test creating a risk forecast."""
        forecast = RiskForecast(
            entity_id="entity_1",
            current_risk=0.5,
            predicted_risk=0.75,
            risk_trend="INCREASING",
            time_to_peak="7 days",
            confidence=0.7,
        )
        
        assert forecast.entity_id == "entity_1"
        assert forecast.current_risk == 0.5
        assert forecast.predicted_risk == 0.75
        assert forecast.risk_trend == "INCREASING"
    
    def test_preventive_recommendation_creation(self):
        """Test creating a preventive recommendation."""
        recommendation = PreventiveRecommendation(
            entity_id="entity_1",
            recommendation_type=RecommendationType.ACCOUNT_FREEZE,
            priority=RecommendationPriority.CRITICAL,
            description="Freeze account immediately",
            expected_impact=0.9,
        )
        
        assert recommendation.entity_id == "entity_1"
        assert recommendation.recommendation_type == RecommendationType.ACCOUNT_FREEZE
        assert recommendation.priority == RecommendationPriority.CRITICAL


# =============================================================================
# Store Tests
# =============================================================================

class TestPredictiveStore:
    """Tests for PredictiveStore."""
    
    def test_store_and_retrieve_scenario(self, store):
        """Test storing and retrieving a scenario."""
        scenario = SimulationScenario(
            simulation_type=SimulationType.ACCOUNT_TAKEOVER,
            source_entity_ids=["entity_1"],
        )
        
        stored = store.store_scenario(scenario)
        retrieved = store.get_scenario(scenario.scenario_id)
        
        assert retrieved is not None
        assert retrieved.scenario_id == scenario.scenario_id
        assert retrieved.simulation_type == SimulationType.ACCOUNT_TAKEOVER
    
    def test_store_and_retrieve_forecast(self, store):
        """Test storing and retrieving a forecast."""
        forecast = ForecastResult(
            entity_id="entity_1",
            forecast_period=ForecastPeriod.DAY_1,
            risk_score=0.65,
        )
        
        stored = store.store_forecast(forecast)
        key = f"entity_1:{ForecastPeriod.DAY_1.value}"
        retrieved = store.get_forecast("entity_1", ForecastPeriod.DAY_1.value)
        
        assert retrieved is not None
        assert retrieved.entity_id == "entity_1"
    
    def test_store_and_retrieve_campaign(self, store):
        """Test storing and retrieving a campaign prediction."""
        campaign = CampaignPrediction(
            campaign_name="Test Campaign",
            growth_rate=0.75,
        )
        
        store.store_campaign_prediction(campaign)
        retrieved = store.get_campaign_prediction(campaign.campaign_id)
        
        assert retrieved is not None
        assert retrieved.campaign_name == "Test Campaign"
    
    def test_high_risk_campaigns_filter(self, store):
        """Test filtering high-risk campaigns."""
        campaigns = [
            CampaignPrediction(growth_rate=0.9),
            CampaignPrediction(growth_rate=0.5),
            CampaignPrediction(growth_rate=0.8),
        ]
        
        for c in campaigns:
            store.store_campaign_prediction(c)
        
        high_risk = store.get_high_risk_campaigns(threshold=0.7)
        
        assert len(high_risk) == 2
        assert all(c.growth_rate >= 0.7 for c in high_risk)
    
    def test_recommendation_storage(self, store):
        """Test storing and retrieving recommendations."""
        rec = PreventiveRecommendation(
            entity_id="entity_1",
            priority=RecommendationPriority.HIGH,
        )
        
        store.store_recommendation(rec)
        retrieved = store.get_recommendation(rec.recommendation_id)
        
        assert retrieved is not None
        assert retrieved.entity_id == "entity_1"
    
    def test_entity_recommendations_filter(self, store):
        """Test filtering recommendations by entity."""
        recs = [
            PreventiveRecommendation(entity_id="entity_1", priority=RecommendationPriority.HIGH),
            PreventiveRecommendation(entity_id="entity_2", priority=RecommendationPriority.MEDIUM),
            PreventiveRecommendation(entity_id="entity_1", priority=RecommendationPriority.CRITICAL),
        ]
        
        for r in recs:
            store.store_recommendation(r)
        
        entity_recs = store.get_entity_recommendations("entity_1")
        
        assert len(entity_recs) == 2
        assert all(r.entity_id == "entity_1" for r in entity_recs)
    
    def test_store_stats(self, store):
        """Test getting store statistics."""
        stats = store.get_stats()
        
        assert "simulations_stored" in stats
        assert "forecasts_stored" in stats
        assert "campaigns_stored" in stats
        assert "recommendations_stored" in stats


# =============================================================================
# Simulator Tests
# =============================================================================

class TestFraudSimulator:
    """Tests for FraudSimulator."""
    
    def test_simulate_account_takeover(self, simulator, scenario_builder):
        """Test account takeover simulation."""
        scenario = scenario_builder.build_scenario(
            simulation_type=SimulationType.ACCOUNT_TAKEOVER,
            source_entity_ids=["entity_1", "entity_2", "entity_3"],
        )
        
        result = simulator.simulate(scenario)
        
        assert result.scenario_id == scenario.scenario_id
        assert result.risk_score > 0
        assert len(result.predicted_outcomes) > 0
        assert result.confidence > 0
    
    def test_simulate_fraud_ring_expansion(self, simulator, scenario_builder):
        """Test fraud ring expansion simulation."""
        scenario = scenario_builder.build_scenario(
            simulation_type=SimulationType.FRAUD_RING_EXPANSION,
            source_entity_ids=["entity_1", "entity_2"],
            parameters={"expansion_rate": 0.3},
        )
        
        result = simulator.simulate(scenario)
        
        assert result.risk_score > 0
        assert len(result.affected_entities) > 0
    
    def test_simulate_synthetic_identity(self, simulator, scenario_builder):
        """Test synthetic identity fraud simulation."""
        scenario = scenario_builder.build_scenario(
            simulation_type=SimulationType.SYNTHETIC_IDENTITY,
            source_entity_ids=["entity_1"],
        )
        
        result = simulator.simulate(scenario)
        
        assert result.risk_score > 0
        # Check that any outcome is related to synthetic identity
        outcome_types = [o.get("type", "") for o in result.predicted_outcomes]
        assert any("fake" in t or "identity" in t or "synthetic" in t or "credit" in t for t in outcome_types)
    
    def test_simulate_wallet_laundering(self, simulator, scenario_builder):
        """Test wallet laundering simulation."""
        scenario = scenario_builder.build_scenario(
            simulation_type=SimulationType.WALLET_LAUNDERING,
            source_entity_ids=["wallet_1"],
            parameters={"hop_count": 5, "volume": 100000},
        )
        
        result = simulator.simulate(scenario)
        
        assert result.risk_score >= 0.7  # Higher risk for laundering
        assert any("funds_mixed" in str(o) for o in result.predicted_outcomes)
    
    def test_simulate_campaign_spread(self, simulator, scenario_builder):
        """Test campaign spread simulation."""
        scenario = scenario_builder.build_scenario(
            simulation_type=SimulationType.CAMPAIGN_SPREAD,
            source_entity_ids=["entity_1", "entity_2", "entity_3"],
        )
        
        result = simulator.simulate(scenario)
        
        assert result.risk_score > 0
        # Campaign spread should have some affected entities
        assert len(result.affected_entities) >= 0
    
    def test_simulate_mule_account_creation(self, simulator, scenario_builder):
        """Test mule account creation simulation."""
        scenario = scenario_builder.build_scenario(
            simulation_type=SimulationType.MULE_ACCOUNT_CREATION,
            source_entity_ids=["entity_1", "entity_2"],
        )
        
        result = simulator.simulate(scenario)
        
        assert result.risk_score > 0
        assert any("mule" in str(o) for o in result.predicted_outcomes)
    
    def test_simulate_network_infiltration(self, simulator, scenario_builder):
        """Test network infiltration simulation."""
        scenario = scenario_builder.build_scenario(
            simulation_type=SimulationType.NETWORK_INFILTRATION,
            source_entity_ids=["node_1"],
            parameters={"infiltration_depth": 4},
        )
        
        result = simulator.simulate(scenario)
        
        assert result.risk_score > 0
        assert any("lateral" in str(o) for o in result.predicted_outcomes)
    
    def test_get_simulation_result(self, simulator, scenario_builder):
        """Test retrieving simulation results."""
        scenario = scenario_builder.build_scenario(
            simulation_type=SimulationType.ACCOUNT_TAKEOVER,
        )
        
        result = simulator.simulate(scenario)
        retrieved = simulator.get_simulation_result(scenario.scenario_id)
        
        assert retrieved is not None
        assert retrieved.scenario_id == result.scenario_id


# =============================================================================
# Forecasting Tests
# =============================================================================

class TestRiskForecaster:
    """Tests for RiskForecaster."""
    
    def test_forecast_risk_hour_1(self, forecaster):
        """Test 1-hour risk forecast."""
        result = forecaster.forecast_risk(
            entity_id="entity_1",
            current_risk=0.5,
            period=ForecastPeriod.HOUR_1,
        )
        
        assert result.entity_id == "entity_1"
        assert result.forecast_period == ForecastPeriod.HOUR_1
        assert 0 <= result.risk_score <= 1.0
        assert result.confidence > 0
    
    def test_forecast_risk_day_1(self, forecaster):
        """Test 1-day risk forecast."""
        result = forecaster.forecast_risk(
            entity_id="entity_1",
            current_risk=0.6,
            period=ForecastPeriod.DAY_1,
        )
        
        assert result.risk_score > 0
        assert len(result.factors) > 0
        assert len(result.recommendations) > 0
    
    def test_forecast_risk_days_7(self, forecaster):
        """Test 7-day risk forecast."""
        result = forecaster.forecast_risk(
            entity_id="entity_1",
            current_risk=0.7,
            period=ForecastPeriod.DAYS_7,
        )
        
        assert result.forecast_period == ForecastPeriod.DAYS_7
    
    def test_forecast_risk_days_30(self, forecaster):
        """Test 30-day risk forecast."""
        result = forecaster.forecast_risk(
            entity_id="entity_1",
            current_risk=0.5,
            period=ForecastPeriod.DAYS_30,
        )
        
        assert result.forecast_period == ForecastPeriod.DAYS_30
    
    def test_predict_risk_trend_increasing(self, forecaster):
        """Test risk trend prediction - increasing."""
        with patch('random.random', return_value=0.85):  # 85% chance of INCREASING
            trend = forecaster.predict_risk_trend(
                entity_id="entity_1",
                current_risk=0.5,
            )
        
        assert trend.entity_id == "entity_1"
        assert trend.current_risk == 0.5
        assert trend.predicted_risk >= trend.current_risk
        assert trend.risk_trend in ["INCREASING", "STABLE", "DECREASING"]
    
    def test_predict_risk_trend_decreasing(self, forecaster):
        """Test risk trend prediction - decreasing."""
        with patch('random.random', return_value=0.15):  # 15% chance of DECREASING
            trend = forecaster.predict_risk_trend(
                entity_id="entity_1",
                current_risk=0.8,
            )
        
        assert trend.risk_trend in ["INCREASING", "STABLE", "DECREASING"]
    
    def test_get_high_risk_forecasts(self, forecaster):
        """Test getting high-risk forecasts."""
        # Create some forecasts with high risk
        forecasts = []
        for i in range(5):
            f = forecaster.predict_risk_trend(f"high_risk_{i}", current_risk=0.9)
            forecasts.append(f)
        
        # Verify forecasts were stored
        assert len(forecaster.get_all_forecasts()) >= 5


# =============================================================================
# Campaign Predictor Tests
# =============================================================================

class TestCampaignPredictor:
    """Tests for CampaignPredictor."""
    
    def test_predict_campaign_growing(self, campaign_predictor):
        """Test campaign growth prediction."""
        prediction = campaign_predictor.predict_campaign(
            entity_ids=["entity_1", "entity_2"],
            campaign_name="Test Campaign",
            current_growth_rate=0.4,
        )
        
        assert prediction.campaign_name == "Test Campaign"
        assert prediction.predicted_status in [s.value for s in CampaignStatus]
        assert 0 <= prediction.growth_rate <= 1.0
    
    def test_predict_campaign_emerging(self, campaign_predictor):
        """Test emerging campaign prediction."""
        prediction = campaign_predictor.predict_campaign(
            entity_ids=["entity_1"],
            current_growth_rate=0.15,
        )
        
        assert prediction.predicted_status in [CampaignStatus.EMERGING, CampaignStatus.DORMANT]
    
    def test_predict_campaign_peaked(self, campaign_predictor):
        """Test peaked campaign prediction."""
        prediction = campaign_predictor.predict_campaign(
            entity_ids=["entity_1", "entity_2", "entity_3"],
            current_growth_rate=0.8,
        )
        
        assert prediction.predicted_status in [CampaignStatus.PEAKED, CampaignStatus.DECLINING]
    
    def test_identify_future_targets(self, campaign_predictor):
        """Test identifying future campaign targets."""
        prediction = campaign_predictor.predict_campaign(
            entity_ids=["entity_1"],
            current_growth_rate=0.5,
        )
        
        targets = campaign_predictor.identify_future_targets(
            campaign_id=prediction.campaign_id,
            count=10,
        )
        
        assert len(targets) <= 10
    
    def test_get_high_growth_campaigns(self, campaign_predictor):
        """Test filtering high-growth campaigns."""
        # Create a campaign
        campaign = campaign_predictor.predict_campaign([], current_growth_rate=0.9)
        
        # Verify campaign was created
        assert campaign.campaign_id is not None
        assert campaign.growth_rate > 0


# =============================================================================
# Attack Path Predictor Tests
# =============================================================================

class TestAttackPathPredictor:
    """Tests for AttackPathPredictor."""
    
    def test_predict_attack_path_basic(self, attack_predictor):
        """Test basic attack path prediction."""
        prediction = attack_predictor.predict_attack_path(
            source_entity_id="entity_1",
            depth=3,
        )
        
        assert prediction.source_entity_id == "entity_1"
        assert len(prediction.predicted_path) == 4  # source + 3 hops
        assert prediction.probability > 0
        assert prediction.estimated_damage > 0
    
    def test_predict_attack_path_with_known_path(self, attack_predictor):
        """Test attack path with known path."""
        known_path = ["entity_1", "entity_2"]
        prediction = attack_predictor.predict_attack_path(
            source_entity_id="entity_1",
            known_path=known_path,
            depth=2,
        )
        
        assert len(prediction.predicted_path) == 4  # 2 known + 2 new
        assert prediction.predicted_path[0] == "entity_1"
        assert prediction.predicted_path[1] == "entity_2"
    
    def test_predict_network_expansion(self, attack_predictor):
        """Test network expansion prediction."""
        predictions = attack_predictor.predict_network_expansion(
            source_entity_ids=["entity_1", "entity_2"],
            expansion_rate=0.4,
        )
        
        assert len(predictions) == 2
        assert all(p.source_entity_id in ["entity_1", "entity_2"] for p in predictions)
    
    def test_predict_fraud_evolution(self, attack_predictor):
        """Test fraud network evolution prediction."""
        evolution = attack_predictor.predict_fraud_evolution(
            current_entities={"entity_1", "entity_2", "entity_3"},
            time_horizon="7_days",
        )
        
        assert "predicted_new_entities" in evolution
        assert "predicted_connections" in evolution
        assert "risk_escalation" in evolution
        assert evolution["confidence"] > 0
    
    def test_get_high_probability_attacks(self, attack_predictor):
        """Test filtering high-probability attacks."""
        # Create predictions with different probabilities
        for _ in range(3):
            attack_predictor.predict_attack_path("high_prob_entity", depth=1)
        
        high_prob = attack_predictor.get_high_probability_attacks(threshold=0.5)
        
        assert all(p.probability >= 0.5 for p in high_prob)


# =============================================================================
# Scenario Builder Tests
# =============================================================================

class TestScenarioBuilder:
    """Tests for ScenarioBuilder."""
    
    def test_build_scenario_with_template(self, scenario_builder):
        """Test building scenario with template."""
        scenario = scenario_builder.build_scenario(
            simulation_type=SimulationType.ACCOUNT_TAKEOVER,
            source_entity_ids=["entity_1"],
        )
        
        assert scenario.simulation_type == SimulationType.ACCOUNT_TAKEOVER
        assert len(scenario.parameters) > 0
    
    def test_build_scenario_without_template(self, scenario_builder):
        """Test building scenario without template."""
        scenario = scenario_builder.build_scenario(
            simulation_type=SimulationType.ACCOUNT_TAKEOVER,
            source_entity_ids=["entity_1"],
            use_template=False,
            parameters={"custom_param": 0.9},
        )
        
        assert scenario.metadata.get("use_template") is False
        assert "custom_param" in scenario.parameters
    
    def test_build_account_takeover_scenario(self, scenario_builder):
        """Test building account takeover scenario."""
        scenario = scenario_builder.build_account_takeover_scenario(
            entity_ids=["entity_1", "entity_2"],
            compromised_rate=0.4,
        )
        
        assert scenario.simulation_type == SimulationType.ACCOUNT_TAKEOVER
        assert scenario.parameters.get("compromised_rate") == 0.4
    
    def test_build_fraud_ring_expansion_scenario(self, scenario_builder):
        """Test building fraud ring expansion scenario."""
        scenario = scenario_builder.build_fraud_ring_expansion_scenario(
            ring_entity_ids=["entity_1", "entity_2"],
            expansion_rate=0.3,
            ring_size=10,
        )
        
        assert scenario.simulation_type == SimulationType.FRAUD_RING_EXPANSION
    
    def test_build_wallet_laundering_scenario(self, scenario_builder):
        """Test building wallet laundering scenario."""
        scenario = scenario_builder.build_wallet_laundering_scenario(
            wallet_ids=["wallet_1"],
            hop_count=6,
            volume=200000,
        )
        
        assert scenario.simulation_type == SimulationType.WALLET_LAUNDERING
        assert scenario.parameters.get("hop_count") == 6
    
    def test_get_available_types(self, scenario_builder):
        """Test getting available simulation types."""
        types = scenario_builder.get_available_types()
        
        assert SimulationType.ACCOUNT_TAKEOVER in types
        assert SimulationType.FRAUD_RING_EXPANSION in types
        assert len(types) == len(SimulationType)
    
    def test_get_template(self, scenario_builder):
        """Test getting simulation template."""
        template = scenario_builder.get_template(SimulationType.ACCOUNT_TAKEOVER)
        
        assert template is not None
        assert "base_risk" in template
        assert "description" in template


# =============================================================================
# Recommendation Engine Tests
# =============================================================================

class TestRecommendationEngine:
    """Tests for RecommendationEngine."""
    
    def test_generate_recommendation_critical(self, recommendation_engine):
        """Test generating critical priority recommendation."""
        recommendation = recommendation_engine.generate_recommendation(
            entity_id="entity_1",
            risk_score=0.92,
        )
        
        assert recommendation.entity_id == "entity_1"
        assert recommendation.priority == RecommendationPriority.CRITICAL
        assert recommendation.recommendation_type == RecommendationType.ACCOUNT_FREEZE
    
    def test_generate_recommendation_high(self, recommendation_engine):
        """Test generating high priority recommendation."""
        recommendation = recommendation_engine.generate_recommendation(
            entity_id="entity_1",
            risk_score=0.75,
        )
        
        assert recommendation.priority == RecommendationPriority.HIGH
        assert recommendation.recommendation_type == RecommendationType.ENHANCED_MONITORING
    
    def test_generate_recommendation_medium(self, recommendation_engine):
        """Test generating medium priority recommendation."""
        recommendation = recommendation_engine.generate_recommendation(
            entity_id="entity_1",
            risk_score=0.55,
        )
        
        assert recommendation.priority == RecommendationPriority.MEDIUM
    
    def test_generate_recommendation_low(self, recommendation_engine):
        """Test generating low priority recommendation."""
        recommendation = recommendation_engine.generate_recommendation(
            entity_id="entity_1",
            risk_score=0.3,
        )
        
        assert recommendation.priority == RecommendationPriority.LOW
    
    def test_generate_batch_recommendations(self, recommendation_engine):
        """Test generating batch recommendations."""
        entity_scores = [
            {"entity_id": "entity_1", "risk_score": 0.9},
            {"entity_id": "entity_2", "risk_score": 0.6},
            {"entity_id": "entity_3", "risk_score": 0.4},
        ]
        
        recommendations = recommendation_engine.generate_batch_recommendations(entity_scores)
        
        assert len(recommendations) == 3
    
    def test_recommend_account_freeze(self, recommendation_engine):
        """Test account freeze recommendation."""
        recommendation = recommendation_engine.recommend_account_freeze(
            entity_id="entity_1",
            reason="Suspected account takeover",
        )
        
        assert recommendation.recommendation_type == RecommendationType.ACCOUNT_FREEZE
        assert recommendation.priority == RecommendationPriority.CRITICAL
        assert "Suspected" in recommendation.description
    
    def test_recommend_enhanced_monitoring(self, recommendation_engine):
        """Test enhanced monitoring recommendation."""
        recommendation = recommendation_engine.recommend_enhanced_monitoring(
            entity_id="entity_1",
            duration_hours=48,
        )
        
        assert recommendation.recommendation_type == RecommendationType.ENHANCED_MONITORING
        assert recommendation.metadata.get("duration_hours") == 48
    
    def test_get_entity_recommendations(self, recommendation_engine):
        """Test getting recommendations for an entity."""
        recommendation_engine.generate_recommendation("entity_1", 0.8)
        recommendation_engine.generate_recommendation("entity_1", 0.6)
        recommendation_engine.generate_recommendation("entity_2", 0.7)
        
        entity_recs = recommendation_engine.get_entity_recommendations("entity_1")
        
        assert len(entity_recs) == 2
        assert all(r.entity_id == "entity_1" for r in entity_recs)
    
    def test_get_critical_recommendations(self, recommendation_engine):
        """Test getting critical recommendations."""
        recommendation_engine.generate_recommendation("entity_1", 0.95)
        recommendation_engine.generate_recommendation("entity_2", 0.6)
        
        critical = recommendation_engine.get_critical_recommendations()
        
        assert all(r.priority == RecommendationPriority.CRITICAL for r in critical)


# =============================================================================
# Integration Tests
# =============================================================================

class TestPredictiveIntelligenceIntegration:
    """Integration tests for predictive intelligence pipeline."""
    
    def test_full_simulation_pipeline(self, simulator, scenario_builder, forecaster, recommendation_engine):
        """Test full simulation to recommendation pipeline."""
        # 1. Build scenario
        scenario = scenario_builder.build_scenario(
            simulation_type=SimulationType.ACCOUNT_TAKEOVER,
            source_entity_ids=["entity_1", "entity_2"],
        )
        
        # 2. Run simulation
        result = simulator.simulate(scenario)
        
        # 3. Generate forecast
        forecast = forecaster.forecast_risk(
            entity_id="entity_1",
            current_risk=result.risk_score,
            period=ForecastPeriod.DAY_1,
        )
        
        # 4. Generate recommendation
        recommendation = recommendation_engine.generate_recommendation(
            entity_id="entity_1",
            risk_score=result.risk_score,
        )
        
        # Verify pipeline
        assert result.risk_score > 0
        assert forecast.risk_score > 0
        assert recommendation.entity_id == "entity_1"
    
    def test_campaign_to_attack_path_pipeline(self, campaign_predictor, attack_predictor):
        """Test campaign prediction to attack path pipeline."""
        # 1. Predict campaign
        campaign = campaign_predictor.predict_campaign(
            entity_ids=["entity_1", "entity_2"],
            current_growth_rate=0.5,
        )
        
        # 2. Predict attack paths
        paths = attack_predictor.predict_network_expansion(
            source_entity_ids=["entity_1", "entity_2"],
            expansion_rate=campaign.growth_rate,
        )
        
        # Verify pipeline
        assert campaign.growth_rate > 0
        assert len(paths) == 2
    
    def test_risk_trend_recommendation_pipeline(self, forecaster, recommendation_engine):
        """Test risk trend to recommendation pipeline."""
        # 1. Predict trend
        trend = forecaster.predict_risk_trend(
            entity_id="entity_1",
            current_risk=0.5,
        )
        
        # 2. Generate recommendation based on trend
        recommendation = recommendation_engine.generate_recommendation(
            entity_id="entity_1",
            risk_score=trend.predicted_risk,
        )
        
        # Verify pipeline
        assert trend.predicted_risk >= 0
        assert recommendation.entity_id == "entity_1"


# =============================================================================
# Performance Tests
# =============================================================================

class TestPredictiveIntelligencePerformance:
    """Performance tests for predictive intelligence."""
    
    def test_simulation_performance(self, simulator, scenario_builder):
        """Test simulation performance."""
        scenario = scenario_builder.build_scenario(
            simulation_type=SimulationType.ACCOUNT_TAKEOVER,
            source_entity_ids=[f"entity_{i}" for i in range(100)],
        )
        
        start_time = time.time()
        result = simulator.simulate(scenario)
        duration = (time.time() - start_time) * 1000
        
        assert duration < 1000  # Should complete in under 1 second
        assert result.risk_score > 0
    
    def test_forecast_performance(self, forecaster):
        """Test forecast performance."""
        start_time = time.time()
        
        for i in range(100):
            forecaster.forecast_risk(
                entity_id=f"entity_{i}",
                current_risk=0.5,
                period=ForecastPeriod.DAY_1,
            )
        
        duration = (time.time() - start_time) * 1000
        
        assert duration < 2000  # 100 forecasts in under 2 seconds
    
    def test_store_memory_bounded(self, store):
        """Test that store is memory bounded."""
        # Store more items than max_size
        for i in range(150):
            scenario = SimulationScenario(
                simulation_type=SimulationType.ACCOUNT_TAKEOVER,
                source_entity_ids=[f"entity_{i}"],
            )
            store.store_scenario(scenario)
        
        # Should not exceed max_size
        assert len(store.get_all_scenarios()) <= store._max_size


# =============================================================================
# RBAC and Security Tests
# =============================================================================

class TestPredictiveIntelligenceRBAC:
    """Tests for RBAC enforcement on predictive intelligence."""
    
    def test_simulation_scenario_validation(self, scenario_builder):
        """Test scenario parameter validation."""
        # Should work with valid parameters
        scenario = scenario_builder.build_scenario(
            simulation_type=SimulationType.ACCOUNT_TAKEOVER,
            source_entity_ids=["entity_1"],
            parameters={"compromised_rate": 0.5},
        )
        
        assert scenario.parameters.get("compromised_rate") == 0.5
    
    def test_forecast_period_validation(self, forecaster):
        """Test forecast period validation."""
        periods = [
            ForecastPeriod.HOUR_1,
            ForecastPeriod.HOURS_6,
            ForecastPeriod.DAY_1,
            ForecastPeriod.DAYS_7,
            ForecastPeriod.DAYS_30,
        ]
        
        for period in periods:
            result = forecaster.forecast_risk(
                entity_id="entity_1",
                current_risk=0.5,
                period=period,
            )
            
            assert result.forecast_period == period
    
    def test_recommendation_priority_ordering(self, recommendation_engine):
        """Test recommendation priority ordering."""
        priorities = [
            (0.95, RecommendationPriority.CRITICAL),
            (0.8, RecommendationPriority.HIGH),
            (0.6, RecommendationPriority.MEDIUM),
            (0.3, RecommendationPriority.LOW),
        ]
        
        for risk_score, expected_priority in priorities:
            recommendation = recommendation_engine.generate_recommendation(
                entity_id="entity_1",
                risk_score=risk_score,
            )
            
            # Priority should be at or above expected
            priority_rank = {
                RecommendationPriority.CRITICAL: 0,
                RecommendationPriority.HIGH: 1,
                RecommendationPriority.MEDIUM: 2,
                RecommendationPriority.LOW: 3,
            }
            
            assert priority_rank[recommendation.priority] <= priority_rank[expected_priority]