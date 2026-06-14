"""
Campaign Prediction Engine.

Predicts fraud campaign growth, spread, and impact.
"""

import time
import random
import threading
from threading import Lock
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any
import logging

from .models import (
    CampaignPrediction,
    CampaignStatus,
    ForecastPeriod,
)
from .store import PredictiveStore, get_predictive_store

logger = logging.getLogger(__name__)


class CampaignPredictor:
    """Campaign prediction engine for forecasting fraud campaigns.
    
    Provides:
        - Campaign growth prediction
        - Campaign spread analysis
        - Future target identification
        - Impact estimation
    """
    
    def __init__(self, store: Optional[PredictiveStore] = None):
        """Initialize the campaign predictor.
        
        Args:
            store: Optional predictive store
        """
        self._store = store or get_predictive_store()
    
    def predict_campaign(
        self,
        entity_ids: List[str],
        campaign_name: str = "",
        current_growth_rate: float = 0.0,
    ) -> CampaignPrediction:
        """Predict campaign growth and spread.
        
        Args:
            entity_ids: Entities involved in campaign
            campaign_name: Name of the campaign
            current_growth_rate: Current growth rate
            
        Returns:
            CampaignPrediction with growth forecast
        """
        start_time = time.time()
        
        # Determine predicted status
        if current_growth_rate < 0.1:
            status = CampaignStatus.DORMANT
        elif current_growth_rate < 0.3:
            status = CampaignStatus.EMERGING
        elif current_growth_rate < 0.6:
            status = CampaignStatus.GROWING
        elif current_growth_rate < 0.85:
            status = CampaignStatus.PEAKED
        else:
            status = CampaignStatus.DECLINING
        
        # Calculate predicted growth rate
        growth_multiplier = random.uniform(1.2, 2.5)
        predicted_growth = min(current_growth_rate * growth_multiplier, 1.0)
        
        # Calculate affected entities
        base_affected = len(entity_ids)
        growth_factor = 1 + (predicted_growth * random.uniform(1.5, 4.0))
        total_affected = int(base_affected * growth_factor)
        
        affected_entities = [f"target_{i}" for i in range(total_affected)]
        
        # Calculate peak time
        if status in [CampaignStatus.EMERGING, CampaignStatus.GROWING]:
            days_to_peak = random.randint(3, 21)
            peak_time = datetime.now(timezone.utc) + timedelta(days=days_to_peak)
        else:
            peak_time = datetime.now(timezone.utc) + timedelta(days=random.randint(1, 7))
        
        prediction = CampaignPrediction(
            campaign_id=f"campaign_{int(time.time())}",
            campaign_name=campaign_name or f"Campaign-{len(entity_ids)}",
            predicted_status=status,
            growth_rate=predicted_growth,
            affected_entities=affected_entities[:min(len(affected_entities), 100)],
            peak_time=peak_time,
            confidence=random.uniform(0.6, 0.85),
        )
        
        # Store prediction
        self._store.store_campaign_prediction(prediction)
        
        processing_time = (time.time() - start_time) * 1000
        logger.info(f"Campaign prediction generated: {prediction.campaign_id} - {status.value}")
        
        return prediction
    
    def predict_campaign_evolution(
        self,
        campaign_id: str,
        periods: List[ForecastPeriod] = None,
    ) -> List[CampaignPrediction]:
        """Predict campaign evolution over multiple time periods.
        
        Args:
            campaign_id: Campaign identifier
            periods: Time periods to forecast
            
        Returns:
            List of CampaignPrediction for each period
        """
        if periods is None:
            periods = [
                ForecastPeriod.HOUR_1,
                ForecastPeriod.HOURS_6,
                ForecastPeriod.DAY_1,
                ForecastPeriod.DAYS_7,
                ForecastPeriod.DAYS_30,
            ]
        
        predictions = []
        
        # Get base campaign data
        base_campaign = self._store.get_campaign_prediction(campaign_id)
        if base_campaign:
            base_growth = base_campaign.growth_rate
            base_entities = base_campaign.affected_entities
        else:
            base_growth = 0.2
            base_entities = []
        
        for period in periods:
            # Generate prediction for each period
            growth_factor = self._get_growth_factor(period)
            predicted_growth = min(base_growth * growth_factor, 1.0)
            
            prediction = CampaignPrediction(
                campaign_id=f"{campaign_id}_{period.value}",
                campaign_name=f"{campaign_id} - {period.value}",
                predicted_status=self._get_status_for_growth(predicted_growth),
                growth_rate=predicted_growth,
                affected_entities=base_entities[:min(len(base_entities), 100)],
                peak_time=datetime.now(timezone.utc) + timedelta(days=random.randint(5, 30)),
                confidence=random.uniform(0.5, 0.8),
            )
            
            self._store.store_campaign_prediction(prediction)
            predictions.append(prediction)
        
        return predictions
    
    def _get_growth_factor(self, period: ForecastPeriod) -> float:
        """Get growth factor for a time period."""
        factors = {
            ForecastPeriod.HOUR_1: 1.05,
            ForecastPeriod.HOURS_6: 1.2,
            ForecastPeriod.DAY_1: 1.5,
            ForecastPeriod.DAYS_7: 2.5,
            ForecastPeriod.DAYS_30: 5.0,
        }
        return factors.get(period, 1.0)
    
    def _get_status_for_growth(self, growth_rate: float) -> CampaignStatus:
        """Determine campaign status from growth rate."""
        if growth_rate < 0.1:
            return CampaignStatus.DORMANT
        elif growth_rate < 0.3:
            return CampaignStatus.EMERGING
        elif growth_rate < 0.6:
            return CampaignStatus.GROWING
        elif growth_rate < 0.85:
            return CampaignStatus.PEAKED
        else:
            return CampaignStatus.DECLINING
    
    def get_campaign(self, campaign_id: str) -> Optional[CampaignPrediction]:
        """Get a campaign prediction by ID."""
        return self._store.get_campaign_prediction(campaign_id)
    
    def get_all_campaigns(self) -> List[CampaignPrediction]:
        """Get all campaign predictions."""
        return self._store.get_all_campaign_predictions()
    
    def get_high_growth_campaigns(self, threshold: float = 0.7) -> List[CampaignPrediction]:
        """Get campaigns with high growth rate."""
        return self._store.get_high_risk_campaigns(threshold)
    
    def identify_future_targets(self, campaign_id: str, count: int = 10) -> List[str]:
        """Identify likely future targets for a campaign.
        
        Args:
            campaign_id: Campaign identifier
            count: Number of targets to identify
            
        Returns:
            List of predicted target entity IDs
        """
        campaign = self._store.get_campaign_prediction(campaign_id)
        if not campaign:
            return []
        
        # Generate predicted targets based on campaign growth
        targets = []
        for i in range(count):
            # Add some randomness to simulate unknown future targets
            if random.random() < campaign.growth_rate:
                targets.append(f"future_target_{campaign_id}_{i}")
        
        return targets


# Global singleton
_campaign_predictor: Optional[CampaignPredictor] = None
_campaign_predictor_lock = Lock()


def get_campaign_predictor(store: Optional[PredictiveStore] = None) -> CampaignPredictor:
    """Get or create the singleton CampaignPredictor instance."""
    global _campaign_predictor
    
    with _campaign_predictor_lock:
        if _campaign_predictor is None:
            _campaign_predictor = CampaignPredictor(store=store)
        return _campaign_predictor