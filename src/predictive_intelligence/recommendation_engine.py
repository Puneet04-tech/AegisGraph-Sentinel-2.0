"""
Prevention Recommendation Engine.

Generates proactive prevention recommendations based on predictive analysis.
"""

import random
import threading
from threading import Lock
from typing import Dict, List, Optional, Any
import logging

from .models import (
    PreventiveRecommendation,
    RecommendationType,
    RecommendationPriority,
)
from .store import PredictiveStore, get_predictive_store

logger = logging.getLogger(__name__)


class RecommendationEngine:
    """Prevention recommendation engine for proactive fraud mitigation.
    
    Generates recommendations for:
        - Account freezes
        - Enhanced monitoring
        - Analyst reviews
        - Entity blocking
        - Transaction limits
        - Device restrictions
        - KYC enhancements
        - Alert creation
    """
    
    def __init__(self, store: Optional[PredictiveStore] = None):
        """Initialize the recommendation engine.
        
        Args:
            store: Optional predictive store
        """
        self._store = store or get_predictive_store()
        
        # Recommendation templates
        self._templates = self._load_templates()
    
    def _load_templates(self) -> Dict[RecommendationType, Dict[str, Any]]:
        """Load recommendation templates."""
        return {
            RecommendationType.ACCOUNT_FREEZE: {
                "priority": RecommendationPriority.CRITICAL,
                "description": "Immediately freeze account due to high risk",
                "expected_impact": 0.9,
            },
            RecommendationType.ENHANCED_MONITORING: {
                "priority": RecommendationPriority.HIGH,
                "description": "Enable enhanced transaction monitoring",
                "expected_impact": 0.7,
            },
            RecommendationType.ANALYST_REVIEW: {
                "priority": RecommendationPriority.MEDIUM,
                "description": "Schedule immediate analyst review",
                "expected_impact": 0.6,
            },
            RecommendationType.ENTITY_BLOCK: {
                "priority": RecommendationPriority.HIGH,
                "description": "Block entity from all transactions",
                "expected_impact": 0.85,
            },
            RecommendationType.TRANSACTION_LIMIT: {
                "priority": RecommendationPriority.MEDIUM,
                "description": "Implement daily transaction limits",
                "expected_impact": 0.5,
            },
            RecommendationType.DEVICE_RESTRICTION: {
                "priority": RecommendationPriority.MEDIUM,
                "description": "Restrict access to known devices only",
                "expected_impact": 0.55,
            },
            RecommendationType.KYC_ENHANCEMENT: {
                "priority": RecommendationPriority.LOW,
                "description": "Require enhanced KYC verification",
                "expected_impact": 0.65,
            },
            RecommendationType.ALERT_CREATION: {
                "priority": RecommendationPriority.HIGH,
                "description": "Create high-priority alert for investigation",
                "expected_impact": 0.4,
            },
        }
    
    def generate_recommendation(
        self,
        entity_id: str,
        risk_score: float,
        risk_factors: List[str] = None,
        context: Dict[str, Any] = None,
    ) -> PreventiveRecommendation:
        """Generate a prevention recommendation for an entity.
        
        Args:
            entity_id: Target entity
            risk_score: Current risk score
            risk_factors: Contributing risk factors
            context: Additional context
            
        Returns:
            PreventiveRecommendation with suggested action
        """
        # Determine recommendation type based on risk
        if risk_score >= 0.85:
            rec_type = RecommendationType.ACCOUNT_FREEZE
        elif risk_score >= 0.7:
            rec_type = RecommendationType.ENHANCED_MONITORING
        elif risk_score >= 0.5:
            rec_type = RecommendationType.ANALYST_REVIEW
        else:
            rec_type = RecommendationType.ALERT_CREATION
        
        # Get template
        template = self._templates.get(rec_type, {})
        
        # Adjust priority based on risk
        if risk_score >= 0.9:
            priority = RecommendationPriority.CRITICAL
        elif risk_score >= 0.7:
            priority = RecommendationPriority.HIGH
        elif risk_score >= 0.5:
            priority = RecommendationPriority.MEDIUM
        else:
            priority = RecommendationPriority.LOW
        
        # Generate description
        description = template.get("description", "Standard monitoring")
        if context:
            description = f"{description} (Context: {context.get('reason', 'high risk')})"
        
        recommendation = PreventiveRecommendation(
            entity_id=entity_id,
            recommendation_type=rec_type,
            priority=priority,
            description=description,
            expected_impact=template.get("expected_impact", 0.5),
            metadata={
                "risk_score": risk_score,
                "risk_factors": risk_factors or [],
                "context": context or {},
            },
        )
        
        # Store recommendation
        self._store.store_recommendation(recommendation)
        
        logger.info(f"Generated recommendation {recommendation.recommendation_id} for {entity_id}")
        return recommendation
    
    def generate_batch_recommendations(
        self,
        entity_scores: List[Dict[str, Any]],
    ) -> List[PreventiveRecommendation]:
        """Generate recommendations for multiple entities.
        
        Args:
            entity_scores: List of dicts with entity_id and risk_score
            
        Returns:
            List of PreventiveRecommendation
        """
        recommendations = []
        
        for item in entity_scores:
            entity_id = item.get("entity_id")
            risk_score = item.get("risk_score", 0.0)
            risk_factors = item.get("risk_factors", [])
            context = item.get("context", {})
            
            if entity_id:
                rec = self.generate_recommendation(
                    entity_id=entity_id,
                    risk_score=risk_score,
                    risk_factors=risk_factors,
                    context=context,
                )
                recommendations.append(rec)
        
        return recommendations
    
    def recommend_account_freeze(
        self,
        entity_id: str,
        reason: str = "High risk score",
    ) -> PreventiveRecommendation:
        """Generate an account freeze recommendation."""
        recommendation = PreventiveRecommendation(
            entity_id=entity_id,
            recommendation_type=RecommendationType.ACCOUNT_FREEZE,
            priority=RecommendationPriority.CRITICAL,
            description=f"URGENT: Freeze account immediately. Reason: {reason}",
            expected_impact=0.9,
            metadata={"reason": reason},
        )
        
        self._store.store_recommendation(recommendation)
        return recommendation
    
    def recommend_enhanced_monitoring(
        self,
        entity_id: str,
        duration_hours: int = 72,
    ) -> PreventiveRecommendation:
        """Generate an enhanced monitoring recommendation."""
        recommendation = PreventiveRecommendation(
            entity_id=entity_id,
            recommendation_type=RecommendationType.ENHANCED_MONITORING,
            priority=RecommendationPriority.HIGH,
            description=f"Enable enhanced monitoring for {duration_hours} hours",
            expected_impact=0.7,
            metadata={"duration_hours": duration_hours},
        )
        
        self._store.store_recommendation(recommendation)
        return recommendation
    
    def recommend_analyst_review(
        self,
        entity_id: str,
        urgency: str = "HIGH",
    ) -> PreventiveRecommendation:
        """Generate an analyst review recommendation."""
        priority = (
            RecommendationPriority.CRITICAL if urgency == "CRITICAL"
            else RecommendationPriority.HIGH if urgency == "HIGH"
            else RecommendationPriority.MEDIUM
        )
        
        recommendation = PreventiveRecommendation(
            entity_id=entity_id,
            recommendation_type=RecommendationType.ANALYST_REVIEW,
            priority=priority,
            description=f"Schedule {urgency} priority analyst review",
            expected_impact=0.6,
            metadata={"urgency": urgency},
        )
        
        self._store.store_recommendation(recommendation)
        return recommendation
    
    def get_entity_recommendations(self, entity_id: str) -> List[PreventiveRecommendation]:
        """Get all recommendations for an entity."""
        return self._store.get_entity_recommendations(entity_id)
    
    def get_high_priority_recommendations(
        self,
        threshold: RecommendationPriority = RecommendationPriority.HIGH,
    ) -> List[PreventiveRecommendation]:
        """Get high priority recommendations."""
        return self._store.get_high_priority_recommendations(threshold)
    
    def get_critical_recommendations(self) -> List[PreventiveRecommendation]:
        """Get all critical recommendations."""
        return self._store.get_high_priority_recommendations(RecommendationPriority.CRITICAL)
    
    def acknowledge_recommendation(self, recommendation_id: str) -> bool:
        """Mark a recommendation as acknowledged."""
        recommendation = self._store.get_recommendation(recommendation_id)
        if recommendation:
            recommendation.metadata["acknowledged"] = True
            recommendation.metadata["acknowledged_at"] = str(random.randint(1, 999999))
            self._store.store_recommendation(recommendation)
            return True
        return False


# Global singleton
_recommendation_engine: Optional[RecommendationEngine] = None
_recommendation_engine_lock = Lock()


def get_recommendation_engine(store: Optional[PredictiveStore] = None) -> RecommendationEngine:
    """Get or create the singleton RecommendationEngine instance."""
    global _recommendation_engine
    
    with _recommendation_engine_lock:
        if _recommendation_engine is None:
            _recommendation_engine = RecommendationEngine(store=store)
        return _recommendation_engine