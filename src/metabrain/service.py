"""MetaBrain Service - Main API Service"""
from typing import Any, Dict, List, Optional
from uuid import uuid4
from datetime import datetime
from .models import (
    IntelligenceSignal, StrategicInsight, StrategicRecommendation,
    Forecast, Strategy, AnalysisType, IntelligenceLevel
)
from .store import MetaBrainStore
from .reasoning_engine import ReasoningEngine
from .recommendation_engine import RecommendationEngine
from .planner import Planner

class MetaBrainService:
    """Main MetaBrain service coordinating all components"""
    
    def __init__(self) -> None:
        self.store = MetaBrainStore()
        self.reasoning_engine = ReasoningEngine()
        self.recommendation_engine = RecommendationEngine()
        self.planner = Planner()
    
    def add_signal(
        self,
        signal_type: str,
        source_module: str,
        severity: str,
        description: str,
        confidence: float,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> IntelligenceSignal:
        """Add an intelligence signal"""
        signal = IntelligenceSignal(
            signal_id=str(uuid4()),
            signal_type=AnalysisType(signal_type),
            source_module=source_module,
            severity=severity,
            description=description,
            confidence=confidence,
            tags=tags or [],
            metadata=metadata or {}
        )
        self.store.add_signal(signal)
        self.reasoning_engine.add_signal(signal)
        return signal
    
    def analyze(self) -> Dict[str, Any]:
        """Perform cross-domain analysis"""
        insights = self.reasoning_engine.correlate_signals()
        recommendations = self.recommendation_engine.generate_recommendations(insights)
        
        # Store insights and recommendations
        for insight in insights:
            self.store.add_insight(insight)
        for recommendation in recommendations:
            self.store.add_recommendation(recommendation)
        
        # Get threat landscape
        threat_landscape = self.reasoning_engine.analyze_threat_landscape()
        
        return {
            "insights": [i.to_dict() for i in insights],
            "recommendations": [r.to_dict() for r in recommendations],
            "threat_landscape": threat_landscape,
            "timestamp": datetime.utcnow().isoformat()
        }
    
    def get_recommendations(self, domain: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get recommendations, optionally filtered by domain"""
        if domain:
            recs = self.recommendation_engine.get_recommendations_by_domain(domain)
        else:
            recs = self.store.get_all_recommendations()
        return [r.to_dict() for r in recs]
    
    def create_forecast(
        self,
        forecast_type: str,
        prediction: str,
        timeframe: str,
        confidence: float,
        affected_sectors: List[str]
    ) -> Forecast:
        """Create a security forecast"""
        forecast = Forecast(
            forecast_id=str(uuid4()),
            forecast_type=forecast_type,
            prediction=prediction,
            timeframe=timeframe,
            confidence=confidence,
            affected_sectors=affected_sectors
        )
        self.store.add_forecast(forecast)
        return forecast
    
    def get_forecasts(self) -> List[Dict[str, Any]]:
        """Get all forecasts"""
        return [f.to_dict() for f in self.store.get_all_forecasts()]
    
    def create_strategy(
        self,
        strategy_type: str,
        name: str,
        description: str
    ) -> Strategy:
        """Create a defense strategy"""
        return self.planner.create_strategy(strategy_type, name, description)
    
    def get_strategies(self) -> List[Dict[str, Any]]:
        """Get all strategies"""
        return [s.to_dict() for s in self.planner.get_all_strategies()]
    
    def get_dashboard(self) -> Dict[str, Any]:
        """Get dashboard data"""
        dashboard = self.store.get_dashboard_data()
        dashboard["threat_landscape"] = self.reasoning_engine.analyze_threat_landscape()
        dashboard["recommendation_stats"] = self.recommendation_engine.get_recommendation_stats()
        return dashboard
    
    def get_all_signals(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get all signals"""
        return [s.to_dict() for s in self.store.get_all_signals(limit)]
    
    def get_all_insights(self) -> List[Dict[str, Any]]:
        """Get all insights"""
        return [i.to_dict() for i in self.store.get_all_insights()]


# Global service instance
_metabrain_service: Optional[MetaBrainService] = None

def get_metabrain_service() -> MetaBrainService:
    """Get the global MetaBrain service instance"""
    global _metabrain_service
    if _metabrain_service is None:
        _metabrain_service = MetaBrainService()
    return _metabrain_service