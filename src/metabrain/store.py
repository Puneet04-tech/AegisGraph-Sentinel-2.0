"""MetaBrain Store - In-memory storage for MetaBrain data"""
from typing import Any, Dict, List, Optional
from datetime import datetime, timedelta
from .models import IntelligenceSignal, StrategicInsight, StrategicRecommendation, Forecast, Strategy

class MetaBrainStore:
    """In-memory store for MetaBrain components"""
    
    def __init__(self) -> None:
        self.signals: Dict[str, IntelligenceSignal] = {}
        self.insights: Dict[str, StrategicInsight] = {}
        self.recommendations: Dict[str, StrategicRecommendation] = {}
        self.forecasts: Dict[str, Forecast] = {}
        self.strategies: Dict[str, Strategy] = {}
        self.created_at: datetime = datetime.utcnow()
    
    def add_signal(self, signal: IntelligenceSignal) -> None:
        """Add an intelligence signal"""
        self.signals[signal.signal_id] = signal
    
    def get_signal(self, signal_id: str) -> Optional[IntelligenceSignal]:
        """Get a signal by ID"""
        return self.signals.get(signal_id)
    
    def get_all_signals(self, limit: int = 100) -> List[IntelligenceSignal]:
        """Get all signals, most recent first"""
        signals = sorted(self.signals.values(), key=lambda s: s.timestamp, reverse=True)
        return signals[:limit]
    
    def get_signals_by_type(self, signal_type: str) -> List[IntelligenceSignal]:
        """Get signals by type"""
        return [s for s in self.signals.values() if s.signal_type.value == signal_type]
    
    def add_insight(self, insight: StrategicInsight) -> None:
        """Add a strategic insight"""
        self.insights[insight.insight_id] = insight
    
    def get_insight(self, insight_id: str) -> Optional[StrategicInsight]:
        """Get an insight by ID"""
        return self.insights.get(insight_id)
    
    def get_all_insights(self) -> List[StrategicInsight]:
        """Get all insights sorted by priority"""
        return sorted(self.insights.values(), key=lambda i: i.priority)
    
    def add_recommendation(self, recommendation: StrategicRecommendation) -> None:
        """Add a recommendation"""
        self.recommendations[recommendation.recommendation_id] = recommendation
    
    def get_recommendation(self, recommendation_id: str) -> Optional[StrategicRecommendation]:
        """Get a recommendation by ID"""
        return self.recommendations.get(recommendation_id)
    
    def get_all_recommendations(self) -> List[StrategicRecommendation]:
        """Get all recommendations"""
        return list(self.recommendations.values())
    
    def add_forecast(self, forecast: Forecast) -> None:
        """Add a forecast"""
        self.forecasts[forecast.forecast_id] = forecast
    
    def get_forecast(self, forecast_id: str) -> Optional[Forecast]:
        """Get a forecast by ID"""
        return self.forecasts.get(forecast_id)
    
    def get_all_forecasts(self) -> List[Forecast]:
        """Get all forecasts"""
        return list(self.forecasts.values())
    
    def add_strategy(self, strategy: Strategy) -> None:
        """Add a strategy"""
        self.strategies[strategy.strategy_id] = strategy
    
    def get_strategy(self, strategy_id: str) -> Optional[Strategy]:
        """Get a strategy by ID"""
        return self.strategies.get(strategy_id)
    
    def get_all_strategies(self) -> List[Strategy]:
        """Get all strategies"""
        return list(self.strategies.values())
    
    def get_dashboard_data(self) -> Dict[str, Any]:
        """Get dashboard data summary"""
        return {
            "total_signals": len(self.signals),
            "total_insights": len(self.insights),
            "total_recommendations": len(self.recommendations),
            "total_forecasts": len(self.forecasts),
            "total_strategies": len(self.strategies),
            "created_at": self.created_at.isoformat()
        }
    
    def clear_old_data(self, days: int = 30) -> None:
        """Clear data older than specified days"""
        cutoff = datetime.utcnow() - timedelta(days=days)
        self.signals = {
            k: v for k, v in self.signals.items()
            if v.timestamp > cutoff
        }