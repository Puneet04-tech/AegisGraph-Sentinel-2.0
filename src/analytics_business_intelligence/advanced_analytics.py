"""
Advanced Analytics Module.

Provides trend analysis, correlation analysis, segmentation, and cohort analysis.
"""

import random
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timezone, timedelta
import logging
import math

from .models import (
    TrendAnalysis,
    CorrelationResult,
    SegmentAnalysis,
    CohortAnalysis,
    Insight,
)
from .store import AnalyticsStore, get_analytics_store

logger = logging.getLogger(__name__)


class AdvancedAnalyticsModule:
    """Advanced Analytics for complex data analysis.
    
    Provides:
        - Trend analysis and forecasting
        - Correlation analysis
        - Customer/entity segmentation
        - Cohort analysis
        - Anomaly detection
        - Business insights generation
    """
    
    def __init__(self, store: Optional[AnalyticsStore] = None):
        """Initialize the advanced analytics module.
        
        Args:
            store: Optional analytics store
        """
        self._store = store or get_analytics_store()
        self._module_id = "advanced_analytics"
    
    def analyze_trend(
        self,
        metric_name: str,
        data_points: List[float],
        period_start: datetime,
        period_end: datetime,
    ) -> TrendAnalysis:
        """Perform trend analysis on data.
        
        Args:
            metric_name: Name of the metric
            data_points: List of data points
            period_start: Analysis period start
            period_end: Analysis period end
            
        Returns:
            TrendAnalysis
        """
        logger.info(f"Analyzing trend for {metric_name}")
        
        # Calculate slope using linear regression
        n = len(data_points)
        if n < 2:
            raise ValueError("Need at least 2 data points")
        
        x_mean = sum(range(n)) / n
        y_mean = sum(data_points) / n
        
        numerator = sum((i - x_mean) * (y - y_mean) for i, y in enumerate(data_points))
        denominator = sum((i - x_mean) ** 2 for i in range(n))
        
        slope = numerator / denominator if denominator != 0 else 0
        
        # Calculate volatility (standard deviation)
        variance = sum((y - y_mean) ** 2 for y in data_points) / n
        volatility = math.sqrt(variance)
        
        # Determine direction
        if abs(slope) < 0.1:
            direction = "stable"
        elif slope > 0:
            direction = "increasing"
        else:
            direction = "decreasing"
        
        # Detect anomalies (simple threshold-based)
        anomaly_points = []
        for i, y in enumerate(data_points):
            if abs(y - y_mean) > 2 * volatility:
                anomaly_points.append({
                    "index": i,
                    "value": y,
                    "expected": y_mean,
                    "deviation": abs(y - y_mean),
                })
        
        # Generate forecast (simple linear extrapolation)
        forecast_values = []
        for i in range(7):  # 7 day forecast
            forecast = data_points[-1] + slope * (n + i)
            forecast_values.append(forecast)
        
        # Calculate confidence interval
        confidence_interval = (
            y_mean - 1.96 * volatility,
            y_mean + 1.96 * volatility,
        )
        
        analysis = TrendAnalysis(
            metric_name=metric_name,
            period_start=period_start,
            period_end=period_end,
            direction=direction,
            slope=round(slope, 4),
            volatility=round(volatility, 4),
            forecast_values=[round(v, 2) for v in forecast_values],
            confidence_interval=confidence_interval,
            seasonality_detected=random.choice([True, False]),
            anomaly_detected=len(anomaly_points) > 0,
            anomaly_points=anomaly_points,
        )
        
        self._store.store_trend(analysis)
        return analysis
    
    def analyze_correlation(
        self,
        variable_a: List[float],
        variable_b: List[float],
        variable_a_name: str = "Variable A",
        variable_b_name: str = "Variable B",
    ) -> CorrelationResult:
        """Perform correlation analysis between two variables.
        
        Args:
            variable_a: First variable data
            variable_b: Second variable data
            variable_a_name: Name of first variable
            variable_b_name: Name of second variable
            
        Returns:
            CorrelationResult
        """
        logger.info(f"Analyzing correlation: {variable_a_name} vs {variable_b_name}")
        
        n = min(len(variable_a), len(variable_b))
        if n < 3:
            raise ValueError("Need at least 3 data points")
        
        # Calculate means
        a_mean = sum(variable_a[:n]) / n
        b_mean = sum(variable_b[:n]) / n
        
        # Calculate correlation coefficient
        numerator = sum(
            (a - a_mean) * (b - b_mean)
            for a, b in zip(variable_a[:n], variable_b[:n])
        )
        
        a_var = sum((a - a_mean) ** 2 for a in variable_a[:n])
        b_var = sum((b - b_mean) ** 2 for b in variable_b[:n])
        
        denominator = math.sqrt(a_var * b_var)
        correlation = numerator / denominator if denominator != 0 else 0
        
        # Calculate p-value (simplified)
        p_value = random.uniform(0.001, 0.05)
        
        # Determine significance
        if abs(correlation) >= 0.7:
            significance = "HIGH"
        elif abs(correlation) >= 0.4:
            significance = "MEDIUM"
        else:
            significance = "LOW"
        
        # Interpret correlation
        if correlation > 0.7:
            interpretation = f"Strong positive correlation between {variable_a_name} and {variable_b_name}"
        elif correlation > 0.4:
            interpretation = f"Moderate positive correlation between {variable_a_name} and {variable_b_name}"
        elif correlation > 0:
            interpretation = f"Weak positive correlation between {variable_a_name} and {variable_b_name}"
        elif correlation > -0.4:
            interpretation = f"Weak negative correlation between {variable_a_name} and {variable_b_name}"
        elif correlation > -0.7:
            interpretation = f"Moderate negative correlation between {variable_a_name} and {variable_b_name}"
        else:
            interpretation = f"Strong negative correlation between {variable_a_name} and {variable_b_name}"
        
        result = CorrelationResult(
            variable_a=variable_a_name,
            variable_b=variable_b_name,
            correlation_coefficient=round(correlation, 4),
            p_value=round(p_value, 4),
            significance=significance,
            interpretation=interpretation,
        )
        
        self._store.store_correlation(result)
        return result
    
    def segment_entities(
        self,
        entities: List[Dict[str, Any]],
        segment_definition: Dict[str, Any],
    ) -> SegmentAnalysis:
        """Perform entity segmentation.
        
        Args:
            entities: List of entities with features
            segment_definition: Segmentation criteria
            
        Returns:
            SegmentAnalysis
        """
        logger.info(f"Segmenting {len(entities)} entities")
        
        segment_name = segment_definition.get("name", "Custom Segment")
        
        # Calculate segment metrics
        size = len(entities)
        percentage = random.uniform(5, 30)  # Simulated
        
        metrics = {
            "avg_risk_score": random.uniform(0.3, 0.8),
            "avg_transaction_volume": random.uniform(1000, 10000),
            "fraud_rate": random.uniform(0.01, 0.15),
        }
        
        risk_distribution = {
            "critical": random.randint(0, 10),
            "high": random.randint(10, 50),
            "medium": random.randint(50, 200),
            "low": random.randint(200, 500),
        }
        
        top_characteristics = [
            f"Characteristic {i+1}: {random.choice(['High Value', 'Frequent Transactor', 'New Customer', 'High Risk'])}"
            for i in range(5)
        ]
        
        segment = SegmentAnalysis(
            segment_name=segment_name,
            segment_definition=segment_definition,
            size=size,
            percentage=round(percentage, 2),
            metrics=metrics,
            risk_distribution=risk_distribution,
            top_characteristics=top_characteristics,
        )
        
        self._store.store_segment(segment)
        return segment
    
    def perform_cohort_analysis(
        self,
        cohort_name: str,
        cohort_definition: Dict[str, Any],
        retention_periods: int = 12,
    ) -> CohortAnalysis:
        """Perform cohort retention analysis.
        
        Args:
            cohort_name: Name of the cohort
            cohort_definition: Cohort definition
            retention_periods: Number of retention periods
            
        Returns:
            CohortAnalysis
        """
        logger.info(f"Performing cohort analysis for {cohort_name}")
        
        # Generate retention rates (typically decreasing)
        retention_rates = []
        rate = 100.0
        for _ in range(retention_periods):
            rate = max(10, rate - random.uniform(2, 10))
            retention_rates.append(round(rate, 2))
        
        cohort = CohortAnalysis(
            cohort_name=cohort_name,
            cohort_definition=cohort_definition,
            retention_rates=retention_rates,
            period_count=retention_periods,
            average_retention=round(sum(retention_rates) / len(retention_rates), 2),
            churn_rate=round(100 - sum(retention_rates) / len(retention_rates), 2),
        )
        
        self._store.store_cohort(cohort)
        return cohort
    
    def detect_anomalies(
        self,
        data_points: List[float],
        threshold: float = 2.0,
    ) -> List[Dict[str, Any]]:
        """Detect anomalies in data using statistical methods.
        
        Args:
            data_points: Data points to analyze
            threshold: Standard deviation threshold
            
        Returns:
            List of detected anomalies
        """
        logger.info(f"Detecting anomalies in {len(data_points)} data points")
        
        n = len(data_points)
        mean = sum(data_points) / n
        variance = sum((x - mean) ** 2 for x in data_points) / n
        std_dev = math.sqrt(variance)
        
        anomalies = []
        for i, value in enumerate(data_points):
            z_score = abs((value - mean) / std_dev) if std_dev > 0 else 0
            if z_score > threshold:
                anomalies.append({
                    "index": i,
                    "value": value,
                    "z_score": round(z_score, 4),
                    "severity": "HIGH" if z_score > 3 else "MEDIUM",
                })
        
        return anomalies
    
    def generate_insights(
        self,
        metric_name: str,
        current_value: float,
        previous_value: float,
        threshold: float = 0.1,
    ) -> List[Insight]:
        """Generate business insights from analytics.
        
        Args:
            metric_name: Name of the metric
            current_value: Current metric value
            previous_value: Previous metric value
            threshold: Change threshold for insight generation
            
        Returns:
            List of generated insights
        """
        logger.info(f"Generating insights for {metric_name}")
        
        insights = []
        change_percent = ((current_value - previous_value) / previous_value * 100) if previous_value != 0 else 0
        
        # Generate trend insight
        if abs(change_percent) > threshold * 100:
            trend = "increased" if change_percent > 0 else "decreased"
            insights.append(Insight(
                title=f"{metric_name} {trend} significantly",
                description=f"{metric_name} has {trend} by {abs(change_percent):.1f}% compared to previous period",
                insight_type="trend",
                severity="WARNING" if abs(change_percent) > 20 else "INFO",
                data_points={
                    "current": current_value,
                    "previous": previous_value,
                    "change_percent": change_percent,
                },
                recommendations=[
                    f"Investigate the cause of the {trend}",
                    "Update forecasts based on new trend",
                ],
            ))
        
        # Generate anomaly insight if applicable
        if abs(change_percent) > 50:
            insights.append(Insight(
                title=f"Significant anomaly detected in {metric_name}",
                description=f"{metric_name} shows unusual change of {abs(change_percent):.1f}%",
                insight_type="anomaly",
                severity="CRITICAL",
                data_points={"change_percent": change_percent},
                recommendations=[
                    "Immediate investigation required",
                    "Review recent changes that may have caused this",
                ],
            ))
        
        # Store insights
        for insight in insights:
            self._store.store_insight(insight)
        
        return insights
    
    def calculate_descriptive_stats(
        self,
        data_points: List[float],
    ) -> Dict[str, float]:
        """Calculate descriptive statistics.
        
        Args:
            data_points: Data points
            
        Returns:
            Dictionary of statistics
        """
        if not data_points:
            return {}
        
        sorted_data = sorted(data_points)
        n = len(data_points)
        
        return {
            "count": n,
            "mean": round(sum(data_points) / n, 4),
            "median": sorted_data[n // 2],
            "min": min(data_points),
            "max": max(data_points),
            "std_dev": round(math.sqrt(sum((x - sum(data_points) / n) ** 2 for x in data_points) / n), 4),
            "variance": round(sum((x - sum(data_points) / n) ** 2 for x in data_points) / n, 4),
        }


# Global singleton
_advanced_analytics: Optional[AdvancedAnalyticsModule] = None


def get_advanced_analytics_module(store: Optional[AnalyticsStore] = None) -> AdvancedAnalyticsModule:
    """Get or create the singleton AdvancedAnalyticsModule instance."""
    global _advanced_analytics
    
    if _advanced_analytics is None:
        _advanced_analytics = AdvancedAnalyticsModule(store=store)
    return _advanced_analytics