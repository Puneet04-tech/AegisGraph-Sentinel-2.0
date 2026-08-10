"""
Advanced Analytics Module.

Provides trend analysis, correlation analysis, segmentation, and cohort analysis.
"""

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

    #: Lags tested for seasonality, in samples. Covers weekly, fortnightly,
    #: monthly and quarterly cycles in daily data.
    SEASONAL_LAGS = (7, 14, 30, 90)

    #: Autocorrelation at a candidate lag above which a series is treated as
    #: seasonal.
    SEASONALITY_THRESHOLD = 0.5

    #: A lag is only tested when the series holds at least this many full
    #: cycles; one repetition is not evidence of a cycle.
    MIN_CYCLES = 2

    #: p-value at or above which a correlation is not treated as significant.
    SIGNIFICANCE_ALPHA = 0.05

    #: Entity keys read as a risk score when summarising a segment.
    RISK_SCORE_KEYS = ("risk_score", "risk", "score")

    #: Entity keys read as transaction volume.
    VOLUME_KEYS = ("transaction_volume", "volume", "amount", "total_amount")

    #: Entity keys read as a confirmed fraud flag.
    FRAUD_KEYS = ("is_fraud", "fraud", "confirmed_fraud")

    #: Risk score bands used for a segment's risk distribution.
    CRITICAL_RISK = 0.8
    HIGH_RISK = 0.6
    MEDIUM_RISK = 0.4

    #: Attribute values listed as a segment's top characteristics.
    TOP_CHARACTERISTIC_COUNT = 5

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
            # Measured by autocorrelation at candidate lags. This used to be
            # random.choice([True, False]) -- a coin flip reported as a
            # property of the data.
            seasonality_detected=self._detect_seasonality(data_points),
            anomaly_detected=len(anomaly_points) > 0,
            anomaly_points=anomaly_points,
        )
        
        self._store.store_trend(analysis)
        return analysis
    
    def _detect_seasonality(self, data_points: List[float]) -> bool:
        """Whether the series repeats at any candidate lag.

        Uses the autocorrelation of the series against itself shifted by each
        lag. A lag is only considered when the series covers at least
        ``MIN_CYCLES`` full periods.
        """
        n = len(data_points)
        for lag in self.SEASONAL_LAGS:
            if n < lag * self.MIN_CYCLES:
                continue
            if self._autocorrelation(data_points, lag) >= self.SEASONALITY_THRESHOLD:
                return True
        return False

    @staticmethod
    def _autocorrelation(data_points: List[float], lag: int) -> float:
        """Autocorrelation of a series at a given lag."""
        n = len(data_points)
        mean_value = sum(data_points) / n

        variance = sum((y - mean_value) ** 2 for y in data_points)
        if variance == 0:
            # A constant series has no cycle to find.
            return 0.0

        covariance = sum(
            (data_points[i] - mean_value) * (data_points[i + lag] - mean_value)
            for i in range(n - lag)
        )
        return covariance / variance

    @staticmethod
    def _correlation_p_value(correlation: float, n: int) -> float:
        """Two-tailed p-value for a Pearson correlation.

        Returns 1.0 when the test is undefined -- fewer than three points, or
        a perfect correlation where the t statistic diverges -- rather than a
        small number that would read as significant.
        """
        degrees_of_freedom = n - 2
        if degrees_of_freedom < 1:
            return 1.0

        r_squared = min(1.0, correlation ** 2)
        if r_squared >= 1.0:
            # Perfect correlation: significant for any usable sample size.
            return 0.0

        t_statistic = abs(correlation) * math.sqrt(
            degrees_of_freedom / (1 - r_squared)
        )

        from scipy import stats

        return float(2 * stats.t.sf(t_statistic, degrees_of_freedom))

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
        
        # Two-tailed p-value for the correlation, from the t statistic
        # t = r * sqrt(n - 2) / sqrt(1 - r^2) on n - 2 degrees of freedom.
        #
        # This used to be random.uniform(0.001, 0.05) -- always below 0.05, so
        # every correlation this module produced was "statistically
        # significant", including a correlation of 0.0 between two unrelated
        # variables.
        p_value = self._correlation_p_value(correlation, n)

        # Determine significance. This graded purely on the size of the
        # coefficient, so a correlation of 0.9 measured over four points --
        # which the t-test does not distinguish from chance -- was reported
        # as HIGH significance. A result that fails the test is LOW however
        # large the coefficient.
        if p_value >= self.SIGNIFICANCE_ALPHA:
            significance = "LOW"
        elif abs(correlation) >= 0.7:
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
        population_size: Optional[int] = None,
    ) -> SegmentAnalysis:
        """Perform entity segmentation.

        Args:
            entities: List of entities with features
            segment_definition: Segmentation criteria
            population_size: Size of the population this segment was drawn
                from, used to compute the segment's share. May also be given
                as ``population_size`` inside ``segment_definition``. Without
                it the percentage is not reported rather than invented.

        Returns:
            SegmentAnalysis
        """
        logger.info(f"Segmenting {len(entities)} entities")

        segment_name = segment_definition.get("name", "Custom Segment")

        # Every figure below used to be a random draw, and `entities` was read
        # only for its length. The risk distribution in particular summed to
        # somewhere between 260 and 760 regardless of how many entities were
        # actually segmented.
        size = len(entities)

        # Share of the wider population this segment represents. Needs a
        # population size to be meaningful; without one it is not reported.
        population_size = (
            population_size
            if population_size is not None
            else segment_definition.get("population_size")
        )
        percentage = (
            round(100 * size / population_size, 2)
            if population_size else None
        )

        metrics = self._segment_metrics(entities)
        risk_distribution = self._risk_distribution(entities)
        top_characteristics = self._top_characteristics(entities)

        segment = SegmentAnalysis(
            segment_name=segment_name,
            segment_definition=segment_definition,
            size=size,
            percentage=percentage,
            metrics=metrics,
            risk_distribution=risk_distribution,
            top_characteristics=top_characteristics,
        )
        
        self._store.store_segment(segment)
        return segment
    
    def _segment_metrics(self, entities: List[Dict[str, Any]]) -> Dict[str, float]:
        """Average the segment's numeric attributes.

        Reads the entities themselves rather than reporting invented averages.
        A metric no entity carries is absent, not zero.
        """
        metrics: Dict[str, float] = {}
        if not entities:
            return metrics

        risk_scores = self._numeric_field(entities, self.RISK_SCORE_KEYS)
        if risk_scores:
            metrics["avg_risk_score"] = round(sum(risk_scores) / len(risk_scores), 4)

        volumes = self._numeric_field(entities, self.VOLUME_KEYS)
        if volumes:
            metrics["avg_transaction_volume"] = round(sum(volumes) / len(volumes), 2)

        fraud_flags = [
            bool(entity[key])
            for entity in entities
            for key in self.FRAUD_KEYS
            if key in entity
        ]
        if fraud_flags:
            metrics["fraud_rate"] = round(
                sum(fraud_flags) / len(fraud_flags), 4,
            )

        return metrics

    def _risk_distribution(self, entities: List[Dict[str, Any]]) -> Dict[str, int]:
        """Bucket the segment's entities by risk score.

        The counts previously came from four independent ``random.randint``
        calls, so they summed to somewhere between 260 and 760 whatever the
        segment size. These sum to the number of entities carrying a score.
        """
        distribution = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        for entity in entities:
            score = self._first_numeric(entity, self.RISK_SCORE_KEYS)
            if score is None:
                continue
            if score >= self.CRITICAL_RISK:
                distribution["critical"] += 1
            elif score >= self.HIGH_RISK:
                distribution["high"] += 1
            elif score >= self.MEDIUM_RISK:
                distribution["medium"] += 1
            else:
                distribution["low"] += 1

        return distribution

    def _top_characteristics(self, entities: List[Dict[str, Any]]) -> List[str]:
        """Most common attribute values across the segment.

        Previously five strings of the form "Characteristic 3: High Risk" with
        the label chosen at random -- they described nothing.
        """
        if not entities:
            return []

        counts: Dict[tuple, int] = {}
        for entity in entities:
            for key, value in entity.items():
                if isinstance(value, (dict, list)):
                    continue
                counts[(key, str(value))] = counts.get((key, str(value)), 0) + 1

        ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
        total = len(entities)

        return [
            f"{key}={value} ({100 * count / total:.0f}% of segment)"
            for (key, value), count in ranked[:self.TOP_CHARACTERISTIC_COUNT]
            if count > 1 or total == 1
        ]

    @staticmethod
    def _first_numeric(entity: Dict[str, Any], keys: tuple) -> Optional[float]:
        """First numeric value on an entity under any of the given keys."""
        for key in keys:
            value = entity.get(key)
            if isinstance(value, bool):
                continue
            if isinstance(value, (int, float)):
                return float(value)
        return None

    def _numeric_field(
        self,
        entities: List[Dict[str, Any]],
        keys: tuple,
    ) -> List[float]:
        """Numeric values across entities under any of the given keys."""
        values = []
        for entity in entities:
            value = self._first_numeric(entity, keys)
            if value is not None:
                values.append(value)
        return values

    @staticmethod
    def _retention_rates(active_counts: Optional[List[int]]) -> List[float]:
        """Retention per period as a share of the cohort's initial size."""
        if not active_counts or not active_counts[0]:
            return []

        initial = active_counts[0]
        return [round(100 * count / initial, 2) for count in active_counts]

    def perform_cohort_analysis(
        self,
        cohort_name: str,
        cohort_definition: Dict[str, Any],
        retention_periods: int = 12,
        active_counts: Optional[List[int]] = None,
    ) -> CohortAnalysis:
        """Perform cohort retention analysis.

        Args:
            cohort_name: Name of the cohort
            cohort_definition: Cohort definition
            retention_periods: Number of retention periods
            active_counts: Members still active at the start of each period,
                beginning with the cohort's initial size. Retention is
                measured against ``active_counts[0]``.

        Returns:
            CohortAnalysis
        """
        logger.info(f"Performing cohort analysis for {cohort_name}")

        # Retention used to be manufactured: starting at 100% and subtracting
        # random.uniform(2, 10) each period produced a plausible-looking decay
        # curve for a cohort nobody had observed. No caller ever supplied
        # observations, because there was no parameter to supply them through.
        retention_rates = self._retention_rates(active_counts)

        if not retention_rates:
            logger.warning(
                "No retention observations supplied for cohort '%s'; "
                "retention is unavailable", cohort_name,
            )
            average_retention = None
            churn_rate = None
        else:
            average_retention = round(
                sum(retention_rates) / len(retention_rates), 2,
            )
            churn_rate = round(100 - average_retention, 2)

        cohort = CohortAnalysis(
            cohort_name=cohort_name,
            cohort_definition=cohort_definition,
            retention_rates=retention_rates,
            period_count=len(retention_rates) or retention_periods,
            average_retention=average_retention,
            churn_rate=churn_rate,
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