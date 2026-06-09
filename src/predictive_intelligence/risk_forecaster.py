"""
Risk Forecaster Module.

This module provides the RiskForecaster class for entity risk prediction.
The main implementation is in forecasting.py - this file provides re-exports.
"""

from .forecasting import RiskForecaster, get_risk_forecaster

__all__ = ["RiskForecaster", "get_risk_forecaster"]