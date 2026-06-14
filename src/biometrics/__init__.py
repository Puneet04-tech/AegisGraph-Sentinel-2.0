"""
Behavioral Biometrics Intelligence Platform.

A production-grade module for keystroke analytics,
mouse dynamics, and behavioral profiling.
"""

from .models import (
    BiometricType,
    BehavioralProfile,
    KeystrokeSample,
    MouseDynamicsSample,
    VerificationResult,
)
from .analyzer import BiometricsAnalyzer, get_biometrics_analyzer

__all__ = [
    "BiometricType",
    "BehavioralProfile",
    "KeystrokeSample",
    "MouseDynamicsSample",
    "VerificationResult",
    "BiometricsAnalyzer",
    "get_biometrics_analyzer",
]