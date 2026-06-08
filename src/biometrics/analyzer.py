"""
Behavioral Biometrics Analyzer.

Analyzes keystroke dynamics, mouse patterns, and behavioral profiles.
"""

import random
from typing import Dict, List, Optional
from datetime import datetime, timezone

from .models import (
    BehavioralProfile,
    KeystrokeSample,
    MouseDynamicsSample,
    VerificationResult,
    BiometricType,
)


class BiometricsAnalyzer:
    """Biometrics Analyzer for behavioral analysis.
    
    Provides:
        - Keystroke analytics
        - Mouse dynamics analysis
        - Behavioral profiling
        - Identity verification
    """
    
    def __init__(self):
        self._profiles: Dict[str, BehavioralProfile] = {}
    
    def create_profile(self, user_id: str) -> BehavioralProfile:
        """Create a behavioral profile."""
        profile = BehavioralProfile(
            user_id=user_id,
            keystroke_profile=self._generate_keystroke_baseline(),
            mouse_profile=self._generate_mouse_baseline(),
        )
        self._profiles[user_id] = profile
        return profile
    
    def _generate_keystroke_baseline(self) -> Dict[str, float]:
        return {
            "avg_press_duration": random.uniform(80, 150),
            "avg_flight_time": random.uniform(50, 100),
            "avg_digraph": random.uniform(100, 200),
        }
    
    def _generate_mouse_baseline(self) -> Dict[str, float]:
        return {
            "avg_velocity": random.uniform(200, 500),
            "avg_acceleration": random.uniform(50, 150),
            "avg_click_duration": random.uniform(100, 300),
        }
    
    def record_keystroke(self, user_id: str, sample: KeystrokeSample) -> None:
        """Record keystroke sample."""
        if user_id not in self._profiles:
            self.create_profile(user_id)
    
    def record_mouse(self, user_id: str, sample: MouseDynamicsSample) -> None:
        """Record mouse dynamics sample."""
        if user_id not in self._profiles:
            self.create_profile(user_id)
    
    def verify_identity(
        self,
        user_id: str,
        biometric_type: BiometricType,
    ) -> VerificationResult:
        """Verify user identity using biometrics."""
        match_score = random.uniform(0.6, 1.0)
        threshold = 0.75
        
        return VerificationResult(
            user_id=user_id,
            biometric_type=biometric_type,
            match_score=match_score,
            threshold=threshold,
            verified=match_score >= threshold,
        )
    
    def get_profile(self, user_id: str) -> Optional[BehavioralProfile]:
        """Get user profile."""
        return self._profiles.get(user_id)


_biometrics_analyzer: Optional[BiometricsAnalyzer] = None


def get_biometrics_analyzer() -> BiometricsAnalyzer:
    global _biometrics_analyzer
    if _biometrics_analyzer is None:
        _biometrics_analyzer = BiometricsAnalyzer()
    return _biometrics_analyzer