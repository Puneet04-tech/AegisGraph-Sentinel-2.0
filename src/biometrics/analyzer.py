"""
Behavioral Biometrics Analyzer.

Analyzes keystroke dynamics, mouse patterns, and behavioral profiles.
"""

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
        self._keystroke_counts: Dict[str, int] = {}
        self._mouse_counts: Dict[str, int] = {}
    
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
            "avg_press_duration": 0.0,
            "avg_release_duration": 0.0,
            "avg_flight_time": 0.0,
            "avg_digraph": 0.0,
        }
    
    def _generate_mouse_baseline(self) -> Dict[str, float]:
        return {
            "avg_velocity": 0.0,
            "avg_acceleration": 0.0,
            "avg_curvature": 0.0,
            "avg_click_duration": 0.0,
        }
    
    @staticmethod
    def _running_average(current: Dict[str, float], sample: Dict[str, float], count: int) -> Dict[str, float]:
        """Incorporate a sample into a running average baseline."""
        prev_count = count - 1
        return {
            key: ((current.get(key, 0.0) * prev_count) + value) / count
            for key, value in sample.items()
        }
    
    @staticmethod
    def _match_score(baseline: Dict[str, float], presented: Dict[str, float]) -> float:
        """Deterministic relative-error match score between a baseline and a presented sample.

        Returns a value in [0, 1] where 1.0 means the presented values are identical
        to the stored baseline and 0.0 means they differ by more than 100%.
        """
        errors = []
        for key, expected in baseline.items():
            if key not in presented:
                continue
            actual = presented[key]
            if expected <= 0:
                errors.append(0.0 if abs(actual) <= 1e-9 else 1.0)
            else:
                errors.append(min(abs(actual - expected) / expected, 1.0))
        if not errors:
            return 0.0
        return max(0.0, 1.0 - (sum(errors) / len(errors)))
    
    def record_keystroke(self, user_id: str, sample: KeystrokeSample) -> None:
        """Record keystroke sample and update the user's running baseline."""
        profile = self._profiles.get(user_id)
        if profile is None:
            profile = self.create_profile(user_id)
        count = self._keystroke_counts.get(user_id, 0) + 1
        baseline = profile.keystroke_profile or self._generate_keystroke_baseline()
        profile.keystroke_profile = self._running_average(
            baseline,
            {
                "avg_press_duration": sample.key_press_duration,
                "avg_release_duration": sample.key_release_duration,
                "avg_flight_time": sample.flight_time,
                "avg_digraph": sample.digraph_duration,
            },
            count,
        )
        profile.updated_at = datetime.now(timezone.utc)
        self._keystroke_counts[user_id] = count
    
    def record_mouse(self, user_id: str, sample: MouseDynamicsSample) -> None:
        """Record mouse dynamics sample and update the user's running baseline."""
        profile = self._profiles.get(user_id)
        if profile is None:
            profile = self.create_profile(user_id)
        count = self._mouse_counts.get(user_id, 0) + 1
        baseline = profile.mouse_profile or self._generate_mouse_baseline()
        profile.mouse_profile = self._running_average(
            baseline,
            {
                "avg_velocity": sample.velocity,
                "avg_acceleration": sample.acceleration,
                "avg_curvature": sample.curvature,
                "avg_click_duration": sample.click_duration,
            },
            count,
        )
        profile.updated_at = datetime.now(timezone.utc)
        self._mouse_counts[user_id] = count
    
    def verify_identity(
        self,
        user_id: str,
        biometric_type: BiometricType,
        sample: Optional[object] = None,
    ) -> VerificationResult:
        """Verify user identity against their recorded behavioral baseline.

        Args:
            user_id: User whose identity is being verified.
            biometric_type: Type of biometric evidence to compare.
            sample: Optional presented sample. When provided, the match score is
                computed deterministically against the recorded baseline. When
                omitted, the profile's stored authenticity score is used.

        Returns:
            VerificationResult with a deterministic, data-derived match score.
        """
        threshold = 0.75
        profile = self._profiles.get(user_id)
        if profile is None:
            return VerificationResult(
                user_id=user_id,
                biometric_type=biometric_type,
                match_score=0.0,
                threshold=threshold,
                verified=False,
            )

        if biometric_type == BiometricType.KEYSTROKE:
            if self._keystroke_counts.get(user_id, 0) == 0:
                return VerificationResult(
                    user_id=user_id,
                    biometric_type=biometric_type,
                    match_score=0.0,
                    threshold=threshold,
                    verified=False,
                )
            if isinstance(sample, KeystrokeSample):
                match_score = self._match_score(
                    profile.keystroke_profile,
                    {
                        "avg_press_duration": sample.key_press_duration,
                        "avg_release_duration": sample.key_release_duration,
                        "avg_flight_time": sample.flight_time,
                        "avg_digraph": sample.digraph_duration,
                    },
                )
            else:
                match_score = profile.authenticity_score
        elif biometric_type == BiometricType.MOUSE_DYNAMICS:
            if self._mouse_counts.get(user_id, 0) == 0:
                return VerificationResult(
                    user_id=user_id,
                    biometric_type=biometric_type,
                    match_score=0.0,
                    threshold=threshold,
                    verified=False,
                )
            if isinstance(sample, MouseDynamicsSample):
                match_score = self._match_score(
                    profile.mouse_profile,
                    {
                        "avg_velocity": sample.velocity,
                        "avg_acceleration": sample.acceleration,
                        "avg_curvature": sample.curvature,
                        "avg_click_duration": sample.click_duration,
                    },
                )
            else:
                match_score = profile.authenticity_score
        else:
            match_score = profile.authenticity_score

        match_score = max(0.0, min(1.0, match_score))
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