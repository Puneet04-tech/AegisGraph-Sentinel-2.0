"""
Behavioral Biometrics Module - Hesitation Monitor

Analyzes keystroke dynamics to detect stress patterns indicating:
- Social engineering attacks
- Victim coercion
- Authentication anomalies

Features extracted:
- Hold time (key press duration)
- Flight time (time between key releases and next press)
- Typing speed (WPM)
- Error rate (backspace frequency)
- Rhythm consistency
"""

import numpy as np
import torch
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass
from scipy.stats import variation


@dataclass
class KeystrokeEvent:
    """Single keystroke event"""
    key_id: str
    press_time: float
    release_time: float
    is_backspace: bool = False


@dataclass
class KeystrokeSequence:
    """Sequence of keystroke events"""
    events: List[KeystrokeEvent]
    session_start: float
    session_end: float


class KeystrokeDynamicsAnalyzer:
    """
    Analyzes keystroke dynamics to extract behavioral biometric features
    
    Based on motor control theory:
    - Stress increases timing variability
    - Stress decreases typing speed
    - Stress increases error rate
    
    Args:
        baseline_wpm: Expected baseline words per minute for user
        baseline_hold_time: Expected baseline hold time in ms
        stress_threshold: Threshold for stress detection (0-1)
    """
    
    def __init__(
        self,
        baseline_wpm: float = 40.0,
        baseline_hold_time: float = 120.0,
        stress_threshold: float = 0.70,
    ):
        self.baseline_wpm = baseline_wpm
        self.baseline_hold_time = baseline_hold_time
        self.stress_threshold = stress_threshold
    
    def extract_features(
        self,
        keystroke_sequence: KeystrokeSequence,
    ) -> Dict[str, float]:
        """
        Extract keystroke dynamics features
        
        Args:
            keystroke_sequence: Sequence of keystroke events
        
        Returns:
            Dictionary of extracted features
        """
        events = keystroke_sequence.events
        
        if len(events) < 2:
            return self._empty_features()
        
        # Extract timing features
        hold_times = [e.release_time - e.press_time for e in events]
        flight_times = [
            events[i+1].press_time - events[i].release_time
            for i in range(len(events) - 1)
        ]
        
        # Compute statistics
        features = {
            # Hold time statistics (ms)
            'hold_time_mean': np.mean(hold_times) * 1000,
            'hold_time_std': np.std(hold_times) * 1000,
            'hold_time_cv': variation(hold_times) if len(hold_times) > 1 else 0.0,
            'hold_time_min': np.min(hold_times) * 1000,
            'hold_time_max': np.max(hold_times) * 1000,
            
            # Flight time statistics (ms)
            'flight_time_mean': np.mean(flight_times) * 1000 if flight_times else 0.0,
            'flight_time_std': np.std(flight_times) * 1000 if flight_times else 0.0,
            'flight_time_cv': variation(flight_times) if len(flight_times) > 1 else 0.0,
            
            # Typing speed
            'wpm': self._compute_wpm(keystroke_sequence),
            'chars_per_second': len(events) / (keystroke_sequence.session_end - keystroke_sequence.session_start),
            
            # Error metrics
            'error_rate': self._compute_error_rate(events),
            'backspace_count': sum(1 for e in events if e.is_backspace),
            'backspace_ratio': sum(1 for e in events if e.is_backspace) / len(events),
            
            # Rhythm consistency
            'rhythm_consistency': self._compute_rhythm_consistency(flight_times),
            
            # Session metadata
            'total_events': len(events),
            'session_duration': keystroke_sequence.session_end - keystroke_sequence.session_start,
        }
        
        return features
    
    def detect_stress(
        self,
        features: Dict[str, float],
        user_baseline: Optional[Dict[str, float]] = None,
    ) -> Dict[str, float]:
        """
        Detect stress indicators from keystroke features
        
        Args:
            features: Extracted keystroke features
            user_baseline: User-specific baseline features (if available)
        
        Returns:
            Dictionary with stress indicators and overall stress score
        """
        # Use provided baseline or default
        if user_baseline is None:
            baseline_wpm = self.baseline_wpm
            baseline_hold_cv = 0.18  # typical CV for relaxed typing
        else:
            baseline_wpm = user_baseline.get('wpm', self.baseline_wpm)
            baseline_hold_cv = user_baseline.get('hold_time_cv', 0.18)
        
        # Stress indicators
        
        # 1. Increased hold time variability
        hold_cv_stress = min(features['hold_time_cv'] / (baseline_hold_cv * 2), 1.0)
        
        # 2. Decreased typing speed
        wpm_ratio = features['wpm'] / baseline_wpm
        wpm_stress = max(1.0 - wpm_ratio, 0.0)  # stress if slower than baseline
        
        # 3. Increased error rate
        error_stress = min(features['error_rate'] * 5, 1.0)  # scale to 0-1
        
        # 4. Decreased rhythm consistency
        rhythm_stress = 1.0 - features['rhythm_consistency']
        
        # 5. Increased flight time variability
        flight_cv_stress = min(features['flight_time_cv'] / 0.5, 1.0)
        
        # Weighted combination
        stress_score = (
            0.30 * hold_cv_stress +
            0.25 * wpm_stress +
            0.20 * error_stress +
            0.15 * rhythm_stress +
            0.10 * flight_cv_stress
        )
        
        return {
            'stress_score': stress_score,
            'is_stressed': stress_score > self.stress_threshold,
            'hold_cv_stress': hold_cv_stress,
            'wpm_stress': wpm_stress,
            'error_stress': error_stress,
            'rhythm_stress': rhythm_stress,
            'flight_cv_stress': flight_cv_stress,
        }
    
    def _compute_wpm(self, sequence: KeystrokeSequence) -> float:
        """
        Compute words per minute (assuming average word length of 5 chars)
        """
        duration_minutes = (sequence.session_end - sequence.session_start) / 60.0
        if duration_minutes == 0:
            return 0.0
        
        # Exclude backspaces from character count
        char_count = sum(1 for e in sequence.events if not e.is_backspace)
        return (char_count / 5.0) / duration_minutes
    
    def _compute_error_rate(self, events: List[KeystrokeEvent]) -> float:
        """
        Compute error rate based on backspace frequency
        """
        if len(events) == 0:
            return 0.0
        backspace_count = sum(1 for e in events if e.is_backspace)
        return backspace_count / len(events)
    
    def _compute_rhythm_consistency(self, flight_times: List[float]) -> float:
        """
        Compute rhythm consistency (inverse of CV)
        Returns value between 0 (inconsistent) and 1 (consistent)
        """
        if len(flight_times) < 2:
            return 0.5
        
        cv = variation(flight_times)
        # Map CV to consistency score (lower CV = higher consistency)
        consistency = 1.0 / (1.0 + cv)
        return consistency
    
    def _empty_features(self) -> Dict[str, float]:
        """Return empty feature dict"""
        return {
            'hold_time_mean': 0.0,
            'hold_time_std': 0.0,
            'hold_time_cv': 0.0,
            'hold_time_min': 0.0,
            'hold_time_max': 0.0,
            'flight_time_mean': 0.0,
            'flight_time_std': 0.0,
            'flight_time_cv': 0.0,
            'wpm': 0.0,
            'chars_per_second': 0.0,
            'error_rate': 0.0,
            'backspace_count': 0,
            'backspace_ratio': 0.0,
            'rhythm_consistency': 0.5,
            'total_events': 0,
            'session_duration': 0.0,
        }


class LightweightBiometricModel:
    """
    Lightweight ML model for stress detection from keystroke features
    
    Uses a simple gradient boosting model for real-time inference
    """
    
    def __init__(self):
        self.model = None
        self.feature_names = [
            'hold_time_cv',
            'flight_time_cv',
            'wpm',
            'error_rate',
            'rhythm_consistency',
        ]
    
    def train(self, X: np.ndarray, y: np.ndarray):
        """
        Train stress detection model
        
        Args:
            X: Feature matrix [num_samples, num_features]
            y: Labels (0=normal, 1=stressed)
        """
        try:
            import lightgbm as lgb
            
            self.model = lgb.LGBMClassifier(
                n_estimators=100,
                max_depth=5,
                learning_rate=0.05,
                num_leaves=31,
                random_state=42,
            )
            self.model.fit(X, y)
        except ImportError:
            # Fallback to sklearn if lightgbm not available
            from sklearn.ensemble import GradientBoostingClassifier
            
            self.model = GradientBoostingClassifier(
                n_estimators=100,
                max_depth=5,
                learning_rate=0.05,
                random_state=42,
            )
            self.model.fit(X, y)
    
    def predict_proba(self, features: Dict[str, float]) -> float:
        """
        Predict stress probability
        
        Args:
            features: Keystroke features dictionary
        
        Returns:
            Probability of stress (0-1)
        """
        if self.model is None:
            raise ValueError("Model not trained")
        
        # Extract relevant features
        X = np.array([[features[name] for name in self.feature_names]])
        
        # Predict
        prob = self.model.predict_proba(X)[0, 1]
        return float(prob)


def analyze_keystroke_data(
    press_times: List[float],
    release_times: List[float],
    key_ids: Optional[List[str]] = None,
    is_backspace: Optional[List[bool]] = None,
) -> Dict[str, float]:
    """
    Convenience function to analyze raw keystroke timing data
    
    Args:
        press_times: List of key press timestamps
        release_times: List of key release timestamps
        key_ids: Optional key identifiers
        is_backspace: Optional backspace indicators
    
    Returns:
        Dictionary with features and stress indicators
    """
    # Create keystroke events
    if key_ids is None:
        key_ids = [f"key_{i}" for i in range(len(press_times))]
    if is_backspace is None:
        is_backspace = [False] * len(press_times)
    
    events = [
        KeystrokeEvent(kid, pt, rt, bs)
        for kid, pt, rt, bs in zip(key_ids, press_times, release_times, is_backspace)
    ]
    
    sequence = KeystrokeSequence(
        events=events,
        session_start=min(press_times),
        session_end=max(release_times),
    )
    
    # Analyze
    analyzer = KeystrokeDynamicsAnalyzer()
    features = analyzer.extract_features(sequence)
    stress_indicators = analyzer.detect_stress(features)
    
    # Combine
    return {**features, **stress_indicators}
