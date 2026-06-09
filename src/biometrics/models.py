"""
Behavioral Biometrics Intelligence Models.

Data models for keystroke analytics, mouse dynamics, and behavioral profiling.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field
import uuid


class BiometricType(str, Enum):
    """Biometric types."""
    KEYSTROKE = "KEYSTROKE"
    MOUSE_DYNAMICS = "MOUSE_DYNAMICS"
    TOUCH_PATTERN = "TOUCH_PATTERN"
    DEVICE_USAGE = "DEVICE_USAGE"


class BehavioralProfile(BaseModel):
    """Behavioral profile."""
    profile_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    keystroke_profile: Dict[str, Any] = Field(default_factory=dict)
    mouse_profile: Dict[str, Any] = Field(default_factory=dict)
    touch_profile: Dict[str, Any] = Field(default_factory=dict)
    authenticity_score: float = 1.0
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class KeystrokeSample(BaseModel):
    """Keystroke sample."""
    sample_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    key_press_duration: float
    key_release_duration: float
    flight_time: float
    digraph_duration: float
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class MouseDynamicsSample(BaseModel):
    """Mouse dynamics sample."""
    sample_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    velocity: float
    acceleration: float
    curvature: float
    click_duration: float
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class VerificationResult(BaseModel):
    """Verification result."""
    verification_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    biometric_type: BiometricType
    match_score: float
    threshold: float
    verified: bool
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))