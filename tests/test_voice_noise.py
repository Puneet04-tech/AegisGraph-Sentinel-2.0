import numpy as np
import pytest
from src.features.voice_stress_analysis import VoiceStressAnalyzer

def test_voice_noise_reduction():
    analyzer = VoiceStressAnalyzer(sample_rate=16000)
    # Generate clean sine wave
    t = np.linspace(0, 1.0, 16000, endpoint=False)
    clean = np.sin(2 * np.pi * 440 * t)
    # Silence the first 0.25 seconds to act as a noise-only profile for spectral subtraction
    clean[:4000] = 0.0
    
    # Generate white noise and noisy signal
    noise = np.random.normal(0, 0.1, 16000)
    noisy = clean + noise
    
    # Run noise reduction
    reduced = analyzer.reduce_noise(noisy, 16000)
    
    # Assert noise power is reduced on the signal portion
    noise_power_orig = np.mean((noisy[4000:] - clean[4000:]) ** 2)
    noise_power_reduced = np.mean((reduced[4000:] - clean[4000:]) ** 2)
    assert noise_power_reduced < noise_power_orig
