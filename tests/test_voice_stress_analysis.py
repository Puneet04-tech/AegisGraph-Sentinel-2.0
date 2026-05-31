import pytest

try:
    import numpy as np
    from src.features import voice_stress_analysis as voice_mod
except ImportError:
    voice_mod = None
    np = None


def test_extract_features_reuses_shared_audio_profile(monkeypatch):
    assert voice_mod is not None

    analyzer = voice_mod.VoiceStressAnalyzer(sample_rate=16000, max_seconds=2)
    audio = np.ones(1600, dtype=float)

    yin_calls = {"count": 0}
    hilbert_calls = {"count": 0}
    peaks_calls = {"count": 0}
    mfcc_calls = {"count": 0}

    def fake_yin(*args, **kwargs):
        yin_calls["count"] += 1
        return np.array([100.0, 102.0, np.nan, 101.0], dtype=float)

    def fake_hilbert(x):
        hilbert_calls["count"] += 1
        return np.ones_like(x, dtype=float)

    def fake_find_peaks(*args, **kwargs):
        peaks_calls["count"] += 1
        return np.array([1, 3], dtype=int), {}

    def fake_mfcc(*args, **kwargs):
        mfcc_calls["count"] += 1
        return np.ones((13, 4), dtype=float)

    class FakeFeatureNamespace:
        def __init__(self):
            self.mfcc = fake_mfcc

    class FakeLibrosa:
        def __init__(self):
            self.feature = FakeFeatureNamespace()

        def note_to_hz(self, note):
            return 110.0

        def yin(self, *args, **kwargs):
            return fake_yin(*args, **kwargs)

    class FakeSignal:
        def hilbert(self, x):
            return fake_hilbert(x)

        def find_peaks(self, *args, **kwargs):
            return fake_find_peaks(*args, **kwargs)

    monkeypatch.setattr(voice_mod, "AUDIO_LIBS_AVAILABLE", True)
    monkeypatch.setattr(voice_mod, "librosa", FakeLibrosa(), raising=False)
    monkeypatch.setattr(voice_mod, "signal", FakeSignal(), raising=False)

    features = analyzer.extract_features(audio, sample_rate=16000)

    assert isinstance(features, voice_mod.VoiceFeatures)
    assert yin_calls["count"] == 1
    assert hilbert_calls["count"] == 1
    assert peaks_calls["count"] == 1
    assert mfcc_calls["count"] == 1
