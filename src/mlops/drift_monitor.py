import os
import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, asdict
from typing import Dict, Mapping, Optional
import numpy as np
from scipy import stats

try:
    import requests
except ImportError:
    requests = None

# Module-level logger — configuration is the responsibility of the
# application entry point, not of library modules.
logger = logging.getLogger(__name__)

# Population Stability Index interpretation, the conventional banding used
# in credit and fraud risk monitoring.
PSI_MODERATE = 0.1
PSI_SIGNIFICANT = 0.25

# Guards log(0) and division by zero when a bin is empty on either side.
_PSI_EPSILON = 1e-6

SEVERITY_STABLE = "STABLE"
SEVERITY_MODERATE = "MODERATE"
SEVERITY_SIGNIFICANT = "SIGNIFICANT"


def population_stability_index(baseline, live, bins: int = 10) -> float:
    """
    Population Stability Index between a baseline and a live sample.

    Bin edges are the baseline's quantiles, so bins hold roughly equal
    baseline mass and the index is not dominated by outliers. Returns
    0.0 when either sample is empty or the baseline is constant, since
    no meaningful shift can be measured.

    Interpretation (industry convention):
        < 0.10  no significant shift
        < 0.25  moderate shift, investigate
        >= 0.25 significant shift, retraining candidate
    """
    baseline = np.asarray(baseline, dtype=float).ravel()
    live = np.asarray(live, dtype=float).ravel()

    if baseline.size == 0 or live.size == 0:
        return 0.0

    quantiles = np.linspace(0.0, 1.0, bins + 1)
    edges = np.unique(np.quantile(baseline, quantiles))
    if edges.size < 2:
        # Degenerate baseline (all values identical): PSI is undefined.
        return 0.0

    # Outer edges are infinite so live values beyond the baseline's
    # observed range are counted rather than silently dropped.
    edges[0] = -np.inf
    edges[-1] = np.inf

    baseline_counts, _ = np.histogram(baseline, bins=edges)
    live_counts, _ = np.histogram(live, bins=edges)

    baseline_pct = baseline_counts / baseline.size
    live_pct = live_counts / live.size

    baseline_pct = np.clip(baseline_pct, _PSI_EPSILON, None)
    live_pct = np.clip(live_pct, _PSI_EPSILON, None)

    return float(np.sum((live_pct - baseline_pct) * np.log(live_pct / baseline_pct)))


@dataclass
class DriftReport:
    """Outcome of comparing one live batch against its baseline.

    Truthy exactly when drift was detected, so existing callers that
    branch on the return value of evaluate_batch keep working.
    """
    feature: str
    ks_statistic: float
    p_value: float
    psi: float
    severity: str
    drift_detected: bool
    baseline_size: int
    live_size: int

    def __bool__(self) -> bool:
        return self.drift_detected

    def to_dict(self) -> Dict:
        return asdict(self)


class AdversarialDriftMonitor:
    """
    MLOps service to monitor continuous data distributions using the
    Kolmogorov-Smirnov (K-S) test and the Population Stability Index.
    Detects when attackers change their behavior.

    Baselines are the feature distributions the model was trained on.
    Supply them explicitly, or point the monitor at a baseline file
    written by ``save_baselines`` (see also the
    ``AEGIS_DRIFT_BASELINE_PATH`` environment variable). Without any of
    those the monitor falls back to clearly-labelled placeholder
    distributions, which are useful for smoke tests but must not be
    relied on to judge production traffic.
    """

    def __init__(
        self,
        p_value_threshold=0.05,
        webhook_url=None,
        alert_workers=4,
        alert_cooldown=300.0,
        baselines: Optional[Mapping[str, object]] = None,
        baseline_path: Optional[str] = None,
        psi_threshold: float = PSI_SIGNIFICANT,
        psi_bins: int = 10,
    ):
        self.p_value_threshold = p_value_threshold
        self.psi_threshold = psi_threshold
        self.psi_bins = psi_bins
        self.baseline_path = baseline_path or os.getenv("AEGIS_DRIFT_BASELINE_PATH")
        self._provided_baselines = baselines
        self.baselines_are_synthetic = False
        resolved_url = webhook_url or os.getenv("SLACK_WEBHOOK_URL")
        if resolved_url and not resolved_url.startswith("https://"):
            raise ValueError(
                f"webhook_url must use HTTPS (got {resolved_url!r}). "
                "Drift alerts contain model telemetry that must not be sent over plaintext HTTP."
            )
        self.webhook_url = resolved_url
        self._alert_workers = max(2, int(alert_workers))
        self._alert_executor = ThreadPoolExecutor(
            max_workers=self._alert_workers,
            thread_name_prefix="drift-alert",
        )
        self._closed = False
        self._last_alert_time: Dict[str, float] = {}
        self._alert_cooldown = alert_cooldown

        # Load or simulate the baseline data (what the model was trained on)
        self.baselines = self._load_training_baselines()

    def close(self):
        """Shut down the alert executor, draining pending work."""
        if self._closed:
            return
        self._closed = True
        self._alert_executor.shutdown(wait=True)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    def __del__(self):
        try:
            self.close()
        except Exception as exc:
            logger.error("AdversarialDriftMonitor cleanup failed: %s", exc)

    def _load_training_baselines(self):
        """Resolve baseline distributions, preferring real training data.

        Order of precedence: explicitly passed baselines, then a saved
        baseline file, then labelled placeholder distributions.
        """
        if self._provided_baselines is not None:
            baselines = self._coerce_baselines(self._provided_baselines)
            logger.info(
                "Loaded %d drift baselines from caller", len(baselines)
            )
            return baselines

        if self.baseline_path:
            baselines = self._read_baseline_file(self.baseline_path)
            logger.info(
                "Loaded %d drift baselines from %s",
                len(baselines),
                self.baseline_path,
            )
            return baselines

        self.baselines_are_synthetic = True
        logger.warning(
            "No training baselines supplied; using placeholder distributions. "
            "Drift results are NOT meaningful for production traffic. Pass "
            "baselines=..., set baseline_path, or export "
            "AEGIS_DRIFT_BASELINE_PATH to a file written by save_baselines()."
        )
        # Seeded so placeholder baselines are at least reproducible across
        # processes; previously each instance invented a different baseline.
        rng = np.random.default_rng(seed=0)
        return {
            # E.g., Humans type with an average flight time of ~120ms with some variance
            "keystroke_flight_time": rng.normal(loc=120.0, scale=15.0, size=1000),
            # E.g., Normal network graph centrality scores are heavily right-skewed (near zero)
            "graph_centrality": rng.exponential(scale=0.05, size=1000),
        }

    @staticmethod
    def _coerce_baselines(baselines: Mapping[str, object]) -> Dict[str, np.ndarray]:
        """Validate and normalize a baseline mapping to 1-D float arrays."""
        coerced: Dict[str, np.ndarray] = {}
        for name, samples in baselines.items():
            array = np.asarray(samples, dtype=float).ravel()
            if array.size == 0:
                raise ValueError(f"Baseline for '{name}' is empty")
            if not np.all(np.isfinite(array)):
                raise ValueError(f"Baseline for '{name}' contains non-finite values")
            coerced[name] = array
        if not coerced:
            raise ValueError("No baselines provided")
        return coerced

    @classmethod
    def _read_baseline_file(cls, path: str) -> Dict[str, np.ndarray]:
        """Load baselines from a .npz archive written by save_baselines."""
        if not os.path.exists(path):
            raise FileNotFoundError(f"Drift baseline file not found: {path}")
        # allow_pickle stays False: baseline files are plain numeric arrays
        # and must never be able to execute code on load.
        with np.load(path, allow_pickle=False) as archive:
            return cls._coerce_baselines(
                {name: archive[name] for name in archive.files}
            )

    def register_baseline(self, feature_name: str, samples) -> None:
        """Add or replace one feature's baseline distribution."""
        self.baselines.update(self._coerce_baselines({feature_name: samples}))
        self.baselines_are_synthetic = False

    def fit_baselines(self, feature_samples: Mapping[str, object]) -> None:
        """Replace all baselines with distributions from training data."""
        self.baselines = self._coerce_baselines(feature_samples)
        self.baselines_are_synthetic = False
        logger.info("Fitted %d drift baselines from training data", len(self.baselines))

    def save_baselines(self, path: str) -> str:
        """Persist current baselines so later runs compare against the same
        training distribution instead of regenerating one."""
        if self.baselines_are_synthetic:
            logger.warning("Saving placeholder baselines to %s", path)
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        np.savez(path, **self.baselines)
        return path

    def trigger_alert(
        self,
        feature_name,
        p_value,
        stat,
        drift_type="Adversarial Adaptation",
        psi=None,
        severity=None,
    ):
        """Fires a high-priority webhook alert to the MLOps team."""
        psi_line = ""
        if psi is not None:
            psi_line = f"PSI: {psi:.4f}" + (f" ({severity})" if severity else "") + "\n"
        baseline_note = (
            "\nNOTE: baselines are placeholders, not real training data."
            if self.baselines_are_synthetic
            else ""
        )
        msg = (
            f"🚨 CRITICAL MLOPS ALERT: Data Drift Detected! 🚨\n"
            f"Feature: {feature_name}\n"
            f"K-S Statistic: {stat:.4f} | P-Value: {p_value:.4e}\n"
            f"{psi_line}"
            f"Diagnosis: {drift_type}. The incoming live data no longer matches the training distribution."
            f" Immediate model retraining recommended."
            f"{baseline_note}"
        )
        logger.warning(msg)

        now = time.time()
        last_time = self._last_alert_time.get(feature_name, 0.0)
        if now - last_time < self._alert_cooldown:
            logger.info("Suppressed duplicate webhook for %s (cooldown active)", feature_name)
            return

        self._last_alert_time[feature_name] = now

        if self.webhook_url and not self._closed:
            self._alert_executor.submit(self._dispatch_webhook_alert, msg)

    def _dispatch_webhook_alert(self, msg, retries=3):
        if requests is None:
            logger.warning("requests is unavailable; skipping webhook dispatch")
            return

        for attempt in range(retries):
            try:
                requests.post(self.webhook_url, json={"text": msg}, timeout=2)
                return
            except Exception as e:
                logger.error("Webhook alert dispatch attempt %d/%d failed: %s", attempt + 1, retries, e)
                if attempt < retries - 1:
                    time.sleep(1 * (attempt + 1))

    def evaluate_batch(self, feature_name, live_data_batch):
        """
        Compares a batch of live incoming data against the training baseline.

        Runs two complementary checks:
        - the two-sample K-S test, which answers "is the shift
          statistically detectable" (and grows more sensitive as batches
          get larger)
        - the Population Stability Index, which answers "how large is
          the shift" on a scale that does not depend on sample size

        Returns a DriftReport, which is truthy when drift was detected.
        """
        if feature_name not in self.baselines:
            logger.error("Feature '%s' not found in baselines.", feature_name)
            return None

        baseline_data = self.baselines[feature_name]
        live_data = np.asarray(live_data_batch, dtype=float).ravel()

        if live_data.size == 0:
            logger.error("Live batch for '%s' is empty.", feature_name)
            return None

        # Two-Sample Kolmogorov-Smirnov Test
        # Null hypothesis: Both samples come from the exact same distribution
        stat, p_value = stats.ks_2samp(baseline_data, live_data)

        psi = population_stability_index(
            baseline_data, live_data, bins=self.psi_bins
        )

        if psi >= PSI_SIGNIFICANT:
            severity = SEVERITY_SIGNIFICANT
        elif psi >= PSI_MODERATE:
            severity = SEVERITY_MODERATE
        else:
            severity = SEVERITY_STABLE

        # bool() so the flag is a Python bool, not numpy.bool_, which
        # would make DriftReport.__bool__ raise.
        drift_detected = bool(
            p_value < self.p_value_threshold or psi >= self.psi_threshold
        )

        report = DriftReport(
            feature=feature_name,
            ks_statistic=float(stat),
            p_value=float(p_value),
            psi=psi,
            severity=severity,
            drift_detected=drift_detected,
            baseline_size=int(np.asarray(baseline_data).size),
            live_size=int(live_data.size),
        )

        if drift_detected:
            self.trigger_alert(feature_name, p_value, stat, psi=psi, severity=severity)
        else:
            logger.info(
                "✅ %s distribution is stable (p=%.4f, PSI=%.4f).",
                feature_name,
                p_value,
                psi,
            )

        return report


def create_monitor(**kwargs) -> "AdversarialDriftMonitor":
    """Return a configured AdversarialDriftMonitor instance.

    Callers control when the monitor is created, avoiding thread-pool
    and baseline-generation side effects at import time.

    All keyword arguments are forwarded to AdversarialDriftMonitor.__init__.
    """
    return AdversarialDriftMonitor(**kwargs)


if __name__ == "__main__":
    print("--- Testing Adversarial Drift Monitor ---")

    # Stand in for distributions measured on the training set; in
    # production these come from fit_baselines()/save_baselines().
    rng = np.random.default_rng(seed=42)
    training_baselines = {
        "keystroke_flight_time": rng.normal(loc=120.0, scale=15.0, size=1000),
    }

    with AdversarialDriftMonitor(baselines=training_baselines) as monitor:
        print("\n[Scenario 1: Normal Traffic]")
        normal_traffic = rng.normal(loc=121.0, scale=14.5, size=300)
        print(monitor.evaluate_batch("keystroke_flight_time", normal_traffic))

        print("\n[Scenario 2: Adversarial Bot Attack]")
        bot_traffic = rng.normal(loc=150.0, scale=2.0, size=300)
        print(monitor.evaluate_batch("keystroke_flight_time", bot_traffic))
