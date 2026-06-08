import os
import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Dict
import numpy as np
from scipy import stats

try:
    import requests
except ImportError:
    requests = None

# Module-level logger — configuration is the responsibility of the
# application entry point, not of library modules.
logger = logging.getLogger(__name__)


class AdversarialDriftMonitor:
    """
    MLOps service to monitor continuous data distributions using the 
    Kolmogorov-Smirnov (K-S) test. Detects when attackers change their behavior.
    """
    def __init__(self, p_value_threshold=0.05, webhook_url=None, alert_workers=4, alert_cooldown=300.0):
        self.p_value_threshold = p_value_threshold
        self.webhook_url = webhook_url or os.getenv("SLACK_WEBHOOK_URL")
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
        """Loads baseline distributions. Mocked here for CI/CD testing."""
        logger.info("Loading training baselines for drift monitoring...")
        return {
            # E.g., Humans type with an average flight time of ~120ms with some variance
            "keystroke_flight_time": np.random.normal(loc=120.0, scale=15.0, size=1000),
            # E.g., Normal network graph centrality scores are heavily right-skewed (near zero)
            "graph_centrality": np.random.exponential(scale=0.05, size=1000)
        }

    def trigger_alert(self, feature_name, p_value, stat, drift_type="Adversarial Adaptation"):
        """Fires a high-priority webhook alert to the MLOps team."""
        msg = (
            f"🚨 CRITICAL MLOPS ALERT: Data Drift Detected! 🚨\n"
            f"Feature: {feature_name}\n"
            f"K-S Statistic: {stat:.4f} | P-Value: {p_value:.4e}\n"
            f"Diagnosis: {drift_type}. The incoming live data no longer matches the training distribution."
            f" Immediate model retraining recommended."
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
        """
        if feature_name not in self.baselines:
            logger.error("Feature '%s' not found in baselines.", feature_name)
            return

        baseline_data = self.baselines[feature_name]
        
        # Two-Sample Kolmogorov-Smirnov Test
        # Null hypothesis: Both samples come from the exact same distribution
        stat, p_value = stats.ks_2samp(baseline_data, live_data_batch)

        if p_value < self.p_value_threshold:
            self.trigger_alert(feature_name, p_value, stat)
            return True # Drift detected
            
        logger.info("✅ %s distribution is stable (p=%.4f).", feature_name, p_value)
        return False # No drift


if __name__ == "__main__":
    print("--- Testing Adversarial Drift Monitor ---")
    monitor = AdversarialDriftMonitor()
    
    print("\n[Scenario 1: Normal Traffic]")
    # Simulating normal human traffic (matches the 120ms baseline)
    normal_traffic = np.random.normal(loc=121.0, scale=14.5, size=300)
    monitor.evaluate_batch("keystroke_flight_time", normal_traffic)
    
    print("\n[Scenario 2: Adversarial Bot Attack]")
    # Simulating bots that figured out the threshold and started typing at exactly 150ms
    bot_traffic = np.random.normal(loc=150.0, scale=2.0, size=300)
    monitor.evaluate_batch("keystroke_flight_time", bot_traffic)
