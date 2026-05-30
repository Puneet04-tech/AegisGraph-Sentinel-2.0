import os
import json
import logging
from concurrent.futures import ThreadPoolExecutor
import numpy as np
from scipy import stats

try:
    import requests
except ImportError:
    requests = None

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class AdversarialDriftMonitor:
    """
    MLOps service to monitor continuous data distributions using the 
    Kolmogorov-Smirnov (K-S) test. Detects when attackers change their behavior.
    """
    def __init__(self, p_value_threshold=0.05, webhook_url=None):
        self.p_value_threshold = p_value_threshold
        self.webhook_url = webhook_url or os.getenv("SLACK_WEBHOOK_URL")
        self._alert_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="drift-alert")
        
        # Load or simulate the baseline data (what the model was trained on)
        self.baselines = self._load_training_baselines()

    def _load_training_baselines(self):
        """Loads baseline distributions. Mocked here for CI/CD testing."""
        logging.info("Loading training baselines for drift monitoring...")
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
        logging.warning(msg)

        if self.webhook_url:
            self._alert_executor.submit(self._dispatch_webhook_alert, msg)

    def _dispatch_webhook_alert(self, msg):
        if requests is None:
            logging.warning("requests is unavailable; skipping webhook dispatch")
            return

        try:
            requests.post(self.webhook_url, json={"text": msg}, timeout=2)
        except Exception as e:
            logging.error(f"Failed to dispatch webhook alert: {e}")

    def evaluate_batch(self, feature_name, live_data_batch):
        """
        Compares a batch of live incoming data against the training baseline.
        """
        if feature_name not in self.baselines:
            logging.error(f"Feature {feature_name} not found in baselines.")
            return

        baseline_data = self.baselines[feature_name]
        
        # Two-Sample Kolmogorov-Smirnov Test
        # Null hypothesis: Both samples come from the exact same distribution
        stat, p_value = stats.ks_2samp(baseline_data, live_data_batch)

        if p_value < self.p_value_threshold:
            self.trigger_alert(feature_name, p_value, stat)
            return True # Drift detected
            
        logging.info(f"✅ {feature_name} distribution is stable (p={p_value:.4f}).")
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
