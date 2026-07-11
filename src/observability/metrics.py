from prometheus_client import Counter, Gauge

model_drift_gauge = Gauge('model_drift', 'Drift detected in ML model')
