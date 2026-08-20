
# Added honeypot velocity tracking
def track_velocity():
    pass

# --- GENERATED: log_cf ---
def log_cf(amount, threshold=1.0):
    """Log-scaled correlation factor for fraud signal normalization."""
    import math
    if amount is None or amount <= threshold:
        return 0.0
    return math.log10(amount)
# --- END GENERATED ---