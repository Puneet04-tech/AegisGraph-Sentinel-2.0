"""
AegisGraph Sentinel 2.0 - Streamlit Web Application
Real-time Fraud Detection Interface
"""
# Updated: May 17, 2026

import atexit
import logging
import streamlit as st
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)
try:
    from streamlit_autorefresh import st_autorefresh
except ImportError:
    st_autorefresh = None
import requests
import json
import html
import base64
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
from datetime import datetime
from datetime import timezone
import time
import os
import random
import numpy as np
import networkx as nx
from src.inference.model_comparison import build_model_explanation_comparison
from src.timeline.doubly_linked_list import DoublyLinkedList

def _get_timestamp() -> str:
    """Return a strict ISO 8601 UTC timestamp (YYYY-MM-DDTHH:MM:SSZ) for the API."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

# Page configuration
st.set_page_config(
    page_title="AegisGraph Sentinel 2.0",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# API Configuration
API_URL = os.getenv("API_URL", "http://127.0.0.1:8000")
MAX_BATCH_UPLOAD_BYTES = int(os.getenv("MAX_BATCH_UPLOAD_BYTES", 5 * 1024 * 1024))
BATCH_PREVIEW_ROWS = int(os.getenv("BATCH_PREVIEW_ROWS", 10))
BATCH_CHUNK_SIZE = int(os.getenv("BATCH_CHUNK_SIZE", 50))
BATCH_MAX_ROWS = int(os.getenv("BATCH_MAX_ROWS", 500))

def display_decision_badge(decision: str):
    """
    Display a color-coded status badge for the given decision.
    """
    status = str(decision).upper()
    if status in ["SAFE", "ALLOW", "APPROVE"]:
        st.success(f"✅ {status}")
    elif status == "REVIEW":
        st.warning(f"⚠️ {status}")
    elif status == "BLOCK":
        st.error(f"🛑 {status}")
    else:
        st.info(f"ℹ️ {status}")

REQUIRED_CSV_COLUMNS = {"transaction_id", "source_account", "target_account", "amount"}
COMMAND_CENTER_REFRESH_KEY = "command_center_live_refresh"

COMMAND_CENTER_IO_EXECUTOR = ThreadPoolExecutor(
    max_workers=int(os.getenv("COMMAND_CENTER_WORKERS", 2)),
    thread_name_prefix="aegis-cmd-center",
)
atexit.register(COMMAND_CENTER_IO_EXECUTOR.shutdown, wait=False, cancel_futures=True)


def _cache_data(ttl: int):
    cache_data = getattr(st, "cache_data", None)
    if cache_data is None:
        def passthrough(fn):
            return fn
        return passthrough
    return cache_data(ttl=ttl)


def _accessible_status(emoji: str, label: str) -> str:
    return f"{emoji} {label} ({label})"


def _escape_network_tooltip_value(value) -> str:
    return html.escape(str(value), quote=True)


def _json_for_inline_script(value) -> str:
    return json.dumps(value, ensure_ascii=False)


def _validate_csv_columns(df: pd.DataFrame) -> list:
    uploaded_cols = {col.strip().lower() for col in df.columns}
    return [col for col in REQUIRED_CSV_COLUMNS if col not in uploaded_cols]


def _build_batch_transaction(row, index: int) -> dict:
    return {
        "transaction_id": str(row.get("transaction_id", f"TXN_{index}")),
        "source_account": str(row.get("source_account", "unknown")),
        "target_account": str(row.get("target_account", "unknown")),
        "amount": float(row.get("amount", 0)),
        "currency": str(row.get("currency", "INR")),
        "mode": str(row.get("mode", "UPI")),
        "timestamp": str(row.get("timestamp", _get_timestamp())),
    }


def _estimate_csv_rows(uploaded_file) -> int:
    uploaded_file.seek(0)
    total_rows = 0
    for i in range(0, len(st.session_state["batch_df"]), BATCH_CHUNK_SIZE):
        chunk = st.session_state["batch_df"].iloc[i:i+BATCH_CHUNK_SIZE]
        total_rows += len(chunk)
        if total_rows >= BATCH_MAX_ROWS:
            break
    uploaded_file.seek(0)
    return total_rows


def _schedule_live_refresh(interval_ms: int = 1500) -> None:
    if st_autorefresh is not None and st.session_state.get("page") == "🧭 Command Center":
        st_autorefresh(interval=interval_ms, key=COMMAND_CENTER_REFRESH_KEY)


def _api_headers(extra: dict | None = None) -> dict:
    key = os.getenv("AEGIS_UI_API_KEY", "")
    if not key:
        try:
            key = st.secrets.get("AEGIS_UI_API_KEY", "")
        except Exception as exc:
            logging.getLogger(__name__).debug("Failed to access Streamlit secrets: %s", exc)
            key = ""
    headers: dict = {}
    if key:
        headers["X-API-Key"] = key
    if extra:
        headers.update(extra)
    return headers


def _safe_api_get(url: str, timeout: int = 5, extra_headers: dict | None = None) -> dict:
    try:
        response = requests.get(url, timeout=timeout, headers=_api_headers(extra_headers))
        response.raise_for_status()
        return response.json()
    except requests.exceptions.ConnectionError:
        logger.warning("API unreachable (ConnectionError): %s", url)
        st.warning("⚠️ Cannot reach the API server — verify it is running (`uvicorn src.api.main:app --reload`).")
        return {}
    except requests.exceptions.Timeout:
        logger.warning("API request timed out: %s", url)
        st.warning("⚠️ API server did not respond in time. It may be overloaded.")
        return {}
    except requests.exceptions.HTTPError as exc:
        status = exc.response.status_code
        logger.warning("API returned HTTP %s: %s", status, url)
        if status in (401, 403):
            st.warning(
                f"⚠️ API returned {status} — verify **AEGIS_UI_API_KEY** is set correctly "
                "in your environment or `st.secrets`."
            )
        return {}
    except Exception as exc:
        logger.error("Unexpected error fetching %s: %s", url, exc)
        return {}


def _safe_api_post(url: str, payload: dict, timeout: int = 5, extra_headers: dict | None = None) -> dict | None:
    try:
        response = requests.post(url, json=payload, timeout=timeout, headers=_api_headers(extra_headers))
        response.raise_for_status()
        return response.json()
    except requests.exceptions.ConnectionError:
        logger.warning("API unreachable (ConnectionError) for POST: %s", url)
        return None
    except requests.exceptions.Timeout:
        logger.warning("API POST timed out: %s", url)
        return None
    except requests.exceptions.HTTPError as exc:
        logger.warning("API POST returned HTTP %s: %s", exc.response.status_code, url)
        return None
    except Exception as exc:
        logger.error("Unexpected error posting to %s: %s", url, exc)
        return None


@_cache_data(ttl=20)
def _fetch_health_snapshot(api_url: str) -> dict:
    return _safe_api_get(f"{api_url}/health", timeout=2)


@_cache_data(ttl=5)
def _fetch_stats_snapshot(api_url: str) -> dict:
    return _safe_api_get(f"{api_url}/stats", timeout=5)


def _build_live_event(api_url: str, txn: dict) -> dict | None:
    start_t = time.time()
    result = _safe_api_post(f"{api_url}/api/v1/fraud/check", txn, timeout=2)
    if result is None:
        return None
    latency = int((time.time() - start_t) * 1000)
    return {
        "time": datetime.now().strftime("%H:%M:%S"),
        "id": txn["transaction_id"],
        "amount": txn["amount"],
        "decision": result.get("decision", "ALLOW"),
        "risk": result.get("risk_score", 0.0),
        "latency": latency,
        "explanation": result.get("explanation", ""),
        "breakdown": result.get("breakdown", {}),
    }


def _render_model_explanation_comparison(transaction: dict, result: dict) -> None:
    comparison = build_model_explanation_comparison(transaction, result)
    model_rows = comparison["models"]
    display_df = pd.DataFrame(
        {
            "Model": [row["model"] for row in model_rows],
            "Risk Score": [row["risk_score"] for row in model_rows],
            "Decision": [row["decision"] for row in model_rows],
            "Confidence": [row["confidence"] for row in model_rows],
            "Key Contributing Factors": [
                ", ".join(row["key_factors"]) for row in model_rows
            ],
        }
    )

    st.markdown("---")
    st.subheader("🧪 Multi-Model Fraud Explanation Comparison")

    top_cols = st.columns(3)
    with top_cols[0]:
        st.metric("Models Compared", len(model_rows))
    with top_cols[1]:
        agreement = comparison["agreement"]
        agreement_label = (
            "Full Agreement" if agreement["all_models_agree"] else "Mixed Decisions"
        )
        st.metric("Decision Agreement", agreement_label)
    with top_cols[2]:
        confidence = comparison["confidence"]
        st.metric("Confidence Spread", f"{confidence['spread']:.1%}")

    st.dataframe(
        display_df.style.background_gradient(cmap="RdYlGn_r", subset=["Risk Score"]),
        use_container_width=True,
        height=220,
    )

    chart_df = display_df.copy()
    fig_compare = px.bar(
        chart_df,
        x="Model",
        y="Risk Score",
        color="Decision",
        text="Decision",
        color_discrete_map={
            "ALLOW": "#22c55e",
            "REVIEW": "#f59e0b",
            "BLOCK": "#ef4444",
        },
        title="Model Risk Score and Decision Comparison",
    )
    fig_compare.update_layout(height=360, yaxis_range=[0, 1])
    st.plotly_chart(fig_compare, use_container_width=True)

    detail_cols = st.columns(3)
    with detail_cols[0]:
        st.markdown("**Common Factors**")
        if comparison["common_factors"]:
            for factor in comparison["common_factors"]:
                st.write(f"- {factor}")
        else:
            st.write("No single factor appears in every model explanation.")
    with detail_cols[1]:
        st.markdown("**HTGNN-Specific Factors**")
        if comparison["unique_htgnn_factors"]:
            for factor in comparison["unique_htgnn_factors"]:
                st.write(f"- {factor}")
        else:
            st.write("HTGNN shares its top factors with benchmark models.")
    with detail_cols[2]:
        st.markdown("**Agreement Analysis**")
        st.write(comparison["agreement"]["summary"])
        st.write(f"Risk score spread: {confidence['risk_score_spread']:.1%}")

    with st.expander("🧠 Generated Model Explanations"):
        for row in model_rows:
            st.markdown(
                f"**{row['model']}**: `{row['decision']}` at "
                f"{row['risk_score']:.1%} risk, {row['confidence']:.1%} confidence. "
                f"{row['explanation']}"
            )


def _advance_timed_state(
    state_key: str,
    timestamp_key: str,
    interval_seconds: float,
    max_steps: int,
    loop: bool = True,
) -> bool:
    if max_steps <= 0:
        return False

    now = datetime.now(timezone.utc)
    last_tick = st.session_state.get(timestamp_key)
    if last_tick is None:
        st.session_state[timestamp_key] = now
        return False

    elapsed = (now - last_tick).total_seconds()
    if elapsed < interval_seconds:
        return False

    current_step = int(st.session_state.get(state_key, 0))
    steps_to_advance = max(1, int(elapsed // interval_seconds))

    if loop:
        next_step = (current_step + steps_to_advance) % max_steps
    else:
        next_step = min(current_step + steps_to_advance, max_steps - 1)

    st.session_state[state_key] = next_step
    st.session_state[timestamp_key] = now
    return next_step != current_step


# Custom CSS Palette
st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&display=swap');
    
    html, body, [class*="css"] {
        font-family: 'Plus Jakarta Sans', sans-serif !important;
    }
    
    .main-header {
        font-size: 3.5rem;
        font-weight: 800;
        text-align: center;
        background: linear-gradient(135deg, #2dd4bf 0%, #0f766e 50%, #f59e0b 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        padding: 10px 0;
        margin-bottom: 2px;
        letter-spacing: -0.04em;
        text-shadow: 0 10px 30px rgba(045, 212,191, 0.15);
    }
    
    [data-testid="stMetric"], .metric-card {
        background: rgba(22, 27, 48, 0.45
