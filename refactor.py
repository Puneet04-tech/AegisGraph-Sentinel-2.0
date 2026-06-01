import re
import os

app_path = "app.py"
with open(app_path, "r", encoding="utf-8") as f:
    lines = f.readlines()

pages = {
    "command_center": "🧭 Command Center",
    "transaction_scan": "💳 Transaction Scan",
    "batch_triage": "📁 Batch Triage",
    "risk_analytics": "📊 Risk Analytics",
    "network_graph": "🕸️ Network Graph Explorer",
    "behavioral_biometrics": "⌨️ Behavioral Biometrics",
    "innovation_lab": "🧪 Innovation Lab",
    "system_brief": "ℹ️ System Brief"
}

# Find the start and end of each block
blocks = {}
current_page = None
current_block = []

pre_app_lines = []

for i, line in enumerate(lines):
    if line.startswith('if page == "🧭 Command Center":') or line.startswith('elif page == "'):
        if current_page:
            blocks[current_page] = current_block
        
        # Find which page this is
        for page_id, page_title in pages.items():
            if f'"{page_title}"' in line:
                current_page = page_id
                break
        current_block = []
    else:
        if current_page:
            # We are inside a block, dedent it
            if line.startswith("    "):
                current_block.append(line[4:])
            else:
                current_block.append(line)
        else:
            pre_app_lines.append(line)

if current_page:
    blocks[current_page] = current_block

# We also need imports for the generated files.
imports = """import streamlit as st
import logging
import requests
import json
import base64
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
from datetime import datetime, timezone
import time
import os
import random
import numpy as np
import networkx as nx

logger = logging.getLogger(__name__)
from src.ui.error_boundary import with_error_boundary
"""

# Let's generate the files!
os.makedirs("src/ui/pages", exist_ok=True)

# For now, to avoid import errors, we'll just inject the helpers into a helpers file?
# Actually, the easiest way to ensure they have access to app.py's helpers is to just pass app.py globals to the functions?
# No, we will just move the helper functions to src/ui/helpers.py.

with open("src/ui/pages/__init__.py", "w") as f:
    pass

for page_id, block_lines in blocks.items():
    with open(f"src/ui/pages/{page_id}.py", "w", encoding="utf-8") as f:
        f.write(imports + "\n\n")
        f.write(f"@with_error_boundary('{pages[page_id]}')\n")
        # innovation_lab needs `innovation_page`
        if page_id == "innovation_lab":
            f.write(f"def render_{page_id}(innovation_page, helpers, st_globals):\n")
        else:
            f.write(f"def render_{page_id}(helpers, st_globals):\n")
        
        f.write("    # Unpack globals\n")
        f.write("    API_URL = st_globals.get('API_URL')\n")
        f.write("    COMMAND_CENTER_IO_EXECUTOR = st_globals.get('COMMAND_CENTER_IO_EXECUTOR')\n")
        f.write("    _fetch_health_snapshot = helpers.get('_fetch_health_snapshot')\n")
        f.write("    _fetch_stats_snapshot = helpers.get('_fetch_stats_snapshot')\n")
        f.write("    _schedule_live_refresh = helpers.get('_schedule_live_refresh')\n")
        f.write("    _build_live_event = helpers.get('_build_live_event')\n")
        f.write("    _accessible_status = helpers.get('_accessible_status')\n")
        f.write("    _build_batch_transaction = helpers.get('_build_batch_transaction')\n")
        f.write("    _estimate_csv_rows = helpers.get('_estimate_csv_rows')\n")
        f.write("    _advance_timed_state = helpers.get('_advance_timed_state')\n")
        f.write("    BATCH_PREVIEW_ROWS = st_globals.get('BATCH_PREVIEW_ROWS', 10)\n")
        f.write("    BATCH_CHUNK_SIZE = st_globals.get('BATCH_CHUNK_SIZE', 50)\n")
        f.write("    BATCH_MAX_ROWS = st_globals.get('BATCH_MAX_ROWS', 500)\n")
        f.write("    MAX_BATCH_UPLOAD_BYTES = st_globals.get('MAX_BATCH_UPLOAD_BYTES', 5 * 1024 * 1024)\n\n")

        for line in block_lines:
            f.write("    " + line)

# Generate new app.py
with open("app_new.py", "w", encoding="utf-8") as f:
    for line in pre_app_lines:
        f.write(line)
    
    # Imports for the pages
    f.write("\n# Modularized Page Imports\n")
    for page_id in blocks.keys():
        f.write(f"from src.ui.pages.{page_id} import render_{page_id}\n")
    
    f.write("\n# Helpers map\n")
    f.write("helpers = {\n")
    f.write("    '_fetch_health_snapshot': _fetch_health_snapshot,\n")
    f.write("    '_fetch_stats_snapshot': _fetch_stats_snapshot,\n")
    f.write("    '_schedule_live_refresh': _schedule_live_refresh,\n")
    f.write("    '_build_live_event': _build_live_event,\n")
    f.write("    '_accessible_status': _accessible_status,\n")
    f.write("    '_build_batch_transaction': _build_batch_transaction,\n")
    f.write("    '_estimate_csv_rows': _estimate_csv_rows,\n")
    f.write("    '_advance_timed_state': _advance_timed_state,\n")
    f.write("}\n")

    f.write("st_globals = {\n")
    f.write("    'API_URL': API_URL,\n")
    f.write("    'COMMAND_CENTER_IO_EXECUTOR': COMMAND_CENTER_IO_EXECUTOR,\n")
    f.write("    'BATCH_PREVIEW_ROWS': BATCH_PREVIEW_ROWS,\n")
    f.write("    'BATCH_CHUNK_SIZE': BATCH_CHUNK_SIZE,\n")
    f.write("    'BATCH_MAX_ROWS': BATCH_MAX_ROWS,\n")
    f.write("    'MAX_BATCH_UPLOAD_BYTES': MAX_BATCH_UPLOAD_BYTES,\n")
    f.write("}\n")
    
    f.write("\n# Page Routing\n")
    for i, (page_id, page_title) in enumerate(pages.items()):
        if i == 0:
            f.write(f"if page == \"{page_title}\":\n")
        else:
            f.write(f"elif page == \"{page_title}\":\n")
        
        if page_id == "innovation_lab":
            f.write(f"    render_{page_id}(innovation_page, helpers, st_globals)\n")
        else:
            f.write(f"    render_{page_id}(helpers, st_globals)\n")

print("Refactoring complete!")
