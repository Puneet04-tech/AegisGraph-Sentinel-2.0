"""Executive Command Dashboard Store"""
from __future__ import annotations
from threading import Lock
from typing import Any, Dict, Optional
from .models import Dashboard, Widget


class DashboardStore:
    """Thread-safe storage."""

    def __init__(self):
        self._lock = Lock()
        self._dashboards: Dict[str, Dashboard] = {}
        self._widgets: Dict[str, Widget] = {}

    def store_dashboard(self, d: Dashboard) -> Dashboard:
        with self._lock:
            self._dashboards[d.dashboard_id] = d
        return d

    def get_dashboard(self, dashboard_id: str) -> Optional[Dashboard]:
        return self._dashboards.get(dashboard_id)

    def store_widget(self, w: Widget) -> Widget:
        with self._lock:
            self._widgets[w.widget_id] = w
        return w

    def get_widget(self, widget_id: str) -> Optional[Widget]:
        return self._widgets.get(widget_id)

    def get_metrics(self) -> Dict[str, Any]:
        return {
            "total_dashboards": len(self._dashboards),
            "total_widgets": len(self._widgets),
            "active_views": len(self._dashboards),
        }


_store: Optional[DashboardStore] = None


def get_dashboard_store() -> DashboardStore:
    global _store
    if _store is None:
        _store = DashboardStore()
    return _store
