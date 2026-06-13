"""Executive Command Dashboard Service"""
from __future__ import annotations
from typing import Any, Dict, Optional
from .models import Dashboard, Widget, DashboardMetrics
from .store import get_dashboard_store, DashboardStore


class DashboardService:
    """Core dashboard service."""

    def __init__(self, store: Optional[DashboardStore] = None):
        self._store = store or get_dashboard_store()

    def create_dashboard(self, name: str, description: str, owner: str = "system") -> Dashboard:
        d = Dashboard(name=name, description=description, owner=owner)
        return self._store.store_dashboard(d)

    def get_dashboard(self, dashboard_id: str) -> Optional[Dashboard]:
        return self._store.get_dashboard(dashboard_id)

    def add_widget(self, dashboard_id: str, widget_type: str, title: str, config: Dict[str, Any]) -> Optional[Widget]:
        d = self._store.get_dashboard(dashboard_id)
        if d:
            w = Widget(widget_type=widget_type, title=title, config=config, position=len(d.widgets))
            d.widgets.append(w)
            self._store.store_dashboard(d)
            return w
        return None

    def create_widget(self, widget_type: str, title: str, config: Dict[str, Any]) -> Widget:
        w = Widget(widget_type=widget_type, title=title, config=config)
        return self._store.store_widget(w)

    def get_widget(self, widget_id: str) -> Optional[Widget]:
        return self._store.get_widget(widget_id)

    def get_metrics(self) -> DashboardMetrics:
        m = self._store.get_metrics()
        return DashboardMetrics(**m)


_service: Optional[DashboardService] = None


def get_dashboard_service() -> DashboardService:
    global _service
    if _service is None:
        _service = DashboardService()
    return _service
