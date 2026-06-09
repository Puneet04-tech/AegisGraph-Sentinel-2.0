"""
KPI Engine Module.

Provides KPI tracking, threshold monitoring, and alert management.
"""

import random
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone, timedelta
import logging

from .models import KPI, Insight
from .store import AnalyticsStore, get_analytics_store

logger = logging.getLogger(__name__)


class KPIEngineModule:
    """KPI Engine for performance tracking and monitoring.
    
    Provides:
        - KPI management
        - Threshold monitoring
        - Status updates
        - Alert generation
    """
    
    def __init__(self, store: Optional[AnalyticsStore] = None):
        """Initialize the KPI engine module.
        
        Args:
            store: Optional analytics store
        """
        self._store = store or get_analytics_store()
        self._module_id = "kpi_engine"
    
    def create_kpi(
        self,
        name: str,
        description: str,
        metric_id: str,
        target_value: float,
        warning_threshold: float,
        critical_threshold: float,
        category: str,
        owner: str = None,
    ) -> KPI:
        """Create a new KPI.
        
        Args:
            name: KPI name
            description: KPI description
            metric_id: Associated metric ID
            target_value: Target value to achieve
            warning_threshold: Warning threshold
            critical_threshold: Critical threshold
            category: KPI category
            owner: KPI owner
            
        Returns:
            KPI
        """
        logger.info(f"Creating KPI: {name}")
        
        kpi = KPI(
            name=name,
            description=description,
            metric_id=metric_id,
            target_value=target_value,
            warning_threshold=warning_threshold,
            critical_threshold=critical_threshold,
            current_value=None,
            previous_value=None,
            change_percent=None,
            status="ON_TARGET",
            category=category,
            owner=owner,
        )
        
        self._store.store_kpi(kpi)
        return kpi
    
    def update_kpi_value(
        self,
        kpi_id: str,
        new_value: float,
    ) -> KPI:
        """Update KPI with a new value.
        
        Args:
            kpi_id: KPI ID
            new_value: New metric value
            
        Returns:
            Updated KPI
        """
        logger.info(f"Updating KPI {kpi_id}: {new_value}")
        
        kpi = self._store.get_kpi(kpi_id)
        if not kpi:
            raise ValueError(f"KPI {kpi_id} not found")
        
        # Calculate change
        previous_value = kpi.current_value
        if previous_value:
            change_percent = ((new_value - previous_value) / previous_value) * 100
        else:
            change_percent = 0
        
        # Determine status
        status = self._calculate_status(
            new_value,
            kpi.target_value,
            kpi.warning_threshold,
            kpi.critical_threshold,
        )
        
        # Update KPI
        kpi.previous_value = previous_value
        kpi.current_value = new_value
        kpi.change_percent = round(change_percent, 2)
        kpi.status = status
        kpi.last_updated = datetime.now(timezone.utc)
        
        self._store.store_kpi(kpi)
        return kpi
    
    def _calculate_status(
        self,
        current_value: float,
        target_value: float,
        warning_threshold: float,
        critical_threshold: float,
    ) -> str:
        """Calculate KPI status based on thresholds."""
        # Handle "lower is better" metrics (like false positive rate)
        if target_value < warning_threshold:
            if current_value >= critical_threshold:
                return "CRITICAL"
            elif current_value >= warning_threshold:
                return "WARNING"
            else:
                return "ON_TARGET"
        else:
            # Handle "higher is better" metrics
            if target_value == 0:
                return "ON_TARGET"
            
            achievement_ratio = current_value / target_value
            if achievement_ratio < 0.8:
                return "CRITICAL"
            elif achievement_ratio < 0.95:
                return "WARNING"
            else:
                return "ON_TARGET"
    
    def monitor_thresholds(
        self,
        kpi_id: str = None,
    ) -> List[Dict[str, Any]]:
        """Monitor KPIs for threshold breaches.
        
        Args:
            kpi_id: Optional specific KPI to monitor
            
        Returns:
            List of threshold alerts
        """
        logger.info(f"Monitoring thresholds for KPI: {kpi_id or 'all'}")
        
        alerts = []
        kpis = [self._store.get_kpi(kpi_id)] if kpi_id else self._store.get_all_kpis()
        
        for kpi in kpis:
            if not kpi:
                continue
            
            # Check for threshold breach
            if kpi.current_value is None:
                continue
            
            achievement_ratio = kpi.current_value / kpi.target_value if kpi.target_value != 0 else 0
            
            if kpi.target_value < kpi.warning_threshold:
                # Lower is better
                if kpi.current_value >= kpi.critical_threshold:
                    alerts.append(self._create_alert(kpi, "CRITICAL", "Critical threshold exceeded"))
                elif kpi.current_value >= kpi.warning_threshold:
                    alerts.append(self._create_alert(kpi, "WARNING", "Warning threshold exceeded"))
            else:
                # Higher is better
                if achievement_ratio < 0.8:
                    alerts.append(self._create_alert(kpi, "CRITICAL", f"Only {achievement_ratio*100:.1f}% of target"))
                elif achievement_ratio < 0.95:
                    alerts.append(self._create_alert(kpi, "WARNING", f"Only {achievement_ratio*100:.1f}% of target"))
        
        return alerts
    
    def _create_alert(self, kpi: KPI, severity: str, message: str) -> Dict[str, Any]:
        """Create a threshold alert."""
        return {
            "kpi_id": kpi.kpi_id,
            "kpi_name": kpi.name,
            "severity": severity,
            "message": message,
            "current_value": kpi.current_value,
            "target_value": kpi.target_value,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    
    def get_kpi_dashboard(self) -> Dict[str, Any]:
        """Get KPI dashboard summary."""
        all_kpis = self._store.get_all_kpis()
        
        on_target = [k for k in all_kpis if k.status == "ON_TARGET"]
        warning = [k for k in all_kpis if k.status == "WARNING"]
        critical = [k for k in all_kpis if k.status == "CRITICAL"]
        
        return {
            "total_kpis": len(all_kpis),
            "on_target": len(on_target),
            "warning": len(warning),
            "critical": len(critical),
            "health_score": round(len(on_target) / len(all_kpis) * 100 if all_kpis else 0, 1),
            "kpis_by_category": self._get_kpis_by_category(),
            "recent_changes": self._get_recent_changes(),
        }
    
    def _get_kpis_by_category(self) -> Dict[str, Dict[str, int]]:
        """Get KPI counts by category and status."""
        result = {}
        for kpi in self._store.get_all_kpis():
            if kpi.category not in result:
                result[kpi.category] = {"total": 0, "on_target": 0, "warning": 0, "critical": 0}
            
            result[kpi.category]["total"] += 1
            result[kpi.category][kpi.status.lower()] += 1
        
        return result
    
    def _get_recent_changes(self) -> List[Dict[str, Any]]:
        """Get recent KPI value changes."""
        changes = []
        for kpi in self._store.get_all_kpis():
            if kpi.change_percent is not None and abs(kpi.change_percent) > 5:
                changes.append({
                    "kpi_id": kpi.kpi_id,
                    "kpi_name": kpi.name,
                    "previous_value": kpi.previous_value,
                    "current_value": kpi.current_value,
                    "change_percent": kpi.change_percent,
                    "timestamp": kpi.last_updated.isoformat(),
                })
        
        return sorted(changes, key=lambda c: c["change_percent"], reverse=True)[:10]
    
    def get_trending_kpis(self, limit: int = 5) -> List[Dict[str, Any]]:
        """Get top trending KPIs."""
        kpis = self._store.get_all_kpis()
        
        # Sort by absolute change
        trending = sorted(
            [k for k in kpis if k.change_percent is not None],
            key=lambda k: abs(k.change_percent),
            reverse=True,
        )
        
        return [
            {
                "kpi_id": k.kpi_id,
                "name": k.name,
                "current_value": k.current_value,
                "target_value": k.target_value,
                "change_percent": k.change_percent,
                "status": k.status,
            }
            for k in trending[:limit]
        ]
    
    def get_underperforming_kpis(self) -> List[KPI]:
        """Get KPIs that are underperforming."""
        return self._store.get_kpis_by_status("CRITICAL") + self._store.get_kpis_by_status("WARNING")
    
    def export_kpi_report(self) -> Dict[str, Any]:
        """Export complete KPI report."""
        kpis = self._store.get_all_kpis()
        
        return {
            "report_date": datetime.now(timezone.utc).isoformat(),
            "summary": self.get_kpi_dashboard(),
            "kpis": [
                {
                    "id": k.kpi_id,
                    "name": k.name,
                    "description": k.description,
                    "category": k.category,
                    "owner": k.owner,
                    "target_value": k.target_value,
                    "current_value": k.current_value,
                    "previous_value": k.previous_value,
                    "change_percent": k.change_percent,
                    "status": k.status,
                    "last_updated": k.last_updated.isoformat(),
                }
                for k in kpis
            ],
        }


# Global singleton
_kpi_engine: Optional[KPIEngineModule] = None


def get_kpi_engine_module(store: Optional[AnalyticsStore] = None) -> KPIEngineModule:
    """Get or create the singleton KPIEngineModule instance."""
    global _kpi_engine
    
    if _kpi_engine is None:
        _kpi_engine = KPIEngineModule(store=store)
    return _kpi_engine