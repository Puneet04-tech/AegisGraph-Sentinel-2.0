"""Command Center Service"""
from typing import Any, Dict, List, Optional
from uuid import uuid4
from datetime import datetime
from .models import SecurityMetric, ThreatEvent, DashboardConfig, MetricType, ThreatLevel

class CommandCenterService:
    """Enterprise Security Operations Command Center Service"""
    
    def __init__(self) -> None:
        self.metrics: Dict[str, SecurityMetric] = {}
        self.threats: Dict[str, ThreatEvent] = {}
        self.dashboards: Dict[str, DashboardConfig] = {}
        self._init_default_metrics()
    
    def _init_default_metrics(self) -> None:
        """Initialize default metrics"""
        metrics = [
            SecurityMetric(
                metric_id="metric-001",
                metric_type=MetricType.SECURITY,
                name="Active Threats",
                value=0,
                unit="count"
            ),
            SecurityMetric(
                metric_id="metric-002",
                metric_type=MetricType.FRAUD,
                name="Fraud Alerts",
                value=0,
                unit="count"
            )
        ]
        for m in metrics:
            self.metrics[m.metric_id] = m
    
    def record_metric(
        self,
        metric_type: str,
        name: str,
        value: float,
        unit: str
    ) -> Dict[str, Any]:
        """Record a metric"""
        metric = SecurityMetric(
            metric_id=str(uuid4())[:8],
            metric_type=MetricType(metric_type),
            name=name,
            value=value,
            unit=unit
        )
        self.metrics[metric.metric_id] = metric
        return metric.to_dict()
    
    def add_threat(
        self,
        title: str,
        severity: str,
        source: str,
        description: str
    ) -> Dict[str, Any]:
        """Add a threat event"""
        threat = ThreatEvent(
            event_id=str(uuid4())[:8],
            title=title,
            severity=severity,
            source=source,
            description=description
        )
        self.threats[threat.event_id] = threat
        return threat.to_dict()
    
    def get_active_threats(self) -> List[Dict[str, Any]]:
        """Get active threats"""
        return [t.to_dict() for t in self.threats.values()]
    
    def get_metrics(
        self,
        metric_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Get metrics"""
        metrics = self.metrics.values()
        if metric_type:
            metrics = [m for m in metrics if m.metric_type.value == metric_type]
        return [m.to_dict() for m in metrics]
    
    def create_dashboard(
        self,
        name: str,
        widgets: List[Dict[str, Any]],
        refresh_interval: int = 60
    ) -> Dict[str, Any]:
        """Create a dashboard"""
        config = DashboardConfig(
            config_id=str(uuid4())[:8],
            name=name,
            widgets=widgets,
            refresh_interval=refresh_interval
        )
        self.dashboards[config.config_id] = config
        return config.to_dict()
    
    def get_dashboard(self, config_id: str) -> Optional[Dict[str, Any]]:
        """Get a dashboard"""
        config = self.dashboards.get(config_id)
        return config.to_dict() if config else None
    
    def get_command_center_dashboard(self) -> Dict[str, Any]:
        """Get the main command center dashboard"""
        threat_level = ThreatLevel.GREEN
        
        if len(self.threats) > 10:
            threat_level = ThreatLevel.RED
        elif len(self.threats) > 5:
            threat_level = ThreatLevel.ORANGE
        elif len(self.threats) > 0:
            threat_level = ThreatLevel.YELLOW
        
        type_metrics: Dict[str, int] = {}
        for m in self.metrics.values():
            type_metrics[m.metric_type.value] = type_metrics.get(m.metric_type.value, 0) + 1
        
        return {
            "threat_level": threat_level.value,
            "active_threats": len(self.threats),
            "total_metrics": len(self.metrics),
            "metrics_by_type": type_metrics,
            "dashboards_configured": len(self.dashboards),
            "timestamp": datetime.utcnow().isoformat()
        }


_command_center_service: Optional[CommandCenterService] = None

def get_command_center_service() -> CommandCenterService:
    """Get the global service instance"""
    global _command_center_service
    if _command_center_service is None:
        _command_center_service = CommandCenterService()
    return _command_center_service