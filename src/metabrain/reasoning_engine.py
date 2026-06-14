"""MetaBrain Global Reasoning Engine"""
from typing import Any, Dict, List, Optional
from uuid import uuid4
from .models import IntelligenceSignal, StrategicInsight, AnalysisType, IntelligenceLevel

class ReasoningEngine:
    """Global reasoning engine for cross-domain analysis"""
    
    def __init__(self) -> None:
        self.signals: Dict[str, IntelligenceSignal] = {}
        self.correlation_rules: List[Dict[str, Any]] = []
        self._init_correlation_rules()
    
    def _init_correlation_rules(self) -> None:
        """Initialize cross-domain correlation rules"""
        self.correlation_rules = [
            {
                "name": "Fraud-CTI Correlation",
                "trigger_domains": ["FRAUD", "CYBER_THREAT"],
                "severity_boost": 1.5
            },
            {
                "name": "Insider-Compliance Correlation",
                "trigger_domains": ["INSIDER_RISK", "COMPLIANCE"],
                "severity_boost": 1.3
            },
            {
                "name": "Financial Crime Pattern",
                "trigger_domains": ["FRAUD", "FINANCIAL_CRIME"],
                "severity_boost": 1.4
            }
        ]
    
    def add_signal(self, signal: IntelligenceSignal) -> str:
        """Add intelligence signal to the reasoning engine"""
        self.signals[signal.signal_id] = signal
        return signal.signal_id
    
    def correlate_signals(self) -> List[StrategicInsight]:
        """Correlate signals across domains to generate insights"""
        insights: List[StrategicInsight] = []
        
        # Group signals by type
        signals_by_type: Dict[str, List[IntelligenceSignal]] = {}
        for signal in self.signals.values():
            if signal.signal_type.value not in signals_by_type:
                signals_by_type[signal.signal_type.value] = []
            signals_by_type[signal.signal_type.value].append(signal)
        
        # Check correlation rules
        for rule in self.correlation_rules:
            matching_signals = []
            for domain in rule["trigger_domains"]:
                if domain in signals_by_type:
                    matching_signals.extend(signals_by_type[domain])
            
            if len(matching_signals) >= 2:
                avg_confidence = sum(s.confidence for s in matching_signals) / len(matching_signals)
                insight = StrategicInsight(
                    insight_id=str(uuid4()),
                    title=f"Cross-Domain Pattern: {rule['name']}",
                    description=f"Detected correlation between {', '.join(rule['trigger_domains'])} signals",
                    intelligence_level=IntelligenceLevel.OPERATIONAL,
                    affected_domains=rule["trigger_domains"],
                    recommended_actions=["Investigate correlated signals", "Update detection rules"],
                    priority=1,
                    confidence=avg_confidence * rule["severity_boost"]
                )
                insights.append(insight)
        
        return insights
    
    def analyze_threat_landscape(self) -> Dict[str, Any]:
        """Analyze the overall threat landscape"""
        severity_counts: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        type_counts: Dict[str, int] = {}
        
        for signal in self.signals.values():
            severity_counts[signal.severity] = severity_counts.get(signal.severity, 0) + 1
            type_counts[signal.signal_type.value] = type_counts.get(signal.signal_type.value, 0) + 1
        
        return {
            "total_signals": len(self.signals),
            "severity_distribution": severity_counts,
            "type_distribution": type_counts,
            "threat_level": self._calculate_threat_level(severity_counts)
        }
    
    def _calculate_threat_level(self, severity_counts: Dict[str, int]) -> str:
        """Calculate overall threat level"""
        weighted_score = (
            severity_counts.get("CRITICAL", 0) * 4 +
            severity_counts.get("HIGH", 0) * 3 +
            severity_counts.get("MEDIUM", 0) * 2 +
            severity_counts.get("LOW", 0) * 1
        )
        if weighted_score > 20:
            return "CRITICAL"
        elif weighted_score > 10:
            return "HIGH"
        elif weighted_score > 5:
            return "MEDIUM"
        return "LOW"
    
    def get_insights_by_level(self, level: IntelligenceLevel) -> List[StrategicInsight]:
        """Get insights filtered by intelligence level"""
        insights = self.correlate_signals()
        return [i for i in insights if i.intelligence_level == level]