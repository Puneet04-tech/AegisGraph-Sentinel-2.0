"""MetaBrain Autonomous Recommendation Engine"""
from typing import Any, Dict, List, Optional
from uuid import uuid4
from .models import StrategicRecommendation, StrategicInsight, IntelligenceLevel

class RecommendationEngine:
    """Autonomous recommendation engine for security operations"""
    
    def __init__(self) -> None:
        self.recommendations: List[StrategicRecommendation] = []
        self.action_templates: Dict[str, Dict[str, Any]] = self._init_templates()
    
    def _init_templates(self) -> Dict[str, Dict[str, Any]]:
        """Initialize recommendation action templates"""
        return {
            "INVESTIGATE": {
                "action_type": "INVESTIGATE",
                "estimated_impact": "Medium",
                "templates": [
                    "Conduct deep investigation on {domain}",
                    "Review recent alerts in {domain}",
                    "Analyze historical patterns in {domain}"
                ]
            },
            "BLOCK": {
                "action_type": "BLOCK",
                "estimated_impact": "High",
                "templates": [
                    "Block suspicious activity in {domain}",
                    "Implement emergency controls for {domain}",
                    "Suspend high-risk operations in {domain}"
                ]
            },
            "ENHANCE": {
                "action_type": "ENHANCE",
                "estimated_impact": "High",
                "templates": [
                    "Enhance monitoring for {domain}",
                    "Strengthen detection rules for {domain}",
                    "Update ML models for {domain}"
                ]
            },
            "ALERT": {
                "action_type": "ALERT",
                "estimated_impact": "Low",
                "templates": [
                    "Alert security team about {domain}",
                    "Notify stakeholders of {domain} changes",
                    "Report {domain} status to leadership"
                ]
            }
        }
    
    def generate_recommendations(
        self,
        insights: List[StrategicInsight]
    ) -> List[StrategicRecommendation]:
        """Generate autonomous recommendations from insights"""
        recommendations: List[StrategicRecommendation] = []
        
        for insight in insights:
            if insight.priority <= 2:
                action = "BLOCK"
            elif insight.priority <= 4:
                action = "ENHANCE"
            elif insight.priority <= 6:
                action = "INVESTIGATE"
            else:
                action = "ALERT"
            
            templates = self.action_templates.get(action, {})
            template_list = templates.get("templates", [])
            
            if template_list:
                description_template = template_list[0]
                domain = ", ".join(insight.affected_domains)
                description = description_template.format(domain=domain)
            else:
                description = f"Address insight: {insight.title}"
            
            recommendation = StrategicRecommendation(
                recommendation_id=str(uuid4()),
                title=f"Action Required: {insight.title}",
                description=description,
                target_domain=", ".join(insight.affected_domains),
                action_type=action,
                estimated_impact=templates.get("estimated_impact", "Medium"),
                confidence=insight.confidence
            )
            recommendations.append(recommendation)
        
        self.recommendations.extend(recommendations)
        return recommendations
    
    def get_recommendations_by_priority(
        self,
        min_priority: int = 0,
        max_results: int = 10
    ) -> List[StrategicRecommendation]:
        """Get recommendations sorted by priority"""
        # In a real implementation, this would filter by priority
        return self.recommendations[:max_results]
    
    def get_recommendations_by_domain(self, domain: str) -> List[StrategicRecommendation]:
        """Get recommendations for a specific domain"""
        return [
            r for r in self.recommendations
            if domain.lower() in r.target_domain.lower()
        ]
    
    def get_recommendation_stats(self) -> Dict[str, Any]:
        """Get recommendation statistics"""
        action_counts: Dict[str, int] = {}
        for rec in self.recommendations:
            action_counts[rec.action_type] = action_counts.get(rec.action_type, 0) + 1
        
        return {
            "total_recommendations": len(self.recommendations),
            "action_distribution": action_counts,
            "avg_confidence": sum(r.confidence for r in self.recommendations) / len(self.recommendations) if self.recommendations else 0
        }