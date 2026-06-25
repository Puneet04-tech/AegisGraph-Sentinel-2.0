import uuid
from datetime import datetime
from typing import Optional, List, Dict, Any
from .models import DecisionIntelligencePlatformDecisionContext, DecisionIntelligencePlatformExplainabilityReport, DecisionIntelligencePlatformRiskRecommendation
from .store import DecisionIntelligencePlatformStore


class DecisionIntelligencePlatformService:
    def __init__(self, store: DecisionIntelligencePlatformStore):
        self.store = store
        self.audit_log: List[Dict[str, Any]] = []

    def log_audit(self, tenant_id: str, action: str, details: Dict[str, Any]) -> None:
        self.audit_log.append({
            "timestamp": datetime.utcnow(),
            "tenant_id": tenant_id,
            "action": action,
            "details": details
        })

    def create_decisioncontext(self, tenant_id: str, record_id: str, decision_id: str, action_taken: str, rationales: List[str], confidence: float) -> DecisionIntelligencePlatformDecisionContext:
        item = DecisionIntelligencePlatformDecisionContext(
            record_id=record_id, tenant_id=tenant_id, decision_id=decision_id, action_taken=action_taken, rationales=rationales, confidence=confidence,
            created_at=datetime.utcnow()
        )
        self.store.save_decisioncontext(tenant_id, item)
        self.log_audit(tenant_id, f"CREATE_{'DecisionContext'.upper()}", {"record_id": record_id})
        return item

    def get_decisioncontext(self, tenant_id: str, record_id: str) -> Optional[DecisionIntelligencePlatformDecisionContext]:
        return self.store.get_decisioncontext(tenant_id, record_id)

    def list_decisioncontexts(self, tenant_id: str) -> List[DecisionIntelligencePlatformDecisionContext]:
        return self.store.list_decisioncontexts(tenant_id)

    def create_explainabilityreport(self, tenant_id: str, record_id: str, report_id: str, model_name: str, feature_importances: Dict[str, float], explanation_text: str) -> DecisionIntelligencePlatformExplainabilityReport:
        item = DecisionIntelligencePlatformExplainabilityReport(
            record_id=record_id, tenant_id=tenant_id, report_id=report_id, model_name=model_name, feature_importances=feature_importances, explanation_text=explanation_text,
            created_at=datetime.utcnow()
        )
        self.store.save_explainabilityreport(tenant_id, item)
        self.log_audit(tenant_id, f"CREATE_{'ExplainabilityReport'.upper()}", {"record_id": record_id})
        return item

    def get_explainabilityreport(self, tenant_id: str, record_id: str) -> Optional[DecisionIntelligencePlatformExplainabilityReport]:
        return self.store.get_explainabilityreport(tenant_id, record_id)

    def list_explainabilityreports(self, tenant_id: str) -> List[DecisionIntelligencePlatformExplainabilityReport]:
        return self.store.list_explainabilityreports(tenant_id)

    def create_riskrecommendation(self, tenant_id: str, record_id: str, recommendation_id: str, threat_vector: str, recommended_action: str, risk_score: float) -> DecisionIntelligencePlatformRiskRecommendation:
        item = DecisionIntelligencePlatformRiskRecommendation(
            record_id=record_id, tenant_id=tenant_id, recommendation_id=recommendation_id, threat_vector=threat_vector, recommended_action=recommended_action, risk_score=risk_score,
            created_at=datetime.utcnow()
        )
        self.store.save_riskrecommendation(tenant_id, item)
        self.log_audit(tenant_id, f"CREATE_{'RiskRecommendation'.upper()}", {"record_id": record_id})
        return item

    def get_riskrecommendation(self, tenant_id: str, record_id: str) -> Optional[DecisionIntelligencePlatformRiskRecommendation]:
        return self.store.get_riskrecommendation(tenant_id, record_id)

    def list_riskrecommendations(self, tenant_id: str) -> List[DecisionIntelligencePlatformRiskRecommendation]:
        return self.store.list_riskrecommendations(tenant_id)

def get_service() -> DecisionIntelligencePlatformService:
    from .store import get_store
    return DecisionIntelligencePlatformService(get_store())
