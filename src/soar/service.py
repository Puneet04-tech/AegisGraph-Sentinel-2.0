import logging
from typing import List, Dict, Any, Optional
from src.soar.store import SOARStore
from src.soar.audit import SOARAuditLogger
from src.soar.orchestrator import IncidentOrchestrator
from src.soar.playbook_engine import PlaybookEngine
from src.soar.investigation_engine import InvestigationEngine
from src.soar.response_engine import ResponseEngine
from src.soar.correlation_engine import SOARCorrelationEngine
from src.soar.enrichment_engine import EnrichmentEngine
from src.soar.containment_engine import ContainmentEngine
from src.soar.notification_engine import NotificationEngine
from src.soar.workflow_engine import WorkflowEngine
from src.soar.models import (
    Incident,
    Playbook,
    Investigation,
    ResponseAction,
    ThreatCorrelation,
    ContainmentAction,
    WorkflowExecution,
    CaseEnrichment,
    AuditRecord,
    ThreatSeverity,
    IncidentStatus,
    ResponseActionType,
    ContainmentType,
    ActionStatus,
    WorkflowState,
)

logger = logging.getLogger("aegis.soar.service")

class SOARService:
    def __init__(self, store: Optional[SOARStore] = None) -> None:
        self.store = store or SOARStore()
        self.audit_logger = SOARAuditLogger(self.store)
        
        self.enrichment_engine = EnrichmentEngine(self.store, self.audit_logger)
        self.response_engine = ResponseEngine(self.store, self.audit_logger)
        self.containment_engine = ContainmentEngine(self.store, self.audit_logger)
        self.notification_engine = NotificationEngine(self.store, self.audit_logger)
        self.investigation_engine = InvestigationEngine(self.store, self.audit_logger)
        self.correlation_engine = SOARCorrelationEngine(self.store, self.audit_logger)
        
        self.workflow_engine = WorkflowEngine(
            self.store,
            self.audit_logger,
            response_engine=self.response_engine,
            enrichment_engine=self.enrichment_engine,
            containment_engine=self.containment_engine,
            notification_engine=self.notification_engine,
        )
        
        self.playbook_engine = PlaybookEngine(
            self.store,
            self.audit_logger,
            workflow_engine=self.workflow_engine,
        )
        
        self.orchestrator = IncidentOrchestrator(
            self.store,
            self.audit_logger,
            playbook_engine=self.playbook_engine,
        )

    # --- Incidents ---
    def create_incident(
        self,
        title: str,
        description: str,
        severity: ThreatSeverity,
        source: str,
        entities: List[str] = None,
        metadata: Dict[str, Any] = None
    ) -> Incident:
        return self.orchestrator.create_incident(title, description, severity, source, entities, metadata)

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        return self.store.get_incident(incident_id)

    def list_incidents(self) -> List[Incident]:
        return self.store.list_incidents()

    def update_incident_status(self, incident_id: str, status: IncidentStatus, user_id: str = "SYSTEM") -> Optional[Incident]:
        return self.orchestrator.update_incident_status(incident_id, status, user_id)

    # --- Playbooks ---
    def register_playbook(
        self,
        name: str,
        description: str,
        version: str,
        tasks: List[Dict[str, Any]],
        rules: Dict[str, Any]
    ) -> Playbook:
        return self.playbook_engine.register_playbook(name, description, version, tasks, rules)

    def get_playbook(self, playbook_id: str) -> Optional[Playbook]:
        return self.store.get_playbook(playbook_id)

    def list_playbooks(self) -> List[Playbook]:
        return self.store.list_playbooks()

    def execute_playbook(self, playbook_id: str, incident_id: str) -> Optional[WorkflowExecution]:
        return self.playbook_engine.execute_playbook(playbook_id, incident_id)

    # --- Investigations ---
    def start_investigation(self, incident_id: str) -> Optional[Investigation]:
        return self.investigation_engine.start_investigation(incident_id)

    def get_investigation(self, investigation_id: str) -> Optional[Investigation]:
        return self.store.get_investigation(investigation_id)

    def list_investigations(self) -> List[Investigation]:
        return self.store.list_investigations()

    def add_analyst_note(self, investigation_id: str, note: str, user_id: str = "ANALYST") -> Optional[Investigation]:
        return self.investigation_engine.add_analyst_note(investigation_id, note, user_id)

    # --- Response Actions ---
    def execute_action(
        self,
        action_type: ResponseActionType,
        target_id: str,
        executed_by: str,
        additional_params: Optional[Dict[str, Any]] = None
    ) -> ResponseAction:
        return self.response_engine.execute_action(action_type, target_id, executed_by, additional_params)

    def list_response_actions(self) -> List[ResponseAction]:
        return self.store.list_response_actions()

    # --- Containment ---
    def trigger_containment(
        self,
        containment_type: ContainmentType,
        target_entity: str,
        initiated_by: str,
        duration_seconds: Optional[int] = None
    ) -> ContainmentAction:
        return self.containment_engine.trigger_containment(containment_type, target_entity, initiated_by, duration_seconds)

    def release_containment(self, containment_id: str, released_by: str) -> Optional[ContainmentAction]:
        return self.containment_engine.release_containment(containment_id, released_by)

    def list_containment_actions(self) -> List[ContainmentAction]:
        return self.store.list_containment_actions()

    # --- Correlation ---
    def correlate_incidents(
        self,
        name: str,
        incident_ids: List[str],
        entities: List[str]
    ) -> ThreatCorrelation:
        return self.correlation_engine.correlate_incidents(name, incident_ids, entities)

    def list_correlations(self) -> List[ThreatCorrelation]:
        return self.store.list_correlations()

    # --- Auditing ---
    def list_audit_records(self) -> List[AuditRecord]:
        return self.store.list_audit_records()

    # --- Dashboard Stats ---
    def get_dashboard_stats(self) -> Dict[str, Any]:
        incidents = self.store.list_incidents()
        containments = self.store.list_containment_actions()
        workflows = self.store.list_workflow_executions()
        
        status_counts = {"NEW": 0, "INVESTIGATING": 0, "CONTAINED": 0, "CLOSED": 0}
        severity_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        
        for inc in incidents:
            status_counts[inc.status] = status_counts.get(inc.status, 0) + 1
            severity_counts[inc.severity] = severity_counts.get(inc.severity, 0) + 1
            
        return {
            "total_incidents": len(incidents),
            "status_distribution": status_counts,
            "severity_distribution": severity_counts,
            "active_containments": len([c for c in containments if c.status == ActionStatus.COMPLETED]),
            "running_workflows": len([w for w in workflows if w.state == WorkflowState.RUNNING]),
            "total_audit_records": len(self.store.list_audit_records())
        }
