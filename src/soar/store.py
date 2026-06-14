import threading
from typing import Dict, List, Optional
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
)

class SOARStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.incidents: Dict[str, Incident] = {}
        self.playbooks: Dict[str, Playbook] = {}
        self.investigations: Dict[str, Investigation] = {}
        self.response_actions: Dict[str, ResponseAction] = {}
        self.correlations: Dict[str, ThreatCorrelation] = {}
        self.containment_actions: Dict[str, ContainmentAction] = {}
        self.workflows: Dict[str, WorkflowExecution] = {}
        self.enrichments: Dict[str, CaseEnrichment] = {}
        self.audit_records: List[AuditRecord] = []

    def reset(self) -> None:
        with self._lock:
            self.incidents.clear()
            self.playbooks.clear()
            self.investigations.clear()
            self.response_actions.clear()
            self.correlations.clear()
            self.containment_actions.clear()
            self.workflows.clear()
            self.enrichments.clear()
            self.audit_records.clear()

    # --- Incidents ---
    def add_incident(self, incident: Incident) -> None:
        with self._lock:
            self.incidents[incident.incident_id] = incident

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        with self._lock:
            return self.incidents.get(incident_id)

    def list_incidents(self) -> List[Incident]:
        with self._lock:
            return list(self.incidents.values())

    def update_incident(self, incident: Incident) -> None:
        with self._lock:
            self.incidents[incident.incident_id] = incident

    # --- Playbooks ---
    def add_playbook(self, playbook: Playbook) -> None:
        with self._lock:
            self.playbooks[playbook.playbook_id] = playbook

    def get_playbook(self, playbook_id: str) -> Optional[Playbook]:
        with self._lock:
            return self.playbooks.get(playbook_id)

    def list_playbooks(self) -> List[Playbook]:
        with self._lock:
            return list(self.playbooks.values())

    # --- Investigations ---
    def add_investigation(self, investigation: Investigation) -> None:
        with self._lock:
            self.investigations[investigation.investigation_id] = investigation

    def get_investigation(self, investigation_id: str) -> Optional[Investigation]:
        with self._lock:
            return self.investigations.get(investigation_id)

    def get_investigation_by_incident(self, incident_id: str) -> Optional[Investigation]:
        with self._lock:
            for inv in self.investigations.values():
                if inv.incident_id == incident_id:
                    return inv
            return None

    def list_investigations(self) -> List[Investigation]:
        with self._lock:
            return list(self.investigations.values())

    def update_investigation(self, investigation: Investigation) -> None:
        with self._lock:
            self.investigations[investigation.investigation_id] = investigation

    # --- Response Actions ---
    def add_response_action(self, action: ResponseAction) -> None:
        with self._lock:
            self.response_actions[action.action_id] = action

    def get_response_action(self, action_id: str) -> Optional[ResponseAction]:
        with self._lock:
            return self.response_actions.get(action_id)

    def list_response_actions(self) -> List[ResponseAction]:
        with self._lock:
            return list(self.response_actions.values())

    def update_response_action(self, action: ResponseAction) -> None:
        with self._lock:
            self.response_actions[action.action_id] = action

    # --- Correlations ---
    def add_correlation(self, correlation: ThreatCorrelation) -> None:
        with self._lock:
            self.correlations[correlation.correlation_id] = correlation

    def get_correlation(self, correlation_id: str) -> Optional[ThreatCorrelation]:
        with self._lock:
            return self.correlations.get(correlation_id)

    def list_correlations(self) -> List[ThreatCorrelation]:
        with self._lock:
            return list(self.correlations.values())

    # --- Containment Actions ---
    def add_containment_action(self, action: ContainmentAction) -> None:
        with self._lock:
            self.containment_actions[action.containment_id] = action

    def get_containment_action(self, containment_id: str) -> Optional[ContainmentAction]:
        with self._lock:
            return self.containment_actions.get(containment_id)

    def list_containment_actions(self) -> List[ContainmentAction]:
        with self._lock:
            return list(self.containment_actions.values())

    def update_containment_action(self, action: ContainmentAction) -> None:
        with self._lock:
            self.containment_actions[action.containment_id] = action

    # --- Workflows ---
    def add_workflow_execution(self, workflow: WorkflowExecution) -> None:
        with self._lock:
            self.workflows[workflow.execution_id] = workflow

    def get_workflow_execution(self, execution_id: str) -> Optional[WorkflowExecution]:
        with self._lock:
            return self.workflows.get(execution_id)

    def list_workflow_executions(self) -> List[WorkflowExecution]:
        with self._lock:
            return list(self.workflows.values())

    def update_workflow_execution(self, workflow: WorkflowExecution) -> None:
        with self._lock:
            self.workflows[workflow.execution_id] = workflow

    # --- Case Enrichment ---
    def add_enrichment(self, enrichment: CaseEnrichment) -> None:
        with self._lock:
            self.enrichments[enrichment.entity_id] = enrichment

    def get_enrichment(self, entity_id: str) -> Optional[CaseEnrichment]:
        with self._lock:
            return self.enrichments.get(entity_id)

    # --- Audit Records ---
    def add_audit_record(self, record: AuditRecord) -> None:
        with self._lock:
            self.audit_records.append(record)

    def list_audit_records(self) -> List[AuditRecord]:
        with self._lock:
            return list(self.audit_records)
