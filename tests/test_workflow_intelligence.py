"""
Tests for Security Workflow Intelligence Platform
"""

import pytest

from src.workflow_intelligence.models import (
    Workflow,
    WorkflowTask,
    SLAMetric,
    OptimizationRecommendation,
    WorkflowType,
    WorkflowStatus,
    WorkflowPriority,
    TaskStatus,
)
from src.workflow_intelligence.store import get_workflow_store, reset_workflow_store
from src.workflow_intelligence.service import WorkflowService


class TestWorkflowModels:
    """Tests for workflow models."""

    def test_create_workflow(self):
        """Test creating a workflow."""
        workflow = Workflow(
            name="Fraud Investigation",
            description="Investigate fraud case",
            workflow_type=WorkflowType.INVESTIGATION,
            priority=WorkflowPriority.HIGH,
        )
        assert workflow.name == "Fraud Investigation"
        assert workflow.workflow_type == WorkflowType.INVESTIGATION
        assert workflow.status == WorkflowStatus.PENDING

    def test_create_workflow_task(self):
        """Test creating a workflow task."""
        task = WorkflowTask(
            workflow_id="wf-001",
            name="Review transaction",
            description="Review suspicious transaction",
            order=1,
        )
        assert task.name == "Review transaction"
        assert task.status == TaskStatus.PENDING

    def test_create_sla_metric(self):
        """Test creating an SLA metric."""
        metric = SLAMetric(
            workflow_id="wf-001",
            sla_type="completion",
            target_hours=24.0,
            actual_hours=20.0,
            is_met=True,
            variance_hours=-4.0,
        )
        assert metric.is_met is True
        assert metric.variance_hours == -4.0

    def test_create_optimization_recommendation(self):
        """Test creating an optimization recommendation."""
        rec = OptimizationRecommendation(
            recommendation_type="process_improvement",
            title="Optimize Review Process",
            description="Streamline the review workflow",
            expected_impact="Reduce time by 30%",
        )
        assert rec.recommendation_type == "process_improvement"


class TestWorkflowStore:
    """Tests for workflow store."""

    def setup_method(self):
        """Set up test store."""
        reset_workflow_store()
        self.store = get_workflow_store()

    def test_store_workflow(self):
        """Test storing a workflow."""
        workflow = Workflow(
            name="Test Workflow",
            description="Test",
            workflow_type=WorkflowType.FRAUD_REVIEW,
        )
        self.store.store_workflow(workflow)
        retrieved = self.store.get_workflow(workflow.workflow_id)
        assert retrieved is not None
        assert retrieved.name == "Test Workflow"

    def test_get_workflows_by_type(self):
        """Test getting workflows by type."""
        self.store.store_workflow(Workflow(
            name="Test",
            description="Test",
            workflow_type=WorkflowType.INVESTIGATION,
        ))
        results = self.store.get_workflows_by_type(WorkflowType.INVESTIGATION)
        assert len(results) >= 1

    def test_get_workflows_by_status(self):
        """Test getting workflows by status."""
        workflow = Workflow(
            name="Active",
            description="Test",
            workflow_type=WorkflowType.THREAT_ANALYSIS,
            status=WorkflowStatus.IN_PROGRESS,
        )
        self.store.store_workflow(workflow)
        results = self.store.get_workflows_by_status(WorkflowStatus.IN_PROGRESS)
        assert len(results) >= 1

    def test_store_task(self):
        """Test storing a task."""
        task = WorkflowTask(
            workflow_id="wf-001",
            name="Test Task",
            description="Test",
        )
        self.store.store_task(task)
        retrieved = self.store.get_task(task.task_id)
        assert retrieved is not None
        assert retrieved.name == "Test Task"

    def test_get_tasks_by_workflow(self):
        """Test getting tasks by workflow."""
        task = WorkflowTask(
            workflow_id="wf-002",
            name="Test",
            description="Test",
        )
        self.store.store_task(task)
        results = self.store.get_tasks_by_workflow("wf-002")
        assert len(results) >= 1

    def test_get_active_workflows(self):
        """Test getting active workflows."""
        workflow = Workflow(
            name="Active",
            description="Test",
            workflow_type=WorkflowType.CASE_MANAGEMENT,
            status=WorkflowStatus.IN_PROGRESS,
        )
        self.store.store_workflow(workflow)
        results = self.store.get_active_workflows()
        assert len(results) >= 1

    def test_get_metrics(self):
        """Test getting metrics."""
        self.store.store_workflow(Workflow(
            name="Test",
            description="Test",
            workflow_type=WorkflowType.OPERATIONAL,
        ))
        metrics = self.store.get_metrics()
        assert "total_workflows" in metrics
        assert metrics["total_workflows"] >= 1


class TestWorkflowService:
    """Tests for workflow service."""

    def setup_method(self):
        """Set up test service."""
        reset_workflow_store()
        self.service = WorkflowService()

    def test_create_workflow(self):
        """Test creating a workflow."""
        workflow = self.service.create_workflow(
            name="New Investigation",
            description="Investigate suspicious activity",
            workflow_type=WorkflowType.INVESTIGATION,
            priority=WorkflowPriority.HIGH,
        )
        assert workflow.workflow_id is not None
        assert workflow.name == "New Investigation"

    def test_get_workflow(self):
        """Test getting a workflow."""
        created = self.service.create_workflow(
            name="Test Workflow",
            description="Test",
            workflow_type=WorkflowType.FRAUD_REVIEW,
        )
        retrieved = self.service.get_workflow(created.workflow_id)
        assert retrieved is not None
        assert retrieved.name == "Test Workflow"

    def test_start_workflow(self):
        """Test starting a workflow."""
        workflow = self.service.create_workflow(
            name="Test",
            description="Test",
            workflow_type=WorkflowType.THREAT_ANALYSIS,
        )
        started = self.service.start_workflow(workflow.workflow_id)
        assert started is not None
        assert started.status == WorkflowStatus.IN_PROGRESS

    def test_complete_workflow(self):
        """Test completing a workflow."""
        workflow = self.service.create_workflow(
            name="Test",
            description="Test",
            workflow_type=WorkflowType.INCIDENT_RESPONSE,
        )
        self.service.start_workflow(workflow.workflow_id)
        completed = self.service.complete_workflow(workflow.workflow_id)
        assert completed is not None
        assert completed.status == WorkflowStatus.COMPLETED
        assert completed.progress_percentage == 100.0

    def test_block_workflow(self):
        """Test blocking a workflow."""
        workflow = self.service.create_workflow(
            name="Test",
            description="Test",
            workflow_type=WorkflowType.CASE_MANAGEMENT,
        )
        blocked = self.service.block_workflow(
            workflow.workflow_id,
            reason="Awaiting approval",
        )
        assert blocked is not None
        assert blocked.status == WorkflowStatus.BLOCKED

    def test_add_task(self):
        """Test adding a task to a workflow."""
        workflow = self.service.create_workflow(
            name="Test",
            description="Test",
            workflow_type=WorkflowType.GOVERNANCE_REVIEW,
        )
        task = self.service.add_task(
            workflow_id=workflow.workflow_id,
            name="Review documents",
            description="Review required documents",
            estimated_hours=2.0,
        )
        assert task is not None
        assert task.name == "Review documents"

    def test_complete_task(self):
        """Test completing a task."""
        workflow = self.service.create_workflow(
            name="Test",
            description="Test",
            workflow_type=WorkflowType.OPERATIONAL,
        )
        task = self.service.add_task(
            workflow_id=workflow.workflow_id,
            name="Test Task",
            description="Test",
        )
        completed = self.service.complete_task(task.task_id)
        assert completed is not None
        assert completed.status == TaskStatus.COMPLETED

    def test_predict_sla(self):
        """Test SLA prediction."""
        workflow = self.service.create_workflow(
            name="Test",
            description="Test",
            workflow_type=WorkflowType.COMPLIANCE_AUDIT,
            sla_hours=48.0,
        )
        self.service.add_task(
            workflow_id=workflow.workflow_id,
            name="Task 1",
            description="Test",
            estimated_hours=4.0,
        )
        prediction = self.service.predict_sla(workflow.workflow_id)
        assert "predicted_completion" in prediction
        assert "remaining_hours" in prediction

    def test_identify_bottlenecks(self):
        """Test bottleneck identification."""
        workflow = self.service.create_workflow(
            name="Blocked",
            description="Test",
            workflow_type=WorkflowType.INVESTIGATION,
        )
        self.service.block_workflow(workflow.workflow_id, reason="Test")
        bottlenecks = self.service.identify_bottlenecks()
        assert len(bottlenecks) >= 1

    def test_recommend_optimization(self):
        """Test optimization recommendations."""
        recommendations = self.service.recommend_optimization()
        assert isinstance(recommendations, list)

    def test_allocate_resource(self):
        """Test resource allocation."""
        workflow = self.service.create_workflow(
            name="Test",
            description="Test",
            workflow_type=WorkflowType.FRAUD_REVIEW,
        )
        allocation = self.service.allocate_resource(
            workflow_id=workflow.workflow_id,
            resource_type="analyst",
            resource_id="analyst-001",
            hours=8.0,
        )
        assert allocation is not None
        assert allocation.allocated_hours == 8.0

    def test_get_metrics(self):
        """Test getting metrics."""
        self.service.create_workflow(
            name="Test",
            description="Test",
            workflow_type=WorkflowType.THREAT_ANALYSIS,
        )
        metrics = self.service.get_metrics()
        assert metrics.total_workflows >= 1
        assert metrics.active_workflows >= 0


class TestWorkflowIntegration:
    """Integration tests for workflow intelligence."""

    def setup_method(self):
        """Set up test environment."""
        reset_workflow_store()
        self.service = WorkflowService()

    def test_full_workflow_lifecycle(self):
        """Test complete workflow lifecycle."""
        workflow = self.service.create_workflow(
            name="Fraud Investigation",
            description="Investigate suspicious transactions",
            workflow_type=WorkflowType.INVESTIGATION,
            priority=WorkflowPriority.HIGH,
            sla_hours=24.0,
        )

        task1 = self.service.add_task(
            workflow_id=workflow.workflow_id,
            name="Review transactions",
            description="Review all suspicious transactions",
            estimated_hours=4.0,
        )
        task2 = self.service.add_task(
            workflow_id=workflow.workflow_id,
            name="Interview stakeholders",
            description="Interview involved parties",
            estimated_hours=2.0,
        )
        task3 = self.service.add_task(
            workflow_id=workflow.workflow_id,
            name="Document findings",
            description="Document investigation findings",
            estimated_hours=1.0,
        )

        self.service.start_workflow(workflow.workflow_id)

        self.service.complete_task(task1.task_id)
        self.service.complete_task(task2.task_id)

        workflow = self.service.get_workflow(workflow.workflow_id)
        assert workflow.progress_percentage > 0

        self.service.complete_task(task3.task_id)
        completed = self.service.complete_workflow(workflow.workflow_id)
        assert completed.status == WorkflowStatus.COMPLETED

        bottlenecks = self.service.identify_bottlenecks()
        assert isinstance(bottlenecks, list)

        recommendations = self.service.recommend_optimization()
        assert isinstance(recommendations, list)

        metrics = self.service.get_metrics()
        assert metrics.total_workflows >= 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
