"""
Asynchronous Bulk Graph Ingestion Router for AegisGraph Sentinel 2.0
"""

import asyncio
import csv
import io
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import networkx as nx
from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile

from src.api.schemas import (
    BulkIngestRequest,
    BulkIngestResponse,
    BulkIngestStatusResponse,
    BulkTaskProgress,
)
from src.api.security import Role, require_role

logger = logging.getLogger(__name__)


# Helper to coerce values to proper Python types from CSV string
def parse_value(val: str) -> Any:
    val_clean = val.strip()
    val_lower = val_clean.lower()
    if val_lower == "true":
        return True
    if val_lower == "false":
        return False
    if val_lower in ("none", "null", ""):
        return None
    try:
        if "." in val_clean:
            return float(val_clean)
        return int(val_clean)
    except ValueError:
        return val_clean


class BulkIngestionManager:
    """Manages asynchronous bulk ingestion tasks with an in-memory queue."""

    def __init__(self):
        self.tasks: Dict[str, Dict[str, Any]] = {}
        self._queue: Optional[asyncio.Queue] = None
        self.worker_task: Optional[asyncio.Task] = None
        self._lock_obj: Optional[asyncio.Lock] = None
        self.testing = False

    @property
    def queue(self) -> asyncio.Queue:
        if self._queue is None:
            self._queue = asyncio.Queue()
        return self._queue

    @property
    def _lock(self) -> asyncio.Lock:
        if self._lock_obj is None:
            self._lock_obj = asyncio.Lock()
        return self._lock_obj

    def start_worker(self):
        """Start the background worker task if it's not already running."""
        if self.testing:
            return
        if self.worker_task is None or self.worker_task.done():
            self.worker_task = asyncio.create_task(self._worker())
            logger.info("Bulk Ingestion background worker started.")

    async def stop_worker(self):
        """Cancel and clean up the background worker task."""
        if self.worker_task:
            self.worker_task.cancel()
            try:
                await self.worker_task
            except asyncio.CancelledError:
                pass
            self.worker_task = None
            logger.info("Bulk Ingestion background worker stopped.")
        # Reset the queue and lock so that new ones are created for new event loops in tests
        self._queue = None
        self._lock_obj = None

    async def create_task(
        self,
        nodes: List[Dict[str, Any]],
        edges: List[Dict[str, Any]],
        initial_errors: List[str] = None,
    ) -> str:
        """Create a task entry, queue it for execution, and return its ID."""
        task_id = str(uuid.uuid4())
        task_info = {
            "task_id": task_id,
            "status": "pending",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "completed_at": None,
            "progress": {
                "total_items": len(nodes)
                + len(edges)
                + (len(initial_errors) if initial_errors else 0),
                "successful_items": 0,
                "failed_items": len(initial_errors) if initial_errors else 0,
            },
            "errors": list(initial_errors) if initial_errors else [],
        }
        async with self._lock:
            self.tasks[task_id] = task_info

        await self.queue.put((task_id, nodes, edges))
        self.start_worker()
        return task_id

    def get_task_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve task information by UUID."""
        return self.tasks.get(task_id)

    async def _worker(self):
        """Infinite loop consuming ingestion tasks from the queue."""
        while True:
            try:
                task_id, nodes, edges = await self.queue.get()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error reading from Bulk Ingestion Queue: {e}")
                await asyncio.sleep(0.1)  # Yield control to prevent CPU spinning
                continue

            async with self._lock:
                if task_id in self.tasks:
                    self.tasks[task_id]["status"] = "processing"

            try:
                await self._process_ingestion(task_id, nodes, edges)
            except Exception as e:
                logger.error(f"Exception processing bulk ingestion task {task_id}: {e}")
                async with self._lock:
                    if task_id in self.tasks:
                        self.tasks[task_id]["status"] = "failed"
                        self.tasks[task_id]["errors"].append(
                            f"Internal processing failure: {e}"
                        )
                        self.tasks[task_id]["completed_at"] = datetime.now(
                            timezone.utc
                        ).isoformat()
            finally:
                self.queue.task_done()

    async def _process_ingestion(
        self, task_id: str, nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]]
    ):
        """Parse lists of nodes/edges and insert them safely into the global graph state."""
        from src.api.main import state

        # Ensure graph is initialized
        if getattr(state, "transaction_graph", None) is None:
            state.transaction_graph = nx.DiGraph()
            state.graph_loaded = True
            logger.info("Initializing new in-memory transaction graph.")

        success_count = 0
        failed_count = 0
        errors = []

        # Access state lock for thread-safe NetworkX updates
        lock = getattr(state, "_centrality_lock", None)

        # Process Nodes
        for i, node_data in enumerate(nodes):
            try:
                node_id = node_data.get("id") or node_data.get("node_id")
                if not node_id:
                    raise ValueError("Missing 'id' or 'node_id'")

                node_type = (
                    node_data.get("type") or node_data.get("node_type") or "Account"
                )
                properties = node_data.get("properties") or {}
                if not isinstance(properties, dict):
                    properties = {}

                node_attrs = {"type": node_type, **properties}

                if lock:
                    with lock:
                        state.transaction_graph.add_node(node_id, **node_attrs)
                else:
                    state.transaction_graph.add_node(node_id, **node_attrs)
                success_count += 1

            except Exception as e:
                failed_count += 1
                errors.append(f"Node element {i} corrupt: {e}")

            if i % 100 == 0:
                await asyncio.sleep(0)

        # Process Edges
        for i, edge_data in enumerate(edges):
            try:
                source = edge_data.get("source") or edge_data.get("from_node")
                target = edge_data.get("target") or edge_data.get("to_node")
                if not source or not target:
                    raise ValueError("Missing 'source' or 'target' endpoint node IDs")

                edge_type = (
                    edge_data.get("type") or edge_data.get("edge_type") or "Transfer"
                )
                properties = edge_data.get("properties") or {}
                if not isinstance(properties, dict):
                    properties = {}

                edge_attrs = {"type": edge_type, **properties}

                if lock:
                    with lock:
                        if not state.transaction_graph.has_node(source):
                            state.transaction_graph.add_node(source, type="Account")
                        if not state.transaction_graph.has_node(target):
                            state.transaction_graph.add_node(target, type="Account")
                        state.transaction_graph.add_edge(source, target, **edge_attrs)
                else:
                    if not state.transaction_graph.has_node(source):
                        state.transaction_graph.add_node(source, type="Account")
                    if not state.transaction_graph.has_node(target):
                        state.transaction_graph.add_node(target, type="Account")
                    state.transaction_graph.add_edge(source, target, **edge_attrs)
                success_count += 1

            except Exception as e:
                failed_count += 1
                errors.append(f"Edge element {i} corrupt: {e}")

            if i % 100 == 0:
                await asyncio.sleep(0)

        async with self._lock:
            if task_id in self.tasks:
                task = self.tasks[task_id]
                task["progress"]["successful_items"] += success_count
                task["progress"]["failed_items"] += failed_count
                task["errors"].extend(errors)
                task["status"] = (
                    "completed"
                    if task["progress"]["failed_items"]
                    < task["progress"]["total_items"]
                    else "failed"
                )
                task["completed_at"] = datetime.now(timezone.utc).isoformat()


# Global ingestion manager instance
bulk_ingestion_manager = BulkIngestionManager()

router = APIRouter(prefix="/api/v1/bulk", tags=["Bulk Ingestion"])


@router.post(
    "/ingest",
    response_model=BulkIngestResponse,
    summary="Ingest bulk graph data via JSON",
    description="Asynchronously loads a payload containing lists of nodes and edges into the graph.",
    dependencies=[Depends(require_role(Role.ANALYST))],
)
async def ingest_bulk_json(payload: BulkIngestRequest):
    """Submit JSON nodes and edges payload to the bulk ingestion background queue."""
    nodes = [n.model_dump() for n in payload.nodes] if payload.nodes else []
    edges = [e.model_dump() for e in payload.edges] if payload.edges else []

    if not nodes and not edges:
        raise HTTPException(
            status_code=400,
            detail="Request payload must contain at least one node or edge to ingest.",
        )

    task_id = await bulk_ingestion_manager.create_task(nodes, edges)
    return BulkIngestResponse(
        task_id=task_id,
        status="pending",
        message="Bulk ingestion task submitted successfully.",
    )


@router.post(
    "/ingest/file",
    response_model=BulkIngestResponse,
    summary="Ingest bulk graph data via CSV or JSON file",
    description="Accepts a CSV or JSON file and processes it asynchronously.",
    dependencies=[Depends(require_role(Role.ANALYST))],
)
async def ingest_bulk_file(
    file: UploadFile = File(...),
    data_type: str = Query(
        "auto",
        enum=["auto", "nodes", "edges"],
        description="CSV Ingestion type override",
    ),
):
    """Parse CSV/JSON file uploads and submit them to the queue."""
    filename_lower = file.filename.lower() if file.filename else ""
    content_type_lower = file.content_type.lower() if file.content_type else ""

    nodes = []
    edges = []
    initial_errors = []

    try:
        # Parse JSON
        if filename_lower.endswith(".json") or "json" in content_type_lower:
            data = json.load(file.file)
            payload = BulkIngestRequest.model_validate(data)
            nodes = [n.model_dump() for n in payload.nodes] if payload.nodes else []
            edges = [e.model_dump() for e in payload.edges] if payload.edges else []

    # Parse CSV
        else:
            import codecs
            reader = csv.DictReader(codecs.iterdecode(file.file, "utf-8"))
            if not reader.fieldnames:
                raise ValueError("CSV file is empty or lacks column headers.")

            # Normalize headers
            headers_lower = [h.lower().strip() for h in reader.fieldnames if h]

            # Detect node vs edge CSV
            is_edge = False
            if data_type == "edges":
                is_edge = True
            elif data_type == "nodes":
                is_edge = False
            else:
                # auto-detect
                if "source" in headers_lower and "target" in headers_lower:
                    is_edge = True
                elif "from_node" in headers_lower and "to_node" in headers_lower:
                    is_edge = True

            if is_edge:
                # Parse Edges
                for idx, row in enumerate(reader, start=1):
                    row_lower = {
                        k.lower().strip() if k else "": v for k, v in row.items()
                    }
                    source = (
                        row_lower.get("source")
                        or row_lower.get("from_node")
                        or row_lower.get("from")
                    )
                    target = (
                        row_lower.get("target")
                        or row_lower.get("to_node")
                        or row_lower.get("to")
                    )

                    if not source or not target:
                        initial_errors.append(
                            f"Row {idx} error: missing source/target node identifier"
                        )
                        continue

                    edge_type = (
                        row_lower.get("type")
                        or row_lower.get("edge_type")
                        or "Transfer"
                    )

                    # Gather other columns as properties
                    properties = {}
                    for k, v in row.items():
                        if k is None or v is None:
                            continue
                        k_clean = k.strip()
                        k_lower = k_clean.lower()
                        if k_lower not in (
                            "source",
                            "from_node",
                            "from",
                            "target",
                            "to_node",
                            "to",
                            "type",
                            "edge_type",
                        ):
                            properties[k_clean] = parse_value(v)

                    edges.append(
                        {
                            "source": str(source).strip(),
                            "target": str(target).strip(),
                            "type": str(edge_type).strip(),
                            "properties": properties,
                        }
                    )
            else:
                # Parse Nodes
                for idx, row in enumerate(reader, start=1):
                    row_lower = {
                        k.lower().strip() if k else "": v for k, v in row.items()
                    }
                    node_id = row_lower.get("id") or row_lower.get("node_id")

                    if not node_id:
                        # fallback: first non-empty value in row
                        non_empty_keys = [k for k in row.keys() if k]
                        if non_empty_keys:
                            node_id = row[non_empty_keys[0]]

                    if not node_id:
                        initial_errors.append(f"Row {idx} error: missing node ID")
                        continue

                    node_type = (
                        row_lower.get("type") or row_lower.get("node_type") or "Account"
                    )

                    # Gather other columns as properties
                    properties = {}
                    for k, v in row.items():
                        if k is None or v is None:
                            continue
                        k_clean = k.strip()
                        k_lower = k_clean.lower()
                        if k_lower not in ("id", "node_id", "type", "node_type"):
                            properties[k_clean] = parse_value(v)

                    nodes.append(
                        {
                            "id": str(node_id).strip(),
                            "type": str(node_type).strip(),
                            "properties": properties,
                        }
                    )

    except Exception as e:
        if isinstance(e, HTTPException):
            raise
        raise HTTPException(
            status_code=400, detail=f"Failed to parse uploaded file: {e}"
        )

    if not nodes and not edges and not initial_errors:
        raise HTTPException(
            status_code=400, detail="The uploaded file contains no node or edge data."
        )

    task_id = await bulk_ingestion_manager.create_task(nodes, edges, initial_errors)
    return BulkIngestResponse(
        task_id=task_id,
        status="pending",
        message="Bulk ingestion file task submitted successfully.",
    )


@router.get(
    "/status/{task_id}",
    response_model=BulkIngestStatusResponse,
    summary="Poll status of bulk ingestion task",
    description="Retrieve execution state, processed elements counts, and skipped row error messages.",
    dependencies=[Depends(require_role(Role.ANALYST))],
)
async def get_bulk_ingest_status(task_id: str):
    """Return task state or raise 404 if invalid UUID."""
    task_info = bulk_ingestion_manager.get_task_status(task_id)
    if not task_info:
        raise HTTPException(
            status_code=404, detail=f"Bulk ingestion task with ID {task_id} not found."
        )

    progress = BulkTaskProgress(
        total_items=task_info["progress"]["total_items"],
        successful_items=task_info["progress"]["successful_items"],
        failed_items=task_info["progress"]["failed_items"],
    )

    return BulkIngestStatusResponse(
        task_id=task_info["task_id"],
        status=task_info["status"],
        created_at=task_info["created_at"],
        completed_at=task_info["completed_at"],
        progress=progress,
        errors=task_info["errors"],
    )
