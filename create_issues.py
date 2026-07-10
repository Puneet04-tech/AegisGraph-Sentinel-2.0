import subprocess

issues = [
    {
        "title": "feat(api): Implement multi-tenancy context propagation in FastAPI",
        "body": """## Description
As we transition AegisGraph Sentinel to an Enterprise SaaS platform, we need to enforce multi-tenancy across all API endpoints. Currently, the system assumes a single tenant. We need to parse tenant IDs from authentication tokens and propagate them through the request context.

### Acceptance Criteria
- [ ] Create a FastAPI dependency to extract `tenant_id` from the JWT token.
- [ ] Store `tenant_id` in context variables (e.g., using `contextvars`).
- [ ] Update Neo4j and Redis database clients to append the `tenant_id` to all queries/keys.
- [ ] Document the new multi-tenant architecture in `docs/architecture/multi-tenancy.md`.

### Type of Change
- [x] Feature
- [ ] Bug Fix
- [ ] Security Enhancement
- [ ] Refactoring
- [ ] Infrastructure

### Steps to Reproduce
1. Generate a JWT token with a specific `tenant_id`.
2. Make a request to the `/api/v1/inference` endpoint.
3. Verify that the `tenant_id` is passed correctly to the underlying graph queries.

### Expected Behavior
Data isolation is strictly maintained between different tenants.
"""
    },
    {
        "title": "infra(k8s): Create Helm charts for HTGNN inference service deployment",
        "body": """## Description
To scale the real-time fraud detection inference, we need to deploy our HTGNN inference service on Kubernetes. Currently, we only have basic Dockerfiles.

### Acceptance Criteria
- [ ] Create a Helm chart for the FastAPI inference service.
- [ ] Add configurations for horizontal pod autoscaling (HPA) based on CPU and memory.
- [ ] Configure readiness and liveness probes.
- [ ] Include setup instructions in the README.

### Type of Change
- [ ] Feature
- [ ] Bug Fix
- [ ] Security Enhancement
- [ ] Refactoring
- [x] Infrastructure

### Steps to Reproduce
1. Run `helm install aegis-inference ./charts/inference`.
2. Check pod status using `kubectl get pods`.
3. Verify the HPA configuration using `kubectl get hpa`.

### Expected Behavior
The inference service can be easily deployed and autoscaled on a Kubernetes cluster.
"""
    },
    {
        "title": "feat(models): Integrate PyTorch Geometric distributed training for large graphs",
        "body": """## Description
Our transaction graph is growing beyond the memory capacity of a single GPU. We need to implement distributed training using PyTorch Geometric to train the HTGNN models on multi-GPU setups.

### Acceptance Criteria
- [ ] Refactor the training loop in `/src/training/train.py` to support `torch.distributed`.
- [ ] Implement graph partitioning logic for distributed sampling.
- [ ] Validate model convergence matches the single-GPU baseline.
- [ ] Add a tutorial notebook demonstrating multi-GPU training.

### Type of Change
- [x] Feature
- [ ] Bug Fix
- [ ] UI/UX Improvement
- [x] Performance Optimization

### Steps to Reproduce
1. Run the training script with `torchrun --nproc_per_node=2 src/training/train.py`.
2. Monitor GPU utilization on both devices.
3. Compare the evaluation metrics with the single-node baseline.

### Expected Behavior
Training scales linearly across multiple GPUs without sacrificing accuracy.
"""
    },
    {
        "title": "sec(auth): Implement OIDC/SAML SSO integration for Enterprise accounts",
        "body": """## Description
Enterprise clients require SSO capabilities (e.g., Azure AD, Okta) to manage access to the Executive Command Center.

### Acceptance Criteria
- [ ] Integrate an OIDC/SAML library (e.g., Authlib) with the FastAPI service.
- [ ] Create endpoints for SP-initiated and IdP-initiated login flows.
- [ ] Implement Role-Based Access Control (RBAC) mapping from IdP claims.
- [ ] Write integration tests for the authentication flow.

### Type of Change
- [x] Feature
- [ ] Bug Fix
- [x] Security Enhancement
- [ ] Refactoring

### Steps to Reproduce
1. Configure a mock Identity Provider (like Keycloak).
2. Attempt login via the SSO endpoint.
3. Verify successful redirection and token issuance.

### Expected Behavior
Users can authenticate seamlessly using their corporate credentials.
"""
    },
    {
        "title": "feat(features): Add real-time honeypot velocity tracking feature",
        "body": """## Description
To enhance mule account detection, we need to track the velocity of transactions interacting with known "honeypot" accounts in real-time.

### Acceptance Criteria
- [ ] Update `/src/features/extractor.py` to calculate honeypot interaction frequency over sliding windows (1h, 24h, 7d).
- [ ] Use Redis sorted sets to efficiently manage the sliding window counters.
- [ ] Pass the new velocity features to the inference model.

### Type of Change
- [x] Feature
- [ ] Integration
- [ ] Infrastructure
- [ ] Bug Fix

### Steps to Reproduce
1. Ingest a stream of transactions where multiple sender accounts interact with a single honeypot node.
2. Query the feature extraction API for those sender accounts.
3. Verify the velocity metrics accurately reflect the interaction frequency.

### Expected Behavior
The model has access to accurate, up-to-date honeypot velocity features during scoring.
"""
    },
    {
        "title": "feat(observability): Implement distributed tracing with OpenTelemetry and Jaeger",
        "body": """## Description
As the platform moves towards microservices, tracking requests across the API, Kafka, and Inference workers is difficult. We need distributed tracing.

### Acceptance Criteria
- [ ] Instrument FastAPI, Redis, and Neo4j clients with OpenTelemetry Python SDK.
- [ ] Configure an OpenTelemetry Collector to export traces to Jaeger.
- [ ] Add a unique `trace_id` to all log messages.
- [ ] Ensure trace context is propagated through Kafka headers.

### Type of Change
- [x] Feature
- [ ] Security Enhancement
- [ ] Bug Fix
- [x] Infrastructure

### Steps to Reproduce
1. Send an inference request to the API.
2. Open the Jaeger UI.
3. Search for the trace and verify it spans the API, Redis cache check, and Neo4j queries.

### Expected Behavior
Complete visibility into the lifecycle and latency of every request.
"""
    },
    {
        "title": "bug(inference): Fix memory leak in Redis caching layer during high-throughput risk scoring",
        "body": """## Description
Under high load, the memory footprint of the API service grows continuously until OOM kill. Profiling indicates the Redis connection pool in `/src/inference/cache.py` is leaking connections.

### Acceptance Criteria
- [ ] Identify and fix the connection leak in the `RedisCache` class.
- [ ] Ensure connections are properly released back to the pool.
- [ ] Add a memory profiling test to the CI pipeline to prevent regressions.

### Type of Change
- [ ] Feature
- [x] Bug Fix
- [ ] UI/UX Improvement
- [x] Performance Optimization

### Steps to Reproduce
1. Start the API service.
2. Use Locust or Apache Benchmark to send 10,000 requests/sec.
3. Monitor the memory usage of the process.

### Expected Behavior
Memory usage remains stable during high-throughput operations.
"""
    },
    {
        "title": "feat(data): Create Kafka consumer group for real-time transaction ingestion",
        "body": """## Description
To support real-time scoring, we need to ingest transaction streams directly from Kafka rather than relying on batch REST API calls.

### Acceptance Criteria
- [ ] Implement a scalable Kafka consumer in `/src/data/consumer.py` using `confluent-kafka`.
- [ ] Parse and validate incoming transaction JSON payloads.
- [ ] Push valid transactions to the Neo4j graph asynchronously.
- [ ] Implement dead-letter queue (DLQ) handling for malformed messages.

### Type of Change
- [x] Feature
- [ ] Bug Fix
- [ ] Performance Optimization
- [x] Infrastructure

### Steps to Reproduce
1. Start the Kafka broker and consumer service.
2. Produce mock transaction messages to the `transactions.raw` topic.
3. Verify the data appears correctly structured in Neo4j.

### Expected Behavior
High-throughput, resilient ingestion of streaming transaction data.
"""
    },
    {
        "title": "feat(integrations): Build Splunk forwarding module for audit trails",
        "body": """## Description
Enterprise clients use Splunk for SIEM. We need a module in `/src/audit/` to forward all security and access logs to a Splunk Http Event Collector (HEC).

### Acceptance Criteria
- [ ] Create a customized Python logging handler for Splunk HEC.
- [ ] Ensure logs are formatted in JSON with required metadata (timestamp, tenant_id, action, status).
- [ ] Implement batching and retry logic for network resilience.

### Type of Change
- [x] Feature
- [x] Integration
- [ ] Bug Fix
- [ ] Refactoring

### Steps to Reproduce
1. Configure the `SPLUNK_HEC_URL` and `SPLUNK_HEC_TOKEN` environment variables.
2. Perform actions that generate audit logs (e.g., logging in, changing model parameters).
3. Check the Splunk dashboard to verify logs are received and parsed correctly.

### Expected Behavior
Audit events are reliably delivered to enterprise SIEM systems.
"""
    },
    {
        "title": "feat(case_management): Implement drag-and-drop workflow builder for case routing",
        "body": """## Description
Fraud analysts need to define custom rules for routing cases (e.g., "If risk_score > 90 and amount > $10k, route to Senior Team").

### Acceptance Criteria
- [ ] Build a React-based UI component for building routing rules visually.
- [ ] Create API endpoints to save and retrieve workflow definitions as JSON.
- [ ] Implement an evaluation engine in `/src/case_management/` to process rules during case creation.

### Type of Change
- [x] Feature
- [ ] Bug Fix
- [x] UI/UX Improvement
- [ ] Refactoring

### Steps to Reproduce
1. Open the Case Management settings.
2. Build a new routing rule using the visual editor.
3. Trigger a risk score that matches the rule.
4. Verify the case is assigned to the correct queue.

### Expected Behavior
Non-technical users can define complex case routing logic visually.
"""
    },
    {
        "title": "test(api): Add end-to-end load testing suite using Locust",
        "body": """## Description
We need to ensure the system can meet our SLA of 50ms p99 latency under a load of 5000 RPS before the Commercial Release.

### Acceptance Criteria
- [ ] Create Locust test scripts covering the main inference and data ingestion APIs.
- [ ] Include setup and teardown hooks to populate test data in Neo4j.
- [ ] Document instructions for running the load tests in `tests/load/README.md`.

### Type of Change
- [ ] Feature
- [ ] Bug Fix
- [x] Testing
- [ ] Refactoring

### Steps to Reproduce
1. Navigate to the `tests/load` directory.
2. Run `locust -f locustfile.py --headless -u 1000 -r 100 --run-time 10m`.
3. Review the generated HTML report.

### Expected Behavior
A repeatable, automated way to benchmark system performance.
"""
    },
    {
        "title": "docs(models): Write comprehensive API documentation for HTGNN embeddings",
        "body": """## Description
To support the Research & Patent Program, we need detailed documentation on how researchers can extract and utilize the intermediate node embeddings from our HTGNN models.

### Acceptance Criteria
- [ ] Add comprehensive docstrings to the model classes in `/src/models/`.
- [ ] Create a Markdown guide explaining the embedding space and dimensions.
- [ ] Provide a Python script example demonstrating how to extract and visualize the embeddings using t-SNE or UMAP.

### Type of Change
- [ ] Feature
- [ ] Bug Fix
- [x] Documentation
- [ ] Refactoring

### Steps to Reproduce
1. Read the newly created `docs/research/embeddings.md`.
2. Run the provided example script.
3. Verify the output visualization is generated correctly.

### Expected Behavior
Clear, accessible documentation that empowers internal and external researchers.
"""
    },
    {
        "title": "perf(graph): Optimize Neo4j Cypher queries for multi-hop neighbor aggregation",
        "body": """## Description
The data extraction step for inference is currently slow when traversing transaction chains longer than 3 hops. We need to optimize the Cypher queries in `/src/data/queries.py`.

### Acceptance Criteria
- [ ] Analyze query execution plans using `EXPLAIN` and `PROFILE`.
- [ ] Introduce necessary indexes or constraints in Neo4j.
- [ ] Refactor queries to avoid Cartesian products and use path pattern matching efficiently.
- [ ] Reduce the 99th percentile query latency from 500ms to < 100ms.

### Type of Change
- [ ] Feature
- [ ] Bug Fix
- [x] Performance Optimization
- [ ] Security Enhancement

### Steps to Reproduce
1. Execute the profiling script against a populated Neo4j instance.
2. Note the execution time of the `get_multi_hop_subgraph` query.
3. Apply the optimizations and re-run the profiling script.

### Expected Behavior
Graph traversals are highly optimized, significantly speeding up the end-to-end inference time.
"""
    }
]

for i, issue in enumerate(issues):
    print(f"Creating issue {i+1}: {issue['title']}")
    try:
        subprocess.run(["gh", "issue", "create", "--title", issue["title"], "--body", issue["body"]], check=True)
        print(f"Successfully created issue {i+1}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to create issue {i+1}: {e}")
