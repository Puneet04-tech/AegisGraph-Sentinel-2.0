# AegisGraph Sentinel Enterprise - Agent Memory

## Project Context
AegisGraph Sentinel 2.0 is a real-time fraud detection platform using HTGNN (Heterogeneous Temporal Graph Neural Networks) for mule account detection. The goal is to transform this into an Enterprise SaaS platform with multi-tenancy, billing, AI agents, and enterprise integrations.

## Project Structure
- `/src/api/` - FastAPI service
- `/src/models/` - HTGNN neural network models
- `/src/data/` - Data generation and graph building
- `/src/features/` - Feature extraction (biometrics, velocity, honeypot, etc.)
- `/src/training/` - Training pipeline
- `/src/inference/` - Risk scoring and explanation
- `/src/security/` - Security modules
- `/src/audit/` - Audit trail
- `/src/case_management/` - Case management
- `/src/observability/` - Monitoring/observability
- `/tests/` - Unit tests

## Key Technologies
- PyTorch, PyTorch Geometric for HTGNN
- Neo4j for graph database
- Redis for caching
- FastAPI for API
- Kafka for streaming (production)
- Kubernetes for orchestration

## Current Authentication
- Simple API key-based auth (`X-API-Key` header)
- `SUPER_ADMIN` as default key

## Enterprise SaaS Roadmap
1. **S1**: Production Cloud Infrastructure (AWS, Azure, GCP, Terraform, Kubernetes)
2. **S2**: Multi-Tenant SaaS Platform (Organization Management, Workspace Isolation)
3. **S3**: Enterprise Identity & Access (SSO, SAML, OAuth2, OIDC, RBAC, ABAC, MFA)
4. **S4**: Enterprise Billing & Licensing (Stripe, Usage Metering)
5. **S5**: Advanced AI Agent Platform
6. **S6**: Enterprise Integrations (Splunk, Sentinel, Elastic, ServiceNow, Jira, Slack, Teams)
7. **S7**: Executive Command Center
8. **S8**: Mobile Applications
9. **S9**: Research & Patent Program
10. **S10**: Commercial Release

## Important Notes
- Use `invoke_skill(name="kubernetes")` for Kubernetes setup
- Use `invoke_skill(name="security")` for security best practices
- Target deployment: https://work-1-vrxmuomdlqeldoad.prod-runtime.all-hands.dev/