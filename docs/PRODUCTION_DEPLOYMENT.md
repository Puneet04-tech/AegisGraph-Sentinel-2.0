# AegisGraph Sentinel Enterprise - Production Deployment Guide

## Version 2.0 | June 2026

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Infrastructure Setup](#infrastructure-setup)
3. [Kubernetes Deployment](#kubernetes-deployment)
4. [Helm Chart Installation](#helm-chart-installation)
5. [Post-Deployment Configuration](#post-deployment-configuration)
6. [Monitoring & Alerting](#monitoring--alerting)
7. [Disaster Recovery](#disaster-recovery)

---

## Prerequisites

### System Requirements

- **Kubernetes Cluster**: 1.28+
- **Helm**: 3.12+
- **kubectl**: 1.28+
- **Terraform**: 1.5+

### Cloud Requirements

#### AWS
- EKS cluster (3+ nodes)
- RDS PostgreSQL 15+
- ElastiCache Redis 7+
- S3 buckets for storage
- ACM certificates

#### Azure
- AKS cluster (3+ nodes)
- Azure Database for PostgreSQL
- Azure Cache for Redis
- Azure Blob Storage
- Application Gateway

#### GCP
- GKE cluster (3+ nodes)
- Cloud SQL for PostgreSQL
- Memorystore Redis
- Cloud Storage
- Cloud Load Balancing

---

## Infrastructure Setup

### Terraform Configuration

```bash
# Clone infrastructure repository
git clone https://github.com/aegisgraph/infrastructure.git
cd infrastructure/terraform

# Initialize Terraform
terraform init

# Plan deployment
terraform plan -var-file=environments/prod.tfvars

# Apply infrastructure
terraform apply -var-file=environments/prod.tfvars
```

### Environment Variables

Create `environments/prod.tfvars`:

```hcl
environment = "production"
cluster_name = "aegisgraph-prod"
node_count = 5
instance_type = "m5.xlarge"
db_password = "your-secure-password"
redis_password = "your-secure-password"
domain_name = "aegisgraph.com"
```

---

## Kubernetes Deployment

### 1. Cluster Preparation

```bash
# Update kubeconfig
aws eks update-kubeconfig --region us-east-1 --name aegisgraph-prod

# Verify cluster access
kubectl get nodes

# Install essential add-ons
kubectl apply -f addons/cert-manager.yaml
kubectl apply -f addons/metrics-server.yaml
kubectl apply -f addons/nginx-ingress.yaml
```

### 2. Namespace Creation

```bash
# Create production namespace
kubectl create namespace aegisgraph

# Apply network policies
kubectl apply -f network-policies.yaml
```

### 3. Secrets Configuration

```bash
# Create secrets from secrets manager
kubectl create secret generic aegisgraph-secrets \
  --from-literal=API_KEY="your-api-key" \
  --from-literal=NEO4J_PASSWORD="your-password" \
  --from-literal=REDIS_PASSWORD="your-password" \
  --from-literal=JWT_SECRET="your-jwt-secret" \
  --namespace=aegisgraph

# Create TLS certificate (if using cert-manager)
kubectl apply -f certificates/production.yaml
```

### 4. Persistent Volume Claims

```bash
# Create storage class (if not using default)
kubectl apply -f storage/gp3-storage-class.yaml

# Create PVCs
kubectl apply -f storage/postgresql-pvc.yaml
kubectl apply -f storage/redis-pvc.yaml
kubectl apply -f storage/neo4j-pvc.yaml
kubectl apply -f storage/models-pvc.yaml
```

---

## Helm Chart Installation

### 1. Add Helm Repository

```bash
# Add AegisGraph Helm repository
helm repo add aegisgraph https://charts.aegisgraph.com
helm repo update
```

### 2. Configure Values

Create `values-production.yaml`:

```yaml
# Cluster configuration
replicaCount: 3

# Image configuration
image:
  repository: aegisgraph/sentinel-api
  tag: "2.0.0"
  pullPolicy: Always

# Service configuration
service:
  type: ClusterIP
  port: 80
  grpcPort: 50051

# Ingress configuration
ingress:
  enabled: true
  className: "nginx"
  annotations:
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
  hosts:
    - host: api.aegisgraph.com
      paths:
        - path: /
          pathType: Prefix
          service: api
    - host: dashboard.aegisgraph.com
      paths:
        - path: /
          pathType: Prefix
          service: dashboard

# Resource limits
resources:
  api:
    limits:
      cpu: 2000m
      memory: 4Gi
      nvidia.com/gpu: 1
    requests:
      cpu: 1000m
      memory: 2Gi

# Autoscaling
autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 10
  targetCPUUtilizationPercentage: 70

# Application configuration
config:
  api:
    url: "https://api.aegisgraph.com"
    logLevel: "info"
    device: "cuda"
  database:
    host: "postgresql"
    port: 5432
    name: "aegisgraph"
    poolSize: 20
  redis:
    host: "redis-master"
    port: 6379
    db: 0
  neo4j:
    uri: "bolt://neo4j:7687"
  kafka:
    bootstrapServers: "kafka:9092"
  ml:
    modelPath: "/models/htgnn_best.pt"
    batchSize: 32
    maxLatencyMs: 200

# Monitoring
monitoring:
  enabled: true
  prometheus:
    port: 9090
  grafana:
    adminUser: "admin"

# PostgreSQL
postgresql:
  enabled: true
  auth:
    database: "aegisgraph"
    username: "aegisgraph"

# Redis
redis:
  enabled: true
  auth:
    enabled: true
```

### 3. Install Chart

```bash
# Install with values file
helm install aegisgraph aegisgraph/aegisgraph \
  --namespace aegisgraph \
  --values values-production.yaml \
  --set security.apiKey="your-api-key" \
  --set security.jwtSecret="your-jwt-secret" \
  --timeout 10m

# Verify installation
helm list -n aegisgraph
kubectl get pods -n aegisgraph
```

### 4. Verify Deployment

```bash
# Check pod status
kubectl get pods -n aegisgraph -l app=aegisgraph-sentinel

# Check services
kubectl get svc -n aegisgraph

# Check ingress
kubectl get ingress -n aegisgraph

# Check logs
kubectl logs -n aegisgraph -l app=aegisgraph-sentinel --tail=100

# Port-forward for local testing
kubectl port-forward -n aegisgraph svc/aegisgraph-api 8000:80
```

---

## Post-Deployment Configuration

### 1. DNS Configuration

```bash
# Get ingress IP/hostname
kubectl get ingress -n aegisgraph -o jsonpath='{.items[0].status.loadBalancer.ingress[0]}'

# Configure DNS (update your DNS provider)
# A record: api.aegisgraph.com -> <ingress-ip>
# A record: dashboard.aegisgraph.com -> <ingress-ip>
```

### 2. SSL Certificate Verification

```bash
# Check certificate status
kubectl get certificate -n aegisgraph

# Describe certificate for details
kubectl describe certificate -n aegisgraph

# Verify SSL endpoint
curl -v https://api.aegisgraph.com/health
```

### 3. Database Migration

```bash
# Run database migrations
kubectl exec -n aegisgraph -it deployment/aegisgraph-api -- python -m src.db.migrate

# Verify database connectivity
kubectl exec -n aegisgraph -it deployment/aegisgraph-api -- python -c "from src.db import engine; print('DB connected')"
```

### 4. Model Loading

```bash
# Copy model to PVC
kubectl cp models/htgnn_best.pt aegisgraph/$(kubectl get pod -n aegisgraph -l component=api -o jsonpath='{.items[0].metadata.name}'):/models/

# Verify model loading
kubectl exec -n aegisgraph -it deployment/aegisgraph-api -- python -c "from src.models import HTGNN; print('Model loaded')"
```

### 5. SSO Configuration

```bash
# Configure SSO providers (update values)
helm upgrade aegisgraph aegisgraph/aegisgraph \
  --namespace aegisgraph \
  --set config.sso.google.enabled=true \
  --set config.sso.google.clientId="your-client-id" \
  --set config.sso.okta.enabled=true \
  --set config.sso.okta.domain="your-domain.okta.com"
```

### 6. Load Testing

```bash
# Run load test
kubectl run load-test --image=wrk:latest --restart=Never -- \
  -t12 -c400 -d30s https://api.aegisgraph.com/api/v1/health

# Monitor performance
kubectl top pods -n aegisgraph
```

---

## Monitoring & Alerting

### 1. Prometheus Setup

```bash
# Verify Prometheus targets
kubectl get servicemonitors -n aegisgraph

# Check Prometheus UI
kubectl port-forward -n monitoring svc/prometheus-server 9090:9090
```

### 2. Grafana Dashboards

```bash
# Import dashboards
kubectl apply -f dashboards/aegisgraph-dashboard.json

# Access Grafana
kubectl port-forward -n monitoring svc/grafana 3000:3000
```

### 3. Alert Configuration

```bash
# Apply alert rules
kubectl apply -f alerts/production-alerts.yaml

# Verify alert rules
kubectl get prometheusrules -n aegisgraph
```

### 4. Key Metrics to Monitor

| Metric | Alert Threshold | Action |
|--------|-----------------|--------|
| API Latency (p99) | > 200ms | Scale up pods |
| Error Rate | > 1% | Investigate logs |
| CPU Usage | > 80% | Scale up nodes |
| Memory Usage | > 85% | Scale up pods |
| Pod Restarts | > 5 in 10min | Investigate |
| Queue Depth | > 1000 | Increase workers |

---

## Disaster Recovery

### 1. Backup Configuration

```bash
# Enable automated backups (PostgreSQL)
kubectl apply -f backup/postgres-backup.yaml

# Enable automated backups (Neo4j)
kubectl apply -f backup/neo4j-backup.yaml

# Configure Redis RDB persistence
kubectl apply -f backup/redis-backup.yaml
```

### 2. Backup Schedule

| Component | Frequency | Retention |
|-----------|-----------|-----------|
| PostgreSQL | Daily + WAL | 30 days |
| Neo4j | Daily | 30 days |
| Redis | Hourly RDB | 7 days |
| Model Files | Weekly | 12 weeks |
| Configuration | On change | Git |

### 3. Recovery Procedures

#### Database Recovery

```bash
# Restore PostgreSQL
kubectl exec -n aegisgraph postgresql-0 -- pg_restore --dbname=aegisgraph --clean /backups/latest.dump

# Restore Neo4j
kubectl exec -n aegisgraph neo4j-0 -- neo4j-admin database restore --overwrite-destination=true /backups/latest
```

#### Full Cluster Recovery

```bash
# Use Terraform for infrastructure recovery
cd infrastructure/terraform
terraform apply -var-file=environments/prod.tfvars

# Reinstall Helm chart
helm install aegisgraph aegisgraph/aegisgraph --namespace aegisgraph --values values-production.yaml
```

### 4. Runbook

**High CPU Alert**:
1. Check which pods are affected: `kubectl top pods -n aegisgraph`
2. Check for memory leaks: `kubectl describe pods -n aegisgraph`
3. Scale up if needed: `kubectl scale deployment aegisgraph-api --replicas=6 -n aegisgraph`
4. Check logs for errors: `kubectl logs -n aegisgraph -l app=aegisgraph-sentinel --tail=500`

**Database Connection Issues**:
1. Check PostgreSQL status: `kubectl exec -n aegisgraph postgresql-0 -- pg_isready`
2. Check connection pool: `kubectl exec -n aegisgraph deployment/aegisgraph-api -- curl localhost:8000/metrics | grep db_pool`
3. Restart if needed: `kubectl rollout restart deployment/aegisgraph-api -n aegisgraph`

---

## Rollback Procedures

### 1. Helm Rollback

```bash
# List releases
helm history aegisgraph -n aegisgraph

# Rollback to previous version
helm rollback aegisgraph -n aegisgraph

# Rollback to specific revision
helm rollback aegisgraph -n aegisgraph --revision 3
```

### 2. Image Rollback

```bash
# Update deployment image
kubectl set image deployment/aegisgraph-api api=aegisgraph/sentinel-api:1.9.0 -n aegisgraph

# Verify rollout
kubectl rollout status deployment/aegisgraph-api -n aegisgraph
```

---

## Security Checklist

- [ ] API keys rotated
- [ ] Secrets encrypted at rest
- [ ] TLS certificates valid
- [ ] Network policies applied
- [ ] RBAC configured
- [ ] Audit logging enabled
- [ ] Vulnerability scan completed
- [ ] Penetration test passed
- [ ] DDoS protection enabled
- [ ] WAF configured

---

## Support & Troubleshooting

### Useful Commands

```bash
# Get all resources
kubectl get all -n aegisgraph

# Describe deployment
kubectl describe deployment aegisgraph-api -n aegisgraph

# Get events
kubectl get events -n aegisgraph --sort-by='.lastTimestamp'

# Check configmap
kubectl get configmap aegisgraph-config -n aegisgraph -o yaml

# Execute into pod
kubectl exec -n aegisgraph -it deployment/aegisgraph-api -- /bin/bash
```

### Support Contact

- **Documentation**: https://docs.aegisgraph.com
- **Support Portal**: https://support.aegisgraph.com
- **Emergency**: support@aegisgraph.com

---

**Document Version**: 2.0.0
**Last Updated**: June 2026