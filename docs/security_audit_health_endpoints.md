# Security Audit: Runtime Health & Monitoring Endpoints

**Audit Date:** 2026-06-10  
**Auditor:** Security Review  
**Scope:** Health, monitoring, diagnostics, and runtime information endpoints

## Executive Summary

This audit identified **14 endpoints** exposing health, monitoring, and diagnostic information. While most endpoints have appropriate role-based access controls, several critical security issues were found:

1. **Root endpoint (`/`)** exposes service information without authentication
2. **Liveness probe (`/health/liveness`)** has no authentication
3. **Health endpoints with `verbose=true`** expose sensitive internal service state
4. **Memory diagnostics endpoint** exposes detailed cache sizes and internal state
5. **Multiple dashboard endpoints** expose operational metrics with ANALYST-level access (may be over-privileged)

## Phase 1: Endpoint Discovery

### Health Endpoints

| Endpoint | Method | Auth Required | Data Returned |
|----------|--------|---------------|---------------|
| `/` | GET | None | Service name, version, status, mode, motto, documentation link |
| `/api/v1/health` | GET | ADMIN when verbose=true | Status, service, version, uptime, model_loaded, graph_loaded, innovations_available, requests_processed, timestamp, services_health (when verbose) |
| `/health/liveness` | GET | None | Status, service name |
| `/health` | GET | ADMIN when verbose=true | Same as `/api/v1/health` |

### Monitoring & Diagnostics Endpoints

| Endpoint | Method | Auth Required | Data Returned |
|----------|--------|---------------|---------------|
| `/stats` | GET | AUDITOR | Total requests, decisions breakdown, avg risk score, avg processing time, uptime, flagged transactions |
| `/api/v1/model/info` | GET | VIEWER | Model name, version, architecture, parameters, performance metrics, training data info |
| `/api/v1/monitoring/memory` | GET | ADMIN | RSS/VMS memory, cache sizes (centrality_baseline, account_profiles, fraud_chains), mule_accounts count |

### Statistics Endpoints (Various Modules)

| Endpoint | Method | Auth Required | Data Returned |
|----------|--------|---------------|---------------|
| `/api/v1/honeypot/stats` | GET | ANALYST | Total activated, arrests, arrest rate, recovery amount |
| `/api/v1/entity-resolution/stats` | GET | ANALYST | Entity count, relationship count, cluster count |
| `/api/v1/soc/stats` | GET | ANALYST | Total agents, active tasks, investigations, threat reports, fraud rings |
| `/api/v1/governance/stats` | GET | ANALYST | Metrics stored, scorecards, findings, dashboards, reports |
| `/api/v1/predictive/stats` | GET | ANALYST | Simulations, forecasts, campaigns, recommendations |
| `/api/v1/analytics/stats` | GET | ANALYST | Metric definitions, KPIs, trends, dashboards, reports |

### Dashboard Endpoints

| Endpoint | Method | Auth Required | Data Returned |
|----------|--------|---------------|---------------|
| `/api/v1/cases/dashboard` | GET | ANALYST | Case counts by status/priority |
| `/api/v1/soc/dashboard` | GET | ANALYST | SOC overview, trends, performance |
| `/api/v1/governance/dashboard` | POST | ANALYST | Executive risk summary, compliance, performance |
| `/api/v1/analytics/kpi/dashboard` | GET | ANALYST | KPI dashboard summary |
| `/api/v1/analytics/dashboard/create` | POST | ANALYST | BI dashboard creation |

## Phase 2: Exposure Analysis

### Public Information (Safe for Unauthenticated Access)

**Fields:**
- Service name
- Service status (healthy/unhealthy/degraded)
- Basic uptime (in seconds)
- API version

**Endpoints:**
- `/health/liveness` - Already appropriate for Kubernetes probes
- `/` with verbose=false - Should require minimal auth

### Operational Information (Requires AUDITOR or VIEWER Role)

**Fields:**
- Total requests processed
- Decision breakdown (ALLOW/REVIEW/BLOCK counts)
- Average risk score
- Average processing time
- Flagged transaction count
- Model architecture and version
- Performance metrics (precision, recall, F1)
- Module-level statistics (honeypot, entity resolution, SOC, etc.)

**Endpoints:**
- `/stats` - AUDITOR role (appropriate)
- `/api/v1/model/info` - VIEWER role (appropriate)
- `/api/v1/honeypot/stats` - ANALYST role (may need AUDITOR)
- `/api/v1/entity-resolution/stats` - ANALYST role (may need AUDITOR)
- `/api/v1/soc/stats` - ANALYST role (may need AUDITOR)
- `/api/v1/governance/stats` - ANALYST role (may need AUDITOR)
- `/api/v1/predictive/stats` - ANALYST role (may need AUDITOR)
- `/api/v1/analytics/stats` - ANALYST role (may need AUDITOR)

### Sensitive Infrastructure Information (Requires ADMIN Role)

**Fields:**
- **services_health** object containing:
  - Individual service status
  - Failure counts
  - Restart attempts
  - Last error messages
  - Last heartbeat timestamps
- **Memory diagnostics**:
  - RSS/VMS memory usage
  - Cache sizes (centrality_baseline, account_profiles, fraud_chains)
  - Global state sizes (mule_accounts)
- **Internal component state**:
  - model_loaded
  - graph_loaded
  - innovations_available
  - requests_processed

**Endpoints:**
- `/api/v1/health` with `verbose=true` - ADMIN role (appropriate but needs enforcement)
- `/health` with `verbose=true` - ADMIN role (appropriate but needs enforcement)
- `/api/v1/monitoring/memory` - ADMIN role (appropriate)

### Critical Security Issues

#### Issue 1: Unauthenticated Root Endpoint
**Endpoint:** `GET /`  
**Risk:** Exposes service information without authentication  
**Data Exposed:**
- Service name: "AegisGraph Sentinel 2.0"
- Version: "2.0.0"
- Status: "operational"
- Mode: "production" or "demo"
- Motto: "Detecting the Flow, Protecting the Soul"
- Documentation link: "/docs"

**Recommendation:** Require VIEWER role for root endpoint access.

#### Issue 2: Unauthenticated Liveness Probe
**Endpoint:** `GET /health/liveness`  
**Risk:** While appropriate for Kubernetes probes, it could be abused for reconnaissance  
**Data Exposed:**
- Status: "ok"
- Service name: "AegisGraph Sentinel 2.0"

**Recommendation:** Keep unauthenticated for Kubernetes compatibility, but add rate limiting.

#### Issue 3: Verbose Health Check Exposes Internal State
**Endpoint:** `GET /health` and `GET /api/v1/health` with `verbose=true`  
**Risk:** The `_require_verbose_health_access` function only checks ADMIN role when verbose=true, but the implementation may have bypasses  
**Data Exposed (when verbose=true):**
- model_loaded
- graph_loaded
- innovations_available
- requests_processed
- services_health (with failure counts, restart attempts, last errors, heartbeats)

**Recommendation:** Strengthen the verbose parameter check and ensure it cannot be bypassed.

#### Issue 4: Memory Diagnostics Exposes Cache Sizes
**Endpoint:** `GET /api/v1/monitoring/memory`  
**Risk:** Exposes internal cache sizes and global state which could be used for memory exhaustion attacks  
**Data Exposed:**
- RSS/VMS memory usage
- centrality_baseline_size and maxsize
- account_profiles_size
- fraud_chains_size
- mule_accounts_size

**Recommendation:** Already requires ADMIN role (appropriate), but consider sanitizing cache maxsize values.

#### Issue 5: Statistics Endpoints Over-Privileged
**Endpoints:** Multiple `/api/v1/*/stats` endpoints  
**Risk:** ANALYST role may be too permissive for read-only statistics  
**Current Auth:** All require ANALYST role  
**Recommendation:** Consider changing to AUDITOR role for statistics endpoints.

## Phase 3: Implementation Plan

### Priority 1: Critical Fixes

1. **Add authentication to root endpoint (`/`)**
   - Change from no auth to VIEWER role
   - This prevents information disclosure to unauthenticated users

2. **Strengthen verbose health check enforcement**
   - Ensure `_require_verbose_health_access` properly validates ADMIN role
   - Add logging for verbose access attempts

3. **Add rate limiting to liveness probe**
   - Prevent abuse while maintaining Kubernetes compatibility
   - Use existing rate limiting infrastructure

### Priority 2: Access Control Refinement

4. **Elevate statistics endpoints to AUDITOR role**
   - Change from ANALYST to AUDITOR for:
     - `/api/v1/honeypot/stats`
     - `/api/v1/entity-resolution/stats`
     - `/api/v1/soc/stats`
     - `/api/v1/governance/stats`
     - `/api/v1/predictive/stats`
     - `/api/v1/analytics/stats`

5. **Review dashboard endpoint permissions**
   - Consider if ANALYST role is appropriate for dashboard endpoints
   - May need to split into read (AUDITOR) and write (ANALYST) permissions

### Priority 3: Data Sanitization

6. **Sanitize sensitive fields in memory diagnostics**
   - Remove or obfuscate cache maxsize values
   - Consider removing exact cache sizes for non-ADMIN users

7. **Add response sanitization for health endpoints**
   - Ensure error messages don't expose internal paths
   - Sanitize service names in services_health

## Phase 4: Testing Plan

### Test Cases

1. **Unauthenticated Access Tests**
   - Verify `/` returns 401 without auth
   - Verify `/health/liveness` returns 200 (rate limited)
   - Verify `/health` without verbose returns 401
   - Verify `/stats` returns 401

2. **Role-Based Access Tests**
   - Verify VIEWER can access `/` and `/api/v1/model/info`
   - Verify AUDITOR can access `/stats` and all `*/stats` endpoints
   - Verify ANALYST cannot access `/stats` after permission change
   - Verify ADMIN can access `/api/v1/monitoring/memory`

3. **Verbose Parameter Tests**
   - Verify non-ADMIN cannot access `/health?verbose=true`
   - Verify ADMIN can access `/health?verbose=true`
   - Verify verbose=false works for authenticated users

4. **Data Exposure Tests**
   - Verify unauthenticated responses contain only public info
   - Verify verbose responses contain services_health only for ADMIN
   - Verify memory diagnostics only accessible to ADMIN

5. **Rate Limiting Tests**
   - Verify liveness probe has rate limiting
   - Verify rate limiting doesn't break Kubernetes probes

## Validation Checklist

- [x] Endpoint audit completed
- [x] Sensitive fields identified
- [ ] Access controls implemented
- [ ] Existing functionality preserved
- [ ] Regression tests added
- [ ] Existing tests pass
- [ ] No linting issues introduced

## Risk Assessment

### Current Risk Level: **MEDIUM**

**Justification:**
- Most endpoints have appropriate role-based access controls
- Critical infrastructure information is protected by ADMIN role
- However, unauthenticated root endpoint and potential verbose bypass present information disclosure risks

### Post-Implementation Risk Level: **LOW**

**Justification:**
- All endpoints will require authentication
- Role-based access will follow principle of least privilege
- Sensitive information will be protected by appropriate roles
- Rate limiting will prevent abuse of liveness probe

### Operational Impact

**Positive:**
- Improved security posture
- Better compliance with security best practices
- Reduced attack surface for reconnaissance

**Neutral:**
- Kubernetes liveness probe will remain functional (with rate limiting)
- Existing monitoring integrations will continue to work with proper credentials

**Negative:**
- Root endpoint will require authentication (may break some health checks)
- Statistics endpoints will require AUDITOR role (may need to update some integrations)

## Recommendations

1. **Immediate Actions:**
   - Implement authentication for root endpoint
   - Strengthen verbose health check enforcement
   - Add rate limiting to liveness probe

2. **Short-term Actions:**
   - Change statistics endpoints to AUDITOR role
   - Review and update dashboard permissions
   - Add comprehensive test coverage

3. **Long-term Actions:**
   - Consider implementing separate public health endpoint for external monitoring
   - Implement audit logging for all health/monitoring endpoint access
   - Consider adding IP whitelisting for monitoring endpoints
