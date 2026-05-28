# Security Policy
 
## Reporting a Vulnerability
 
Report security issues privately via GitHub Security Advisories:
 
https://github.com/Puneet04-tech/AegisGraph-Sentinel-2.0/security/advisories/new
 
Please do not file public issues for sensitive findings. We aim to acknowledge reports within seven days.
 
## Trust Boundary
 
AegisGraph Sentinel 2.0 is designed to run inside a bank-internal network behind an authenticated edge (mTLS, OAuth proxy, or VPN). Direct internet exposure is not a supported deployment configuration.
 
The FastAPI service in `src/api/` handles:
 
- Financial transaction data (`/api/v1/fraud/check`, `/api/v1/fraud/batch`)
- Biometric audio (`/api/v1/voice/analyze`)
- Blockchain evidence (`/api/v1/blockchain/seal`, `/api/v1/blockchain/verify`, `/api/v1/blockchain/export`)
- Honeypot operational data (`/api/v1/honeypot/active`, `/api/v1/honeypot/stats`)
- Model metadata (`/api/v1/model/info`)
- Explainability output (`/api/v1/explain`, `/api/v1/oracle/explain`)
Operators are responsible for the network-level perimeter. The in-process controls described below are defence in depth, not a replacement for it.
 
## In-Process Controls
 
### API key authentication
 
All business endpoints require a valid `X-API-Key` header. Keys are stored on the server side as SHA-256 hashes in the `AEGIS_API_KEY_HASHES` environment variable (comma-separated, lowercase hex). The plaintext key is only known to clients; the server never reads or writes it.
 
The dependency `src.api.security.require_api_key` enforces this and returns:
 
- `503 Service Unavailable` if `AEGIS_API_KEY_HASHES` is unset (fail closed)
- `401 Unauthorized` if the header is missing
- `403 Forbidden` if the supplied key's hash does not match any configured hash
Public endpoints that bypass this gate: `/`, `/health`, `/api/v1/health`, `/stats`. These return service-liveness information only and are intentionally reachable by orchestrator probes without credentials.
 
### Admin token gates
 
Two endpoint groups require an additional admin token in addition to the API key:
 
- `/api/v1/honeypot/active` and `/api/v1/honeypot/stats` require `X-Honeypot-Token`, with the SHA-256 hash configured in `AEGIS_HONEYPOT_ADMIN_TOKEN_HASH`.
- `/api/v1/blockchain/export` requires `authorization_token` in the request body, with the hash in `AEGIS_LEGAL_EXPORT_TOKEN_HASH`.
These tokens use the same hash-and-compare pattern as the API key and are independently rotatable.
 
### Rate limiting
 
`slowapi` is wired in at the application level with a 100/minute per-IP default. Per-endpoint limits can be tightened in a follow-up change (`/api/v1/voice/analyze` is the most expensive endpoint and a natural candidate for a lower cap).
 
### CORS
 
Allowed origins are read from `AEGIS_ALLOWED_ORIGINS` (comma-separated). The service does not allow wildcard origins with credentials, which would let any site issue credentialed cross-origin requests.
 
### Graph artifact integrity
 
The synthetic graph artifact loaded at startup (`data/synthetic/graph.graphml`) is verified against the SHA-256 hash in `AEGIS_GRAPH_SHA256` before parsing. Startup refuses to proceed on hash mismatch.
 
## Key Rotation
 
`AEGIS_API_KEY_HASHES` accepts a list, which is what makes zero-downtime rotation possible:
 
1. Generate a new key and compute its hash:
   ```bash
   python -c "import hashlib, secrets; k = secrets.token_urlsafe(32); print('key:', k); print('hash:', hashlib.sha256(k.encode()).hexdigest())"
   ```
 
2. Add the new hash to `AEGIS_API_KEY_HASHES` alongside the existing one.
3. Restart the service. Both keys are now accepted.
4. Distribute the new key to clients and switch them over.
5. Once all clients are migrated, remove the old hash from `AEGIS_API_KEY_HASHES`.
6. Restart the service again. Only the new key is accepted from this point on.
The same procedure applies to `AEGIS_HONEYPOT_ADMIN_TOKEN_HASH` and `AEGIS_LEGAL_EXPORT_TOKEN_HASH`, except those env vars currently hold a single hash. Extending them to accept lists is a low-risk follow-up if rotation becomes operationally painful.
 
## Hardening Recommendations
 
1. **Deploy behind an authenticated edge.** API key auth is a defence-in-depth layer, not a substitute for network-level authentication. mTLS or an OAuth proxy in front of the service is the expected production posture.
2. **Generate keys with `secrets.token_urlsafe(32)` or equivalent.** Keys must be unguessable; do not use short, dictionary, or shared values.
3. **Store key hashes in your secrets manager**, not in source control or plain `.env` files committed to repos. The hashes are irreversible, but treating them as secrets reduces accidental exposure.
4. **Rotate keys at least every 90 days** — more often for high-traffic deployments or after any incident involving the operator host.
5. **Monitor 401/403 rates.** A sustained spike means either a misconfigured client or an attacker probing for valid keys; both warrant investigation. The repo's audit logger (`src.observability.get_audit_logger`) already records security actions and is the right place to plug in an alert.
6. **Restrict the orchestrator-probe network path.** The `/health` and `/stats` endpoints stay open by design but should not be reachable from outside the cluster's pod network.