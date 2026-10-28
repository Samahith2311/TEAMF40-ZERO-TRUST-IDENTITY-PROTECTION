# Product Requirements Document (PRD): Track 2 Zero Trust for Everyone

## 1. Product Thesis
"An identity-risk engine that stitches Okta sessions to CloudTrail API activity into one provenance-labeled attack chain, scores it with a transparent privilege-and-sensitivity-weighted model, and picks the least-disruptive simulated response the evidence justifies."

- **U1**: Stitching with basis/confidence/provenance (`LABEL_DERIVED` | `VALIDATED_OBSERVATION` | `ANALYTICAL_INFERENCE`).
- **U2**: Additive factor-by-factor score; breakdown = explanation.
- **U3**: Per alert: top-3 contributing factors (upgrade: computed counterfactual).
- **U4**: Response: risk-tier action table (upgrade: minimize expected loss, numbers shown; cost tables ASSUMPTION).
- **U5**: Evidence verifier: re-resolves every cited `(source_file, record_id)` against RAW data, prints % valid.
- **U6**: Streaming replay with per-event and end-to-end latency, plus incident dedupe.

---

## 2. Definitions
- **Continuous Scoring**: Re-score the identity and session on EVERY event in timestamp order with recency decay; replay emits a score time series.
- **Dormant Identity**: Inactivity gap > `max(30 days [ASSUMPTION], p95 inter-activity gap for that identity)`.
- **Reporting Separation**: Event-level evaluation, identity-level evaluation, and session-level evaluation are measured and outputted as separate evaluation metrics.
- **Validation vs Legitimacy**: Passing schema validation does not imply benign legitimacy, and failing schema validation does not imply malicious attack. Structural failures are routed to `validation_results` and quarantined, distinct from security detection.
- **Evidence Provenance**:
  - `LABEL_DERIVED`: Direct label linkage provided by training/benchmark datasets.
  - `VALIDATED_OBSERVATION`: Exact deterministic matching across raw fields (e.g. source IP + timestamp window + session ID).
  - `ANALYTICAL_INFERENCE`: Heuristic or probabilistic correlation across disparate signals.

---

## 3. Milestones & Acceptance Checks

| Milestone | Scope | Observable Acceptance Check |
|---|---|---|
| **M1: Ingest & Normalize** | Ingest Okta and CloudTrail logs, validate structure/timestamps, normalize fields, dedupe | One command ingests both sources; report separates "failed validation" from "suspicious"; re-ingest = 0 new rows. |
| **M2: Five Detectors** | Dormant account, token/session abuse, privilege escalation, unusual API calls, impossible travel | Harness prints event-level P/R/F1 per detector beside baseline; delta and sample counts printed. |
| **M3: Stitching & Chains** | Link Okta session to CloudTrail principal; reconstruct attack sequence | Known sample attack chain reconstructed end-to-end with provenance-labeled links; score breakdown sums to total. |
| **M4: Alerts & Response** | Deduplicated alerts with evidence refs, hash-chained audit, policy simulator adapter | Each alert contains what/who/why/evidence/breakdown/impact/action; verifier prints 100% valid; simulator receives action, response logged. |
| **M5: Dashboard** | React + Vite + TS + Tailwind web interface | Alert queue, chain timeline with provenance styles, risk breakdown, and response panel load real pipeline output from FastAPI; log strings inert. |

---

## 4. Frozen Data Contract

Each contract object maps to a dedicated MongoDB collection:

### `normalized_events`
- `event_id`: string (UUID or canonical source ID)
- `source`: string (`okta` | `cloudtrail`)
- `source_file`: string
- `record_ref`: string / integer
- `ts_utc`: string (ISO8601 UTC)
- `ts_original_tz`: string
- `identity_key`: string (normalized corporate email or ARN)
- `principal_raw`: string
- `session_id`: string (nullable)
- `ip`: string
- `geo`: object `{city: string, country: string, lat: float, lon: float}`
- `user_agent`: string
- `action`: string
- `resource`: string
- `outcome`: string (`SUCCESS` | `FAILURE` | `UNKNOWN`)
- `privilege_context`: object `{role: string, clearance: int, admin: bool}`
- `raw_hash`: string (SHA-256 of raw line)
- `validation`: object `{status: string, reasons: [string]}`

### `validation_results`
- `record_ref`: string
- `structural_ok`: boolean
- `timestamp_ok`: boolean
- `order_ok`: boolean
- `duplicate_of`: string (nullable)
- `identity_ref_ok`: boolean
- `reasons`: array of strings

### `identity_links`
- `link_id`: string
- `from_subject`: string (Okta identity or session)
- `to_subject`: string (AWS IAM principal)
- `basis`: array of strings (`["ip_match", "session_correlation", "temporal_proximity"]`)
- `confidence`: float (0.0 to 1.0)
- `provenance`: string (`LABEL_DERIVED` | `VALIDATED_OBSERVATION` | `ANALYTICAL_INFERENCE`)

### `risk_scores`
- `subject`: object `{type: "identity" | "session", id: string}`
- `total`: integer (0-100, clamped)
- `factors`: array of objects `{name: string, weight: float, value: float, contribution: float, evidence_refs: [{source_file: string, record_id: string}]}`
- `explanation`: object `{top_factors: [string], counterfactual: string (optional)}`

### `alerts`
- `alert_id`: string
- `incident_id`: string
- `subject`: object `{type: string, id: string}`
- `severity`: string (`LOW` | `MEDIUM` | `HIGH` | `CRITICAL`)
- `what`: string
- `why`: string
- `evidence_refs`: array of objects `{source_file: string, record_id: string}`
- `risk_score_ref`: string
- `impact`: string
- `recommended_action`: string (`MONITOR` | `STEP_UP` | `REVOKE_SESSION` | `RESTRICT`)
- `status`: string (`OPEN` | `INVESTIGATING` | `RESOLVED` | `DISMISSED`)
- `first_seen`: string (ISO8601 UTC)
- `last_seen`: string (ISO8601 UTC)
- `dup_count`: integer

### `incident_chains`
- `incident_id`: string
- `stages`: array of objects `{stage: string, event_ref: string, link_provenance: string}`
- `links`: array of strings (link_ids)
- `subject_ids`: array of strings
- `confidence`: float
- `unresolved`: array of strings

### `simulator_actions`
- `action_id`: string
- `incident_id`: string
- `action`: string (`MONITOR` | `STEP_UP` | `REVOKE_SESSION` | `RESTRICT`)
- `target`: string
- `expected_loss`: object `{disruption_cost: float, breach_risk: float}`
- `approval`: object `{required: bool, by: string, ts: string}`
- `preview`: string
- `result`: string
- `rollback`: string
- `label`: string (`SIMULATED` | `MOCKED`)

### `audit_logs`
- `log_id`: string
- `prev_hash`: string
- `curr_hash`: string
- `ts_utc`: string
- `actor`: string
- `action`: string
- `details`: object

### `eval_results`
- `level`: string (`event` | `identity` | `session` | `chain`)
- `detector`: string
- `tp`: integer
- `fp`: integer
- `fn`: integer
- `precision`: float
- `recall`: float
- `f1`: float
- `baseline`: object `{precision: float, recall: float, f1: float}`
- `delta`: object `{precision: float, recall: float, f1: float}`
- `split`: string
- `n`: integer
- `label`: string (`VERIFIED` | `MOCKED` | `NOT RUN`)
- `latency`: object `{p50_ms: float, p95_ms: float, p99_ms: float}`
- `evidence_ref_valid_pct`: float

---

## 5. Factor Weights & Scoring Model [ASSUMPTION]

Total Risk Score is additive and strictly bounded in $[0, 100]$:
$$\text{Score} = \min\left(100, \sum_{i=1}^k w_i \cdot v_i \cdot \delta_{\text{recency}}\right)$$

| Factor Name | Weight ($w_i$) | Value Metric ($v_i \in [0, 100]$) | Basis / Description |
|---|---|---|---|
| `behavioral_anomaly` | 0.25 | Anomaly deviation score | Dormant reactivation, unusual hours, or anomalous API velocity |
| `privilege_level` | 0.20 | Base clearance of identity | Higher clearance (Admin / root) carries higher baseline risk weight |
| `privilege_delta` | 0.25 | Grant magnitude | Dynamic escalation (e.g. `AttachAdminPolicy`, new access keys) |
| `resource_sensitivity` | 0.15 | Target classification | Sensitive buckets, IAM policies, or KMS cryptographic keys |
| `sequence_stage` | 0.15 | Multi-step attack chain progress | Single event vs advanced kill-chain stage (credential reuse -> exfil) |

- **Recency Decay**: $\delta_{\text{recency}} = e^{-\lambda \Delta t}$, with half-life set to 4 hours ($\lambda = \frac{\ln 2}{4 \text{ hours}}$).

---

## 6. Risk-Tier Action Table [ASSUMPTION]

| Score Band | Severity | Action | Approval Required | Safeguard / Restriction |
|---|---|---|---|---|
| **0 – 29** | `LOW` | `MONITOR` | No (Auto) | Log event to telemetry stream |
| **30 – 59** | `MEDIUM` | `STEP_UP` | No (Auto) | Trigger MFA prompt simulation; log user prompt |
| **60 – 84** | `HIGH` | `REVOKE_SESSION` | Yes (Analyst) | Invalidate active Okta and AWS temporary session tokens |
| **85 – 100** | `CRITICAL` | `RESTRICT` | Yes (Senior Analyst) | Quarantine identity; never auto-restrict protected accounts (break-glass/admin) |

---

## 7. Rule-Spec Table (5 Detectors)

| Rule ID | Detector | Source | Selection | Condition | Window | Known FPs | Target Level |
|---|---|---|---|---|---|---|---|
| `DET-01` | Dormant Account Reactivation | Okta / CloudTrail | `eventType == user.session.start` or API call | Inactivity gap $> \max(30\text{d}, p95)$ | Rolling 90d history | Legitimate contractor returning from leave | Identity |
| `DET-02` | Token & Session Abuse | CloudTrail | `sts:AssumeRole` or reused token | Mismatched ASN/IP or concurrent sessions in divergent regions | 15 minutes | Cloud developer switching VPN endpoints | Session |
| `DET-03` | Privilege Escalation Chain | CloudTrail | `iam:Attach*`, `iam:CreateAccessKey`, `iam:Put*` | Principal with clearance $\le 2$ elevating to clearance $\ge 4$ | 60 minutes | Authorized DevOps deployment pipelines | Identity |
| `DET-04` | Unusual API Calls | CloudTrail | S3/DynamoDB/SecretsManager reads | High-velocity calls outside top-90% histogram profile | 30 minutes | Periodic automated backup / data sync jobs | Session |
| `DET-05` | Impossible Travel | Okta | `user.session.start` | Great-circle speed between successive logins $> 800\text{ km/h}$ | 2 hours | Split-tunnel VPNs or cellular egress gateways | Identity |

---

## 8. Cut Order

If time is constrained, features are dropped strictly in this order:
1. **Stretch features**: Attack graph SVG visualization & dynamic feedback weights.
2. **Dashboard visual polish**: Animations, responsive fine-tuning, complex filters.
3. **Timeline view**: Collapse multi-step visual timeline to simple tabular list.
4. **Counterfactual calculation**: Drop dynamic counterfactual explanation, retaining top-3 factor explanations.
5. **NEVER CUT**: Evaluation harness, evidence resolution verifier (U5), cross-source stitching, attack chain reconstruction.

---

## 9. Dependency List & Rationale

| Dependency | Category | Rationale |
|---|---|---|
| `fastapi` | Backend | High-performance asynchronous API framework for read-only pipeline endpoints |
| `uvicorn` | Backend | Lightweight ASGI production server for FastAPI |
| `pymongo` | Database | Official MongoDB driver for atomic collection queries and schema validations |
| `mongomock` | Testing | In-memory MongoDB mock for isolated fast logic unit tests |
| `pydantic` | Data Validation | Strict data contracts and JSON schema generation |
| `pytest` | Testing | Standard test runner for security invariants and acceptance checks |
| `react` & `react-dom` | Frontend | Core declarative UI rendering |
| `vite` | Frontend | Fast, deterministic frontend build tool |
| `typescript` | Frontend | Strict type safety mirroring backend PRD contract |
| `tailwindcss` | Frontend | Utility-first CSS styling without heavy component library bloat |
