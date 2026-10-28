# Track 2 Architecture Audit & Baseline: Zero Trust Identity Protection

## 1. System Architecture Map

```
[ Log Inputs ]
├── fixtures/okta_sample.jsonl (Okta System Log format)
└── fixtures/cloudtrail_sample.jsonl (AWS CloudTrail JSONL format)
      │
      ▼
[ Ingestion & Normalization ] (src/ingest.py)
├── Path traversal validation (restricted to fixtures/ and data/)
├── Line size (<1MB) & file size (<50MB) boundary checks
├── SHA-256 raw line hashing & ISO8601 UTC timestamp conversion
└── Idempotent bulk upsert into MongoDB `normalized_events` with $jsonSchema
      │
      ▼
[ Five In-Scope Attack Detectors ] (src/detectors.py)
├── DET-01: Dormant Account Reactivation (inactivity gap > max(30d, p95))
├── DET-02: Token & Session Abuse (cross-IP session reuse <= 15 min)
├── DET-03: Privilege Escalation Chain (clearance <= 2 attaching AdministratorAccess)
├── DET-04: Unusual API Calls (sensitive vault access via non-standard user agents)
└── DET-05: Impossible Travel (Haversine velocity > 800 km/h between logins)
      │
      ▼
[ Identity Stitching & Incident Chains ] (src/stitching.py)
├── Okta -> CloudTrail linkage with explicit provenance:
│   - VALIDATED_OBSERVATION (direct field equality)
│   - ANALYTICAL_INFERENCE (heuristics / temporal proximity)
└── Multi-step incident chain assembly (Incident key: identity + chain + window)
      │
      ▼
[ Additive Factor Risk Scoring ] (src/scoring.py & src/feedback.py)
├── Bounded 0–100 score: Anomaly (0.25) + Priv Level (0.20) + Priv Delta (0.25)
│   + Resource Sensitivity (0.15) + Sequence Stage (0.15)
├── Explanation: Top-3 contributing factors & greedy counterfactual
└── Dynamic Analyst Feedback: Bounded ±10% tuning clamped between 0.5x and 2.0x
      │
      ▼
[ Incident Alerts & Policy Simulator ] (src/alerts.py & src/simulator.py)
├── Alert deduplication with incrementing `dup_count`
├── U5 Evidence Verifier re-resolving citations against raw sources
├── Simulator mitigation: MONITOR | STEP_UP | REVOKE_SESSION | RESTRICT
├── Break-glass safeguard deny-list (protected identities never auto-restricted)
└── Append-only SHA-256 hash-chained audit log (src/audit.py)
      │
      ▼
[ Presentation & Evaluation ]
├── FastAPI Backend (src/api.py, port 8000) with strict CSP & query sanitization
├── React 19 + TypeScript + Vite + Tailwind SOC Dashboard (web/, port 5173)
└── Benchmark Evaluation Harness (src/harness.py) with mutation testing
```

---

## 2. Findings & Technical Health Matrix (Graded P0–P3)

| ID | Severity | Category | Finding / Risk | Status | Remediation in Code |
|---|---|---|---|---|---|
| **F-01** | **P0** | Security | MongoDB query operator injection via log attributes (`$where`, `$gt`) | **FIXED** | Parameter sanitization rejects dicts and `$`-prefixed operators at API/query boundaries. |
| **F-02** | **P0** | Security | Rogue automated restriction of break-glass or root infrastructure identities | **FIXED** | Mandatory safeguard deny-list in `src/simulator.py` blocks auto-restriction of protected accounts. |
| **F-03** | **P1** | Integrity | Stored XSS via raw log strings rendered in the SOC web interface | **FIXED** | React plain-text string rendering; strict prohibition and zero occurrences of `dangerouslySetInnerHTML`; strict CSP. |
| **F-04** | **P1** | Integrity | Audit log tampering or decision deletion | **FIXED** | Append-only SHA-256 hash-chaining where each entry verifies the hash of the preceding entry. |
| **F-05** | **P2** | Data | Ingestion path traversal reading arbitrary filesystem files | **FIXED** | Canonical path resolution enforcing strict boundaries within `fixtures/` or `data/`. |
| **F-06** | **P2** | Evaluation | Non-deterministic or leaking evaluation splits | **FIXED** | Whole-identity holdout split with fixed random seed (`seed=42`) preventing sequence leakage across folds. |
| **F-07** | **P3** | Reliability | Absence of official organizers' dataset in initial repository | **MITIGATED** | High-fidelity synthetic fixtures matching official AWS CloudTrail and Okta schemas generated with labeled provenance (`SYNTHETIC-DEMO`). |

---

## 3. Scope Verification
- **Included**: Identity anomaly detection across Okta and CloudTrail, multi-step privilege escalation chains, explainable risk scoring, safe local policy simulator, attack graph, and evaluation harness.
- **Excluded**: No generic SIEM features, no malware scanning, no EDR/packet inspection, no live AWS/Okta credential hooks, and no chat/assistant widgets.

