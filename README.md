# Zero Trust Identity Protection Engine (Track 2)
### Intelligent Identity Threat Detection, Risk-Adaptive mTLS Caching & Automated Response across AWS CloudTrail + Okta Logs

---

## 1. Executive Summary
An enterprise-grade Zero Trust identity protection engine that correlates and stitches Okta IdP authentication events to AWS CloudTrail API actions into provenance-labeled attack chains. Employs a transparent, additive factor risk-scoring model (0–100) and executes simulated policy responses with strict break-glass safeguards, RFC 8705 cryptographic mutual TLS (mTLS) session binding with sub-millisecond decision caching, and hash-chained audit logging.

---

## 2. Key Capabilities & Specifications

- **6 Core Zero Trust Detectors (0 Zero-Recall Detectors)**:
  - `DET-01`: Dormant Account Reactivation (session activity tracking, activity timestamps)
  - `DET-02`: Token & Session Abuse (browser-to-SDK transitions, mid-session ASN shifts, 15m session timeouts)
  - `DET-03`: Privilege Escalation Chain (IAM policy attachment taxonomy and administrative elevation)
  - `DET-04`: Unusual Automated API Sweep (sensitive vault access, suspicious user-agents restricted to data APIs)
  - `DET-05`: Impossible Travel (Haversine geodesic speed calculation > 800 km/h, 0.0 lat/lon equator preservation)
  - `DET-06`: Certificate-Binding Violation (RFC 8705 token-binding violation detection and replay defense)
- **Phase 7 Risk-Adaptive mTLS Decision Caching**:
  - Sub-millisecond fast path (`~0.010 ms`, 97,000+ req/s) for low-risk sessions presenting bound certificates.
  - Automatic cache invalidation, session revocation, and DET-06 alert generation on certificate mismatch.
  - Seamless, audited zero-downtime approved certificate rotation workflow.
- **Ordered Kill-Chain Reconstruction**:
  - Chronological alignment with link provenance (`EXACT_ID`, `ROLE_SESSION_NAME`, `IP_TIME_WINDOW`).
  - Sequence alignment metrics reporting exact match rate (100%), stage F1 (1.00), and duplicate prevention.
- **Executable Explanation Quality Rubric**:
  - 100% assertion pass rate (6/6 checks) verifying exact evidence citations, mathematical factor weights, score clamping, dynamic counterfactual calculations, and provenance.
- **Reproducible Evaluation & Blind Scoring**:
  - Fully decoupled synthetic dataset generator (`scripts/generate_dataset.py`) emitting raw events and isolated labels without truth leakage.
  - Blind scoring subcommand (`python -m src.cli score --input <path>`) for evaluating arbitrary unlabelled datasets.

---

## 3. Quick Start (Run in 2 Minutes)

### Prerequisites
- **Python 3.11+**
- **Node.js 18+** & **npm**
- **MongoDB** running on `localhost:27017`

### Step 1: Install Dependencies
```bash
# Python dependencies
pip install -r requirements.txt

# Frontend dependencies
cd web && npm install && cd ..
```

### Step 2: Run Verification Test Suite
```bash
# Runs all 47 unit, robustness, and mTLS tests
python -m pytest tests -q
```

### Step 3: Ingest & Run Complete Detection Pipeline
```bash
# Ingest, normalize, stitch, score, generate alerts, and record simulated response
python -m src.cli run-all
```

### Step 4: Run Evaluation Benchmark
```bash
# Evaluates event, identity, session, and chain levels beside baseline threshold detector
python -m src.cli eval
```

### Step 5: Run mTLS Fast-Path Benchmark
```bash
# Runs high-resolution monotonic mTLS decision cache benchmark
python scripts/bench_mtls.py --quick
```

### Step 6: Start Backend API & SOC Dashboard
```bash
# Terminal 1: Launch FastAPI Backend (Port 8000)
python -m uvicorn src.api:app --reload --port 8000

# Terminal 2: Launch Frontend Dashboard (Port 5173)
cd web && npm run dev
```
Open **`http://localhost:5173`** to access the SOC Incident Queue and Response Dashboard.

---

## 4. Architecture & Workflow

```
                                  [ Raw Telemetry ]
                           Okta System Log   AWS CloudTrail
                                \               /
                                 \             /
                         [ Ingestion & Normalization ]
                         - RFC 8601 UTC timestamp parsing
                         - Schema validation & SHA-256 raw hash
                         - Idempotent upsert via MongoDB (source, event_id)
                                       |
                                       v
                             [ Anomaly Detectors ]
                    DET-01: Dormant Account Reactivation
                    DET-02: Token & Session Abuse
                    DET-03: Privilege Escalation Chain
                    DET-04: Unusual Automated API Sweep
                    DET-05: Impossible Travel (Geodesic)
                    DET-06: Certificate-Binding Violation
                                       |
                                       v
                          [ Cross-Source Stitching ]
                  Links Okta session -> CloudTrail principal
                  Provenance: EXACT_ID | ROLE_SESSION_NAME | IP_TIME_WINDOW
                                       |
                                       v
                         [ Additive Factor Scoring ]
                   0.25 Anomaly + 0.20 Privilege + 0.25 Delta
                       + 0.15 Sensitivity + 0.15 Stage
                                       |
                                       v
                          [ SOC Incident & Alerts ]
                     - Deduplicated alert stream
                     - Top-3 contributing factors
                     - Dynamic counterfactual calculation
                     - Verifiable evidence citations (U5)
                                       |
                    +------------------+------------------+
                    |                                     |
                    v                                     v
         [ React Dashboard ]                   [ Policy Simulator ]
         - Incident queue                      - Safeguard deny-list
         - Interactive bubble attack graph     - Break-glass protection
         - Factor breakdown bars               - Approval gate
         - Phase 7 mTLS Cache Console          - SHA-256 audit log
```

---

## 5. Security Controls & Safeguards

- **Strict Identity Isolation**: Ground-truth labels stripped during ingestion; detectors receive only raw event semantics.
- **Break-Glass Defense**: Critical administrative identities with `is_protected: true` are immune to simulated disruption and return HTTP 403 / DENY.
- **No Mongo Injection**: Strict parameter typing and rejection of `$`-prefixed query operators (`SECURITY.md`).
- **Tamper-Evident Audit Trail**: SHA-256 hash-chained log detecting any modification, deletion, or reordering of audit entries (`src/audit.py`).
- **XSS-Safe UI**: Zero `dangerouslySetInnerHTML`, strict Content Security Policy (CSP), plain text log rendering (`web/src/App.tsx`).
- **Cryptographic Token Binding**: RFC 8705 client certificate SHA-256 fingerprinting prevents token replay across disparate workstations.
- **Clean Packaging**: Hardened packaging script (`scripts/package_submission.py`) excluding caches, private keys, and bloated development files (< 15 MB).

---

## 6. Project Documentation Index

- [`docs/EVAL_RESULTS.md`](docs/EVAL_RESULTS.md) — Comprehensive evaluation methodology, target-specific confusion matrices, ordered chain metrics, and latency profile.
- [`docs/TRACK2_FINAL_VERIFICATION.md`](docs/TRACK2_FINAL_VERIFICATION.md) — Gates 1–10 and Phases 0–10 compliance verification matrix with recorded command outputs.
- [`docs/DEMO_MTLS.md`](docs/DEMO_MTLS.md) — Step-by-step 60–90 second SOC walkthrough for Phase 7 mTLS decision caching and DET-06 token replay defense.
- [`docs/MTLS_BENCHMARK.md`](docs/MTLS_BENCHMARK.md) — Monotonic high-resolution benchmark report comparing plain HTTP, uncached mTLS, and warm fast-path decisions.
- [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md) — Documented operational boundaries, localhost benchmark characteristics, and simulation scopes.
