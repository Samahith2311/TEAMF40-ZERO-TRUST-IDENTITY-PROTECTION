# Zero Trust Identity Protection Engine (Track 2)
### Intelligent Identity Threat Detection & Response across AWS CloudTrail + Okta Logs

## 1. Executive Summary
An identity-risk engine that correlates and stitches Okta session authentication events to AWS CloudTrail API actions into provenance-labeled attack chains. Employs a transparent, additive factor risk-scoring model (0–100) and executes simulated policy responses with strict break-glass safeguards and hash-chained audit logging.

---

## 2. Quick Start (Run in 2 Minutes)

### Prerequisites
- **Python 3.11+**
- **Node.js 18+** & **npm**
- **MongoDB** running on `localhost:27017`

### Step 1: Install Dependencies
```bash
# Python dependencies
pip install -r requirements.txt
# (or: pip install fastapi uvicorn pymongo pydantic pytest)

# Frontend dependencies
cd web && npm install && cd ..
```

### Step 2: Ingest & Run Complete Detection Pipeline
```bash
# Ingest, normalize, stitch, score, generate alerts, and record simulated response
python -m src.cli run-all
```

### Step 3: Run Evaluation Benchmark vs Baseline
```bash
# Evaluates event, identity, session, and chain levels beside baseline threshold detector
python -m src.cli eval
```

### Step 4: Verify Evidence References (U5)
```bash
# Re-resolves 100% of cited evidence lines against raw log sources
python -m src.cli verify-evidence
```

### Step 5: Start Backend API & SOC Dashboard
```bash
# Terminal 1: Launch FastAPI Backend (Port 8000)
uvicorn src.api:app --reload --port 8000

# Terminal 2: Launch Frontend Dashboard (Port 5173)
cd web && npm run dev
```
Open **`http://localhost:5173`** to access the SOC Incident Queue and Response Dashboard.

---

## 3. Architecture & Contract Mapping

```
                                  [ Raw Telemetry ]
                           Okta Logs     AWS CloudTrail
                               \               /
                                \             /
                         [ Ingestion & Normalization ]
                         - Schema validation & raw hash
                         - Idempotent upsert via Mongo
                                       |
                                       v
                             [ Anomaly Detectors ]
                    DET-01: Dormant Account Reactivation
                    DET-02: Token & Session Abuse
                    DET-03: Privilege Escalation Chain
                    DET-04: Unusual API Calls
                    DET-05: Impossible Travel
                                       |
                                       v
                          [ Cross-Source Stitching ]
                  Links Okta session -> CloudTrail principal
                  Provenance: VALIDATED | DERIVED | INFERENCE
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
                     - Verifiable evidence citations (U5)
                                       |
                    +------------------+------------------+
                    |                                     |
                    v                                     v
         [ React Dashboard ]                   [ Policy Simulator ]
         - Incident queue                      - Safeguard deny-list
         - Provenance timeline                 - Approval gate
         - Factor breakdown bars               - SHA-256 audit log
```

---

## 4. Key Security Controls & Tests
- **No Mongo Injection**: Strict parameter typing and rejection of `$`-prefixed operators (`SECURITY.md`).
- **Protected Accounts Safe**: Break-glass and admin accounts cannot be auto-restricted (`src/simulator.py`).
- **Tamper-Evident Audit**: SHA-256 hash-chained log detecting any modification or record deletion (`src/audit.py`).
- **XSS-Safe UI**: Zero `dangerouslySetInnerHTML`, strict CSP headers, plain text log rendering (`web/src/App.tsx`).
- **100% Traceability**: Every alert cites verifiable `(source_file, record_id)` resolving back to raw logs.

