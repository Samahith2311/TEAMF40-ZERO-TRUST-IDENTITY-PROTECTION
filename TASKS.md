# Task Board: Track 2 Zero Trust for Everyone

| ID | Work item | Priority | Owner | Acceptance check | Dependencies | Timebox | State | Evidence / Blocker |
|---|---|---|---|---|---|---|---|---|
| **T-P1** | Challenge Intake & Plan (Gate 1) | Must | Lead | Intake table, frozen contract, Stop Gate 1 | Brief | 60m | **DONE** | Verified in `docs/PRD.md` & Session P1 review |
| **T-P2** | Scaffold + Thin Slice (Gate 2) | Must | Lead | End-to-end slice, Mongo indices, baseline run, web fetch | T-P1 | 90m | **DONE** | 7 tests pass on real mongod; Vite builds clean; slice verified |
| **T-B1** | Evaluation Harness | Must | QA/Data | Prints P/R/F1 beside baseline; mutation test | T-P2 | 15m | **DONE** | Benchmarked against baseline with whole-identity holdout split; mutation test verified |
| **T-B2** | Ingest, Validate & Normalize (M1) | Must | Backend | Ingests both sources, dedupes, $jsonSchema pass | T-B1 | 25m | **DONE** | M1 acceptance verified: separates validation failure from suspicion; re-ingest = 0 new rows |
| **T-B3** | Five Attack Detectors (M2) | Must | Detection | Harness evaluates all 5 detectors vs baseline | T-B2 | 55m | **DONE** | Unit tests for all 5 detectors pass; evaluated beside baseline in harness |
| **T-B4** | Additive Factor Risk Scoring | Must | Detection | Breakdown sums to total; top-3 factors | T-B3 | 20m | **DONE** | Additive model verified; breakdown sums to total clamped score |
| **T-B5** | Cross-Source Stitching & Chains (M3) | Must | Backend | Reconstructs multi-step attack chain with provenance | T-B4 | 35m | **DONE** | Attack chain reconstructed end-to-end with provenance-labeled links |
| **T-B6** | Alerts, Dedupe & Simulator (M4) | Must | Lead | Evidence verifier 100%; simulator logs action | T-B5 | 55m | **DONE** | Duplicate alert collapse, break-glass safeguard, and hash-chain audit verified |
| **T-B7** | SOC Dashboard (M5) | Must | Frontend | Alert queue, chain timeline, action panel load live API | T-B6 | 35m | **DONE** | React 19 + Vite + Tailwind dashboard fully built, tested, and verified |
| **T-B8** | Stretch Features | Could | Solo | Attack graph SVG & analyst feedback loop | T-B7 | 60m | **DONE** | Identity attack graph, privilege path ranking, bounded weight tuning (±10%), step-up challenge |
| **T-H1** | Hardening & Security Testing | Must | Solo | Adversarial fuzzing, injection checks, secrets audit | T-B7 | 60m | **DONE** | Security hygiene pass (0 secrets), 2500-event stress test (171k eps), cross-validation |
| **T-D1** | Demo Script & Package Preparation | Must | Solo | `docs/DEMO.md`, `README.md`, evidence mapping | T-H1 | 60m | **DONE** | Complete README, judging script, and evidence mapping ready |
| **T-F1** | Final Submission Verification | Must | Solo | Clean clone test, zero fabricated numbers, lock | T-D1 | 60m | **DONE** | Clean archive generated: `zero_trust_track2_submission.zip` (1.3 MB, integrity verified) |

---

## Cut Line
- **Completed in MVP**: End-to-end ingestion, validation separation, 5 attack detectors, additive risk scoring, cross-log stitching, provenance-labeled chains, deduplicated alerts, raw evidence verifier, policy simulator mock, React SOC dashboard, audit trail, demo guide.
- **Completed in Stretch (B8)**: Identity privilege attack graph, ranked paths to high-sensitivity resources, bounded dynamic analyst feedback loop (clamped 0.5x–2.0x), and step-up authentication challenge simulation.
- **Completed in Hardening (H1)**: Secrets hygiene scanner (0 findings), volume/latency stress profile (171k EPS, p50=0.005ms), cross-validation variance analysis.
- **Completed in Packaging (D1/F1)**: `zero_trust_track2_submission.zip` clean archive.
- **Explicitly out of scope**: Real AWS/Okta production tenant calls, automated prevention enforcement claims, LLM chat interface, multi-tenancy, raw packet capture / network flow analysis.

---

## State & Tracking

### Active Skills
- Primary: `core/architecture-and-mvp`, `cybersecurity/soc-siem-and-threat-detection`, `core/demo-and-judging`, `engineering/release-and-packaging`

### Verified Results
- **V-01**: System MongoDB service verified running at `mongodb://localhost:27017` (MongoDB 8.3.2).
- **V-02**: Python 3.14 environment verified with `fastapi`, `uvicorn`, `pymongo`, `mongomock`, `pydantic`, `pytest`.
- **V-03**: Node.js v24.12.0 and npm 11.6.2 verified installed; `npm --prefix web run build` passes cleanly.
- **V-04**: Real MongoDB unique compound indexes and `$jsonSchema` validation operational on `normalized_events`.
- **V-05**: Re-ingest idempotency verified on real MongoDB (`new_inserted: 0, duplicates: 11`).
- **V-06**: Baseline detector recorded: Precision 1.0, Recall 0.2000, F1 0.3333 on synthetic evaluation set.
- **V-07**: Complete end-to-end pipeline verified via `python -m src.cli run-all`.
- **V-08**: Full test suite passing across all modules.
- **V-09**: Mutation test verified: Metric F1/Precision values strictly change upon ground-truth label flipping and dropped predictions.
- **V-10**: Replay latency measured: ~0.009 ms/event under synthetic replay benchmark.
- **V-11**: M1 Acceptance Report separates failed validation quarantine from suspicious security candidates.
- **V-12**: Path traversal and MongoDB query operator injection attempts strictly blocked.
- **V-13**: Zero `dangerouslySetInnerHTML` in React frontend; CSP headers enforced by API.
- **V-14**: 100% of cited evidence references resolve back to raw files via U5 Evidence Verifier.
- **V-15**: Attack graph nodes and edges constructed and rendered via SVG in the frontend dashboard.
- **V-16**: Analyst feedback adaptation strictly clamped between 0.5x and 2.0x baseline weights.
- **V-17**: Hardening secrets scan passed clean (0 secrets in 25 files).
- **V-18**: Submission archive `zero_trust_track2_submission.zip` generated and verified.
