# Architecture & Implementation Map — Track 2 Zero Trust Identity Protection

This document maps the end-to-end data flow, contracts, function bindings, persistence layers, and plane separations for the Zero Trust Identity Protection Engine.

---

## 1. End-to-End Pipeline Data Flow

```
[Raw Sources: Okta & CloudTrail]
                │
                ▼ (src.ingest: validate_and_normalize, parse_raw_log)
       [NormalizedEvent] (Labels stripped into Evaluation Plane)
                │
                ├──────────────────────────────────────┐
                ▼ (src.detectors: DET-01..06)          ▼ (src.stitching: extract_identity_candidates)
       [DetectorFindings]                      [IdentityLinks & Cross-Source Correlation]
                │                                      │
                └──────────────────┬───────────────────┘
                                   ▼ (src.stitching: reconstruct_chains)
                            [IncidentChain]
                                   │
                                   ▼ (src.scoring: calculate_risk_score)
                             [RiskScore]
                                   │
                                   ▼ (src.alerts: create_alerts)
                              [AlertRecord]
                                   │
                                   ▼ (src.simulator: simulate_action)
                        [SimulatorResult & Audit]
                                   │
                                   ▼ (src.api & web/src/App.tsx)
                        [FastAPI Endpoints & UI]
```

---

## 2. Logical Data Plane Separation

To prevent label leakage and ensure evaluation integrity, the engine strictly separates:

1. **Signal Plane (`src.ingest`, `src.models`)**:
   - `NormalizedEvent` containing raw event attributes, timestamps, IP, user-agent, session ID, action, and provenance.
   - **Label Stripping**: At the ingestion boundary, `label`, `ground_truth`, and `attack_type` are removed from `NormalizedEvent`.
   - Raw line hash `raw_sha256` is computed over the unstripped raw line for evidence verifiability.

2. **Detection Plane (`src.detectors`, `src.stitching`)**:
   - Rules DET-01 to DET-06 operate purely on `NormalizedEvent`, identity metadata, and observed baselines.
   - Multi-step chain reconstruction orders stages by UTC timestamp without reading external labels.

3. **Decision Plane (`src.scoring`, `src.simulator`, `src.feedback`, `src.mtls`)**:
   - Additive factor scoring (`behavioral_anomaly`, `privilege_level`, `privilege_delta`, `resource_sensitivity`, `sequence_stage`).
   - Zero-trust expected loss action simulation (`MONITOR`, `STEP_UP`, `REVOKE_SESSION`, `RESTRICT`).
   - Protected identity policy guardrails (`is_protected: true`).
   - Fast risk-adaptive mTLS decision caching (`FAST_PATH`, `FULL_RESCORING`).

4. **Evaluation Plane (`src.harness`, `src.cli`)**:
   - Isolated side-table of ground-truth labels keyed by `event_id`.
   - Confusion matrices, per-detector precision/recall/F1, ordered chain stage precision/recall/F1, and mutation checks.
   - The Signal, Detection, and Decision planes never import or query the Evaluation Plane.

---

## 3. Function & Module Reference

| Stage | Module | Key Functions | Contracts / Models |
|---|---|---|---|
| Ingest | `src.ingest` | `validate_and_normalize_event`, `parse_raw_log`, `run_ingest_all` | `NormalizedEvent`, `IngestReport` |
| Detectors | `src.detectors` | `detect_dormant_reactivation` (DET-01), `detect_token_abuse` (DET-02), `detect_privilege_escalation` (DET-03), `detect_unusual_api` (DET-04), `detect_impossible_travel` (DET-05), `detect_cert_binding_violation` (DET-06) | `DetectorFinding`, `RuleStatus` |
| Correlation | `src.stitching` | `extract_identity_candidates`, `correlate_cross_source`, `reconstruct_chains` | `IdentityCandidate`, `IdentityLink`, `IncidentChain` |
| Scoring | `src.scoring` | `calculate_risk_score`, `evaluate_factors` | `RiskScore`, `RiskFactor` |
| Alerting | `src.alerts` | `create_alerts`, `verify_evidence_refs` | `AlertRecord`, `EvidenceRef`, `VerificationReport` |
| Simulator | `src.simulator` | `simulate_action`, `check_protected_identity`, `calculate_expected_loss` | `SimulatorAction`, `SimulatorResult` |
| Audit | `src.audit` | `append_audit_event`, `verify_audit_chain` | `AuditRecord` |
| Feedback | `src.feedback` | `submit_analyst_feedback`, `get_current_weights`, `revert_feedback` | `FeedbackEntry`, `WeightState` |
| mTLS Fast Path | `src.mtls` | `cert_fingerprint`, `verify_cert_binding`, `evaluate_mtls_risk_decision`, `MTLSDecisionCache` | `MTLSDecision`, `CertBindingState` |
| API | `src.api` | FastAPI application endpoints | Pydantic Request/Response models |
| Evaluation | `src.harness` | `run_evaluation_harness`, `run_mutation_check`, `evaluate_predictions` | `EvalReport`, `MetricSummary` |

---

## 4. API Endpoints Map

- `GET /api/alerts`: Retrieve deduplicated alerts with risk scores and evidence refs.
- `GET /api/chains`: Retrieve reconstructed attack chains.
- `GET /api/scores`: Retrieve additive factor scores and explanations.
- `GET /api/graph`: Attack graph with node/edge provenance and path rankings.
- `POST /api/feedback`: Submit analyst feedback on alert verdicts and factor weights.
- `GET /api/feedback/weights`: Active calibrated weights.
- `GET /api/feedback/tuning-log`: Historical tuning audit log.
- `POST /api/actions/simulate`: Simulated policy action with expected-loss evaluation.
- `POST /api/actions/approve`: Analyst approval gate for simulated actions.
- `POST /api/actions/step-up`: Simulate step-up MFA dispatch.
- `POST /api/mtls/decide`: Evaluate mTLS peer certificate binding and risk-adaptive fast-path decision.
- `GET /api/mtls/stats`: Cache hit/miss and decision latency counters.
- `POST /api/synthetic/generate`: Trigger raw synthetic attack scenario through normal pipeline.
