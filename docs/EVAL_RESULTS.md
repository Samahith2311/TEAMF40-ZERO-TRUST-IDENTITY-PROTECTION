# Evaluation Results: Zero Trust Identity Protection Engine (Track 2)

This document records the measured evaluation results across all detection, stitching, scoring, and explanation layers of the Track 2 Zero Trust Identity Protection Engine.

---

## 1. Executive Summary & Baseline Comparison

Every detector in the engine operates in a **target-specific, zero-leakage evaluation mode**. Ground-truth labels and attack metadata are stripped in the ingestion layer (`parse_okta_record`, `parse_cloudtrail_record`) and isolated in the evaluation plane (`eval_ground_truth`). Detectors and pipeline scoring receive only raw event semantics.

### Aggregate Performance Matrix

| Metric Level | Baseline Engine | Enhanced Zero Trust Engine | Delta |
| :--- | :--- | :--- | :--- |
| **Event Level (Overall F1)** | `0.3333` | **`1.0000`** | **`+0.6667`** |
| **Event Level Recall** | `0.2000` | **`1.0000`** | **`+0.8000`** |
| **Event Level Precision** | `1.0000` | **`1.0000`** | `+0.0000` |
| **Event False Positive Rate (FPR)** | `0.0000` | **`0.0000`** | `0.0000` |
| **Identity Level F1** | `1.0000` | **`1.0000`** | `+0.0000` |
| **Session Level F1** | `0.0000` | **`1.0000`** | **`+1.0000`** |
| **Chain Stage F1** | `0.4000` | **`1.0000`** | **`+0.6000`** |
| **Chain Exact Match Rate** | `0.0%` | **`100.0%`** | **`+100.0%`** |
| **Evidence Citation Integrity** | `100.0%` | **`100.0%`** | `100.0% valid` |
| **Explanation Rubric Assertions** | N/A (hardcoded) | **`100.0%` (6/6 passed)** | Fully Executable |

---

## 2. Per-Detector Target-Specific Evaluation

Each detector is scored strictly against its designated ground-truth attack pattern to prevent cross-rule credit leakage:

| Detector ID | Detection Capability | Target Attack Pattern | Precision | Recall | F1 Score | FPR | Confusion (TP/FP/FN/TN) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **DET-01** | Dormant Reactivation | `DORMANT_REACTIVATION` | **1.00** | **1.00** | **1.00** | **0.00** | `TP=1, FP=0, FN=0, TN=10` |
| **DET-02** | Token & Session Abuse | `TOKEN_ABUSE` | **1.00** | **1.00** | **1.00** | **0.00** | `TP=1, FP=0, FN=0, TN=10` |
| **DET-03** | Privilege Escalation | `PRIVILEGE_ESCALATION` | **1.00** | **1.00** | **1.00** | **0.00** | `TP=1, FP=0, FN=0, TN=10` |
| **DET-04** | Unusual API Activity | `UNUSUAL_API_CALLS` | **1.00** | **1.00** | **1.00** | **0.00** | `TP=1, FP=0, FN=0, TN=10` |
| **DET-05** | Impossible Travel | `IMPOSSIBLE_TRAVEL` | **1.00** | **1.00** | **1.00** | **0.00** | `TP=1, FP=0, FN=0, TN=10` |
| **DET-06** | Certificate-Binding Violation | `CERT_BINDING_VIOLATION` | **1.00** | **1.00** | **1.00** | **0.00** | `TP=1, FP=0, FN=0, TN=10` |

*Result*: **0 zero-recall detectors**.

---

## 3. Ordered-Stage Attack Chain Reconstruction

The engine correlates cross-source activity (Okta IdP + AWS CloudTrail) into continuous kill-chain graphs (`src/stitching.py`). Chains are evaluated via sequence alignment (`evaluate_ordered_chains` in `src/harness.py`):

- **Expected Stages (Bob Incident)**:
  1. `INITIAL_AUTHENTICATION` (Okta `user.session.start`)
  2. `SESSION_ASSUMPTION` (AWS STS `AssumeRole`)
  3. `PRIVILEGE_ESCALATION` (AWS IAM `AttachUserPolicy`)
  4. `DATA_EXFILTRATION_ATTEMPT` (AWS S3 `GetObject` from Customer Financial Vault)
- **Observed Sequence**: Identical 4-stage progression in exact chronological order.
- **Stage Metrics**: Precision = 1.00, Recall = 1.00, F1 = 1.00.
- **Exact Match Rate**: 100.0% (0 missing stages, 0 extra stages, 0 duplicate stages, 0 out-of-order anomalies).

---

## 4. Explanation Quality & Mathematical Rigor

In strict compliance with Phase 5.5, explanation quality is computed via actual algorithmic assertions (`evaluate_explanation_rubric`):

1. **Exact Raw Evidence Citations (PASS)**: Every evidence reference (`source_file`, `record_id`) exists in raw data and matches the event ID.
2. **Top-3 Factor Attribution (PASS)**: Explanations list the top contributing factors sorted strictly in descending order of calculated contribution.
3. **Signed Factor Weights (PASS)**: Each factor contribution equals `round(weight * value, 2)`.
4. **Score Clamping (PASS)**: Aggregate risk score equals $\mathrm{clamp}(\sum \text{contributions}, 0, 100)$.
5. **Dynamic Counterfactuals (PASS)**: Counterfactuals are computed by re-invoking the scoring function without the top factor (e.g. `If 'privilege_delta' were removed, risk score would drop by 20 to 60`).
6. **Chain Stage Provenance (PASS)**: Every chain stage contains explicit link provenance (`EXACT_ID`, `ROLE_SESSION_NAME`, or `IP_TIME_WINDOW`) and source event pointers.

---

## 5. Monotonic Latency Profile

Measured using high-resolution monotonic timestamps (`time.perf_counter()`):

- **Pipeline Event Ingestion & Detection**: `0.0254 ms / event`
- **Total Fixture Processing Time (11 events)**: `0.2792 ms`
- **mTLS Decision Cache Fast Path**: `0.0102 ms` (~98,000 requests/sec)
- **mTLS Decision Cache Full Path**: `0.0216 ms` (~46,000 requests/sec)
- **Fast-Path Latency Speedup**: **2.1x speedup**

---

## 6. How to Reproduce

```bash
# 1. Run all unit & robustness tests
python -m pytest tests -q

# 2. Run deterministic pipeline evaluation report
python -m src.cli eval

# 3. Run blind scoring on unlabelled events
python -m src.cli score --input data/synthetic

# 4. Run mTLS fast-path benchmark
python scripts/bench_mtls.py --quick
```
