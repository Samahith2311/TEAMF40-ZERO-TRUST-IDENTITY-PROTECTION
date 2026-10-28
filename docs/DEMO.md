# Presentation & Live Judging Script: Track 2 Zero Trust

## 1. Pitch Outline (3-Minute Live Demo Walkthrough)

### 0:00 - 0:30: Problem & Context
> "Traditional identity security focuses on failed logins. But modern attackers don't fail logins—they compromise legitimate credentials, reactivate dormant accounts, assume cloud roles, and elevate privileges quietly. Our engine, **Zero Trust Identity Protection**, correlates Okta authentication with AWS CloudTrail API activity to detect multi-stage attack chains before data exfiltration occurs."

### 0:30 - 1:15: Ingestion & Live Pipeline Execution
- Run in terminal: `python -m src.cli run-all`
- Show console output:
  - Ingests both Okta and CloudTrail feeds.
  - Re-ingest yields 0 new rows (idempotent unique compound indexes on real MongoDB).
  - Correlates events across sources into provenance-labeled links (`VALIDATED_OBSERVATION` vs `ANALYTICAL_INFERENCE`).
  - Stitches multi-stage attack chain: Dormant Login -> AssumeRole -> AdministratorAccess Escalation -> PII Vault Access.

### 1:15 - 2:00: Evidence Traceability (U5)
- Run in terminal: `python -m src.cli verify-evidence`
- Highlight:
  - 100% of cited evidence references resolve directly back to raw log file records.
  - Zero hallucinations, zero untraceable claims.

### 2:00 - 2:45: React SOC Dashboard & Policy Mitigation Gate
- Open browser at `http://localhost:5173`:
  - Show **Alert Queue**: Real incident `alt-inc-bob_contractor_corp_internal` (Severity: HIGH, Dup count: 1).
  - Show **Risk Factor Breakdown (U2/U3)**: Score 80/100, additive contributions (`behavioral_anomaly`, `privilege_delta`, `resource_sensitivity`), top contributing factors, and counterfactual explanation.
  - Show **Provenance-Labeled Timeline**: Visualizing stages with color + shape + text badge (never color alone).
  - Show **Response Panel (M4)**: Click *"Authorize & Dispatch Simulated REVOKE_SESSION"*. Show real-time approval update and hash-chained audit log entry.

### 2:45 - 3:00: Benchmark Numbers & Differentiation
- Run in terminal: `python -m src.cli eval`
- Show benchmark comparison:
  - Event-level F1: **1.00** vs Baseline: **0.33** (+0.67 delta).
  - Session-level F1: **1.00** vs Baseline: **0.00**.
  - Sub-millisecond replay latency: **<0.01 ms / event**.

---

## 2. Technical Q&A Cheat Sheet for Judges

| Question | Defensible Technical Answer |
|---|---|
| **Why not use an LLM for detection?** | LLMs are non-deterministic, have high inference latency, hallucinate non-existent evidence, and cannot guarantee sub-millisecond replay under high event volume. We use deterministic statistical rules and additive factor scoring with 100% verifiable raw evidence pointers. |
| **How do you handle false positives (e.g. authorized admins)?** | We ingest identity metadata clearance levels and peer groups. Authorized admin actions match their baseline clearance ($4$), whereas contractors ($1$) performing IAM policy attachments trigger critical privilege delta factors. |
| **How is evidence integrity preserved?** | On ingestion, every raw record is hashed (`SHA-256`). Citations explicitly reference `source_file` and line number. The U5 Evidence Verifier re-resolves and parses citations from raw storage on demand. |
| **What happens if someone tampers with decision logs?** | All mitigation approvals append to an SHA-256 hash-chained audit trail where each entry includes the digest of the prior record. Any tampering or deletion breaks the chain. |

