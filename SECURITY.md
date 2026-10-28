# Security Architecture & Threat Model: Track 2 Zero Trust

## 1. Scope & Assets
- **Protected Assets**:
  - Telemetry & Normalized Events: Integrity of historical CloudTrail and Okta log events.
  - Incident Evidence Citations: Verifiability of raw log pointers (`source_file`, `record_ref`).
  - Identity Privileges: Protection against unauthorized policy actions or rogue session revocation.
  - Audit Trail: Immutable record of automated and analyst-driven responses.

## 2. Trust Boundaries
- **Untrusted Input Boundary**: Raw log ingestion (`fixtures/` or uploaded files), analyst API requests.
- **Database Boundary**: MongoDB collections with `$jsonSchema` validation and strict typed query interfaces.
- **Simulated Response Boundary**: Approval gate required before issuing high-severity mitigation actions.
- **Presentation Boundary**: Browser dashboard rendering log strings as inert plain text with strict CSP.

---

## 3. Ranked Abuse Cases & Controls

| # | Threat / Abuse Case | Impact | Control Implemented | Verification Test |
|---|---|---|---|---|
| **AC-01** | **MongoDB Operator Injection**: Attacker supplies `{"$gt": ""}` in `userAgent` or `identity_key` | Data leak or auth bypass | Strict parameter type enforcement; rejection of dict or `$`-prefixed input at API boundary | `tests/test_slice.py::test_mongo_operator_injection_denied` |
| **AC-02** | **Denial of Service via Replay**: Attacker bombards system with duplicate log lines | Resource exhaustion, alert fatigue | Unique compound index on `(source, event_id)` + upsert deduplication | `tests/test_slice.py::test_duplicate_reingest_idempotency` |
| **AC-03** | **Protected Identity Auto-Restriction**: Malicious spoofing against break-glass or root account | Accidental administrative lockout | Hardcoded safeguard deny-list for protected accounts; analyst approval mandatory | `tests/test_slice.py::test_protected_identity_restriction_denied` |
| **AC-04** | **Audit Log Tampering**: Insider alters decision logs to conceal malicious activity | Non-repudiation failure | Hash-chained audit logs where each record includes SHA256 of previous entry | `tests/test_slice.py::test_audit_chain_tamper_detection` |
| **AC-05** | **Stored XSS via Log Telemetry**: Attacker injects `<script>` or `<img onerror>` in log attributes | Session compromise in SOC UI | React default text escaping; elimination of `dangerouslySetInnerHTML`; strict CSP | `tests/test_slice.py::test_log_string_sanitization_inert` |
| **AC-06** | **Evidence Fabrication**: System emits alerts citing nonexistent raw log positions | Invalid alert / lost trust | U5 Evidence Verifier verifies 100% of citations against raw source files | `tests/test_slice.py::test_evidence_verifier_resolves_raw` |

---

## 4. Accepted Risks & Mitigations
1. **Local Unauthenticated MongoDB**: MongoDB on localhost has no TLS/auth enabled in development environment.
   - *Mitigation*: Service strictly bound to `127.0.0.1`; production deployment requires authenticated URI with credentials passed via environment variables.
2. **Synthetic Data Latency Profile**: Benchmark load profile is simulated locally.
   - *Mitigation*: Latency results explicitly labeled `SYNTHETIC_LOAD` in evaluation tables.
