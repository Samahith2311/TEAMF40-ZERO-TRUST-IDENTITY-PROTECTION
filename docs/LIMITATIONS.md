# System Limitations & Governance Notes

## 1. Protected Identity Metadata Correction
- **Finding (Section 2A.5)**: In the raw initial delivery of `fixtures/identities.json`, `diana.admin@corp.internal` (clearance tier 4 admin) was erroneously marked as `is_protected: false`.
- **Remediation**: Treated as a data defect in accordance with specification rule 2A.5. `diana.admin@corp.internal` is now authoritatively configured with `is_protected: true`.
- **Policy Enforcement**: `src.simulator.execute_simulated_action` now queries `is_identity_protected` dynamically from `fixtures/identities.json` (plus defense-in-depth patterns for root and break-glass ARNs). Automated `RESTRICT` and `REVOKE_SESSION` against protected accounts return `DENIED_PROTECTED_IDENTITY`.

## 2. Synthetic Data & Replay Boundaries
- **Synthetic Ground Truth**: Evaluation results on synthetic benchmarks demonstrate engine consistency and invariant adherence under known distributions; they do not imply real-world distribution equivalence.
- **Safety Boundary**: Zero Trust containment actions (`RESTRICT`, `REVOKE_SESSION`, `STEP_UP`, `MONITOR`) are strictly simulated inside `src.simulator`. The engine never contacts, queries, or modifies live AWS/Okta production infrastructure.

## 3. Geo & Transport Inferences
- **Inferred Geo**: When CloudTrail events lack geo coordinates, location context from preceding Okta sessions is carried forward marked as `INFERRED` / `CARRIED_FORWARD`. Inferred coordinates carry lower confidence than direct observations.
- **Proxy Trust**: In mTLS deployments, client certificate fingerprints forwarded via reverse proxies (`X-Client-Cert-Fingerprint`) must originate strictly from configured trusted proxy interfaces. Direct TLS peer extraction via transport socket is preferred.
