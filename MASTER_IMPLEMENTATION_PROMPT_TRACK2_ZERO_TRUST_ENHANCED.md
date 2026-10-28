# MASTER IMPLEMENTATION PROMPT — Track 2: Intelligent Identity Protection + Risk-Adaptive mTLS

> **How to use:** Open the existing `MIT-T-HACKATHON-` repository at its root in Codex, Claude Code, Cursor, or another repository-aware coding agent. Paste this entire prompt. Treat it as an implementation specification, not a request for a review-only response. Work inside the existing project; do not rebuild the product from scratch.

---

## 1. ROLE, MISSION, AND EVALUATION STANDARD

Act as all of the following:

1. A senior detection-and-response engineer responsible for correctness, not merely a convincing demo.
2. A data engineer responsible for event provenance, identity resolution, deterministic replay, and evaluation integrity.
3. A security engineer responsible for safe simulated enforcement, certificate handling, and application security.
4. A performance engineer responsible for reproducible latency measurement.
5. A strict hackathon evaluator who reads implementation and tests, not only the README or dashboard.

Your task is to improve the **existing repository** to satisfy the supplied problem statement:

**Track 2 — Zero Trust for Everyone: Intelligent Identity Protection.** The engine should assign identity/session risk from behavior, privilege level, resource sensitivity, and event history; detect contextual combinations of suspicious events and multi-step privilege escalation; correlate Okta System Log and AWS CloudTrail activity; explain what was flagged and why with verifiable evidence; and recommend safe actions through the provided simulator. The original five attack patterns are:

- Dormant-account reactivation.
- Impossible travel.
- Multi-step privilege-escalation chains.
- Unusual API calls.
- Token/session abuse.

The extension in this specification adds **DET-06 certificate-binding violation** and **risk-adaptive mTLS decision caching**. Keep the extension clearly distinguished from the five original attack families when reporting original-track metrics.

### Core success criteria from the supplied problem statement

- Event-level precision, recall, and F1 measured against held-out labels.
- Identity/session-level alert precision measured separately from event-level quality.
- Detection latency measured under an explicitly described load profile.
- Explanation quality and raw-evidence traceability.
- Correct reconstruction of **ordered** multi-step privilege-escalation chains.
- All access enforcement through the supplied simulator. Never contact or modify real AWS accounts, Okta tenants, identity providers, or production resources.

The bar is a working, auditable detection system, not a dashboard that displays plausible numbers.

---

## 2. NON-NEGOTIABLE ENGINEERING RULES

1. **Do not rewrite from scratch.** Inspect and extend the existing files and API contracts. Preserve working UI, security controls, audit logging, simulator approval gates, and current tests unless a real defect requires a migration.
2. **Inspect before changing.** Read the current code, tests, docs, fixture schemas, and Git status first. Do not assume the previous audit is perfectly current; reproduce each finding against the checkout.
3. **Never destroy user work.** Do not run `git reset --hard`, `git clean -fd`, destructive database drops, or broad deletion commands. Do not overwrite uncommitted changes. Create a branch only after checking the working tree; do not commit unless asked.
4. **No truth leakage.** Detection, scoring, chain reconstruction, recommendations, and production-style API responses must not read ground-truth labels. Labels may be read only by evaluation code.
5. **No hardcoded scenario outputs.** No hardcoded target identity, risk-factor value, evidence record ID, alert prose, attack label inferred from a username, prebuilt attack chain, hand-written metric, or constant latency result. Demo fixtures and policy configuration are allowed, but the engine must infer the result from raw events.
6. **No fabricated success.** Never insert `PASS`, `VERIFIED`, `100%`, or a success status merely because a function ran. Generate status from executed assertions and results. Do not claim tests passed unless the exact command was run and its exit status/output observed.
7. **Synthetic means synthetic.** Label synthetic datasets, generated alerts, certificate demos, simulated actions, and synthetic benchmark results consistently in API payloads, UI, and documentation. Do not imply that synthetic evaluation proves real-world effectiveness.
8. **Measure, don't promise.** Do not hardcode latency, throughput, accuracy, cache hit rate, confidence intervals, or F1. Never claim mTLS handshakes become faster unless a measured result specifically demonstrates a supported TLS behavior such as session resumption.
9. **Preserve safe boundaries.** No live AWS/Okta requests, real credential collection, real revocation/restriction, or production tenant modification. The simulator is the only enforcement sink.
10. **Security invariant for mTLS:** a cached low-risk decision may reduce repeated **risk-analysis overhead**, but it must never bypass TLS handshake validation, trusted-certificate-chain validation, certificate validity checks, required revocation policy, identity/session binding checks, or authorization controls. High-risk decisions and certificate-binding violations must fail closed to the full risk path / simulator policy.
11. **Configuration over brittle literals.** Detection thresholds, action taxonomy, resource sensitivity, benign allowlists, trusted proxy addresses, cache TTL, and policy thresholds belong in explicit configuration or identity metadata, not scattered string checks.
12. **Maintain backward compatibility where practical.** If a model or API response must change, update all call sites and tests, document the schema change, and provide a migration or compatibility adapter for persisted records where needed.
13. **Keep scope narrow.** Do not add generic IDS, packet capture, endpoint malware scanning, unrelated SaaS integrations, or live cloud actions.
14. **No silent skips.** If a feature cannot be completed or a benchmark mode is unsupported in the installed runtime, record the limitation and return `NOT_RUN` / `UNSUPPORTED` / `INCONCLUSIVE`, not a fabricated pass or zero-latency number.


## 3. REPOSITORY CONTEXT TO VERIFY

The current ZIP contains these key files. Confirm they still exist and inspect them before editing:

### Backend

- `src/models.py` — Pydantic event, factor, score, evidence, alert, chain, simulator, audit, and evaluation models.
- `src/ingest.py` — Okta/CloudTrail ingestion, validation, normalization, path and input safeguards.
- `src/detectors.py` — existing DET-01 through DET-05 rules.
- `src/stitching.py` — cross-source correlation and chain construction.
- `src/scoring.py` — weighted risk factors.
- `src/pipeline.py` — current vertical run; presently includes hardcoded identity/scoring/alert logic according to the supplied audit and must be made data-driven.
- `src/alerts.py` — alert creation, deduplication, and evidence verification.
- `src/simulator.py` — simulated response and protected-account safeguards.
- `src/feedback.py` — analyst feedback and current in-memory weight state.
- `src/graph.py` — attack graph.
- `src/harness.py` — event/identity/session/chain evaluation and current metric/report logic.
- `src/baseline.py` — baseline comparison.
## 2A. ADDITIONAL RULES (priority, leakage, robustness)

### 2A.1 Priority tiers and stop rules
Work in this tier order. Do not start a tier until the previous tier's gate passes.
- **TIER 1 (must ship, core credibility):** Phase 0, Phase 1, DET-01..05 fixes (Phase 2), the evidence verifier, the harness fixes (5.1–5.5), and the 2A.2/2A.3 requirements below.
  Gate: all existing and new tests pass, and the original 11-event fixtures are detected by all five detectors (no zero-recall detector).
- **TIER 2:** Phase 3 (correlation), Phase 4 (generator), Phase 5.6/5.7 (latency, reports), Phase 6 (feedback, simulator, graph).
- **TIER 3 (extension, only after Tiers 1–2 gates pass):** DET-06 and Phase 7 (mTLS). Ship the `--quick` benchmark and the cert-binding detector first. Mark full-mode benchmarks, the UI panel and the proxy path as optional.
If context or time runs out, stop at a clean tier boundary and report exactly which tier is complete. A finished Tier 1 beats a half-finished Tier 3.
Before and after Tier 1, record per-detector recall on the original fixtures in `docs/baseline_before.txt` and `docs/baseline_after_tier1.txt`.

### 2A.2 Inline label leakage (known defect in this repo)
The provided raw fixtures contain an inline `label` field on every event (BENIGN, TOKEN_ABUSE, PRIVILEGE_ESCALATION, and so on).
- At the ingestion boundary, remove `label` (and any `ground_truth`/`attack_type`-style field) from the detector-visible event. Store it only in an evaluation-only side table keyed by `event_id`.
- Compute the evidence `raw_sha256` over the original line (so evidence stays verifiable). Never expose the stripped field to detectors, scoring or alert text.
- **Required test:** replace every inline label with `BENIGN`, then with random values, and assert that detections, scores, chains and alerts are byte-identical. Add a second test proving the evaluator still reads the original labels.
- Apply the same rule to any dataset the generator or a user supplies.

### 2A.3 Hidden-dataset robustness (anti-overfitting gate)
The grader's dataset will differ from the fixtures. Prove the engine does not depend on fixture literals:
1. **Metamorphic test:** programmatically rename every identity, bucket/resource name, IP address, session ID and user-agent token in the fixtures and the generated dataset (updating `identities.json` and the resource catalog consistently). Detections, scores, chain structures and evidence links must be equivalent up to the renaming.
2. **Schema-drift tolerance:** ingestion must accept CloudTrail both as JSONL and as a `{"Records":[...]}` wrapper, Okta timestamps with and without fractional seconds and with offsets, and missing optional fields. Unparseable records go to quarantine with a reason and never crash the run.
3. **Blind-run command:** provide `python -m src.cli score --input <dir> --out predictions.json` (no label access) and `python -m src.cli evaluate --predictions predictions.json --labels <file>`. The scorer must not need to know the dataset in advance. Document the prediction schema (event-level, session-level, identity-level, chain).
4. **Tuning discipline:** thresholds may be tuned only on the calibration identities. Report the held-out result even if it is worse than the fixture result, and do not hide a drop.

### 2A.4 Causal streaming replay (for the latency rubric)
Add a replay mode that feeds events in timestamp order, one at a time, using only state built from earlier events (no lookahead, no whole-dataset statistics computed up front). Measure per-event latency from event accepted to detector/score/alert emitted, in this mode. Add a test that detections for event N are unchanged when events N+1.. are deleted. Report batch and streaming results separately, with the load profile (event count, arrival rate or schedule, workers, runs, seed).

### 2A.5 Protected-identity metadata
`fixtures/identities.json` currently marks `diana.admin@corp.internal` as `is_protected: false`. Treat that as a data defect. Mark admin and break-glass identities `is_protected: true` in the fixture, document the change in `docs/LIMITATIONS.md`, and make the simulator read only this metadata (plus root/break-glass ARN patterns from config). The test must iterate every fixture identity and assert that the simulator's decision matches its metadata.- `src/audit.py` — hash-chained audit log.
- `src/db.py`, `src/config.py`, `src/cli.py`, `src/api.py` — persistence, settings, CLI, and FastAPI endpoints.
- `src/synthetic_generator.py` — current attack demo generator; refactor it so it produces raw synthetic events and then invokes the real pipeline, rather than fabricating downstream results.

### Frontend

- `web/src/App.tsx` — current React/TypeScript SOC dashboard.
- `web/src/main.tsx`, `web/src/index.css`, `web/package.json`, and `web/vite.config.ts`.

### Inputs, tests, and documentation

- `fixtures/okta_sample.jsonl`, `fixtures/cloudtrail_sample.jsonl`, `fixtures/identities.json`, `fixtures/ground_truth.json`.
- `tests/` — preserve the current suite and add focused regression tests.
- `docs/PRD.md`, `docs/DEMO.md`, `docs/EVIDENCE_MAP.md`, `docs/DATASET_REPORT.md`, `docs/TRACK2_AUDIT.md`, `docs/TRACK2_FINAL_VERIFICATION.md`, `README.md`.
- `scripts/package_submission.py` — currently excludes common caches but must be tightened to exclude irrelevant embedded documentation, build prompts, skill packs, nested archives, local certificates, and secrets from the final archive.

The delivered ZIP currently appears to contain `.git`, cache directories, a nested `zero_trust_track2_submission.zip`, build prompts, beginner/vibecoding guides, and a skill pack. **Do not delete these from the working repository as a shortcut.** Make the package builder exclude them from the generated deliverable and verify the archive contents.

---

## 4. EXECUTION PROTOCOL

Work through the phases below in order. After every phase, run its focused tests and keep the project runnable. Continue through all phases that can be implemented and verified in this task; do not stop after building only a visual mTLS panel. If tool/context limits prevent completion, leave a clean checkpoint and precisely list completed, pending, and blocked requirements.

For each phase, report:

1. **Changed files** and the reason for each change.
2. **Commands actually executed** and their real exit codes/output summaries.
3. **Tests added**, including which failure would have occurred before the fix.
4. **Limitations or unsupported behavior**, if any.
5. **Next phase** and any unresolved dependencies.

At the start:

- Run `git status --short --branch` and note the working tree state.
- Inspect the current Python and Node versions and installed dependencies.
- Run the existing backend tests (`python -m pytest tests -q` or the repository-supported equivalent), the current evaluation CLI (`python -m src.cli eval`), and frontend production build (`npm --prefix web run build`) when dependencies/services permit.
- Save the observed baseline, including failures and environment constraints, to `docs/baseline_before.txt`. Do not edit the baseline output afterward to make it look cleaner.
- Inspect the actual CLI commands before selecting later verification commands.
- Use local/mocked persistence for automated tests. Do not require a developer's real MongoDB or credentials for unit tests.

---

# PHASE 0 — BASELINE, CONTRACTS, AND SAFETY NET

## 0.1 Establish current behavior

Map the current ingestion-to-response path:

`raw source -> parse/validate -> normalized events -> detector results -> identity links -> chains -> risk scores -> alerts -> simulator -> audit log -> evaluation -> API/UI`.

Write a compact architecture map to `docs/IMPLEMENTATION_MAP.md` including the actual current functions, schemas, and API endpoints. Call out where evaluation labels can be read, where state is persisted, and which code is currently a demo-only shortcut.

## 0.2 Define one event contract

Use one documented normalized-event contract across ingestion, detectors, stitching, risk scoring, evidence verification, and evaluation. Extend `NormalizedEvent` or add versioned models as appropriate. It must preserve at least:

- Stable `event_id` (deterministic for the same raw record; avoid a new random ID on every replay).
- `source` (`okta`, `cloudtrail`, or explicitly labelled synthetic origin), raw source filename or dataset-relative path, raw line/record reference, and raw SHA-256 hash.
- Parsed UTC timestamp and original timestamp/timezone where available.
- Canonical identity candidates instead of assuming one email string always exists.
- Session/token/request identifiers where present.
- Source-specific principal fields retained for later identity resolution.
- Source IP, port/ASN/geo if available, user-agent, certificate fingerprint if trusted evidence exists, action/API name, resource, outcome, and privilege context.
- Validation status and any normalization assumptions.
- Evidence provenance sufficient to locate the exact raw record without reconstructing an ID by hand.

Avoid losing source-specific fields in normalization. Store unknown/missing fields as unknown, not guessed values. Parse timestamps timezone-safely and consistently. Never use falsey checks that accidentally discard valid numeric zero values (for example latitude `0.0`).

## 0.3 Separate data planes

Enforce the following logical separation in code and documentation:

- **Signal plane:** raw and normalized event data used by the detector.
- **Detection plane:** findings inferred from event data and metadata.
- **Decision plane:** calculated risk score, explanation, recommendation, and simulator action.
- **Evaluation plane:** truth labels, attack injection metadata, and scoring metrics. The detection plane must not import or read evaluation labels.

Add a regression test that instruments or monkeypatches label-file access and proves a normal detection run does not read `fixtures/ground_truth.json` or generated `labels.json`.

---

# PHASE 1 — MAKE THE END-TO-END PIPELINE DATA-DRIVEN

This is the highest-priority integrity fix. A passing test on a hardcoded target is not sufficient.

## 1.1 Replace the hardcoded pipeline slice

Refactor `src/pipeline.py` into reusable functions with explicit inputs/outputs. The fixture CLI path can remain easy to run, but the core should be able to accept an arbitrary collection of normalized events plus identity metadata. Do not make a new identity-specific branch for the sample attacker.

The run should:

1. Load/ingest raw event sources through the existing ingestion layer.
2. Normalize and validate records; retain rejected/quarantined reasons.
3. Load identity/resource/action configuration.
4. Build event context and per-identity/session baselines without using ground-truth labels.
5. Run applicable detectors against single events and relevant timelines/session contexts.
6. Resolve identities and correlate Okta/CloudTrail events.
7. Build ordered incident chains from observed events and detector findings.
8. Calculate risk for every eligible identity and session, not one hardcoded identity.
9. Generate alerts only when calculated risk/findings exceed configurable thresholds; deduplicate on identity/session/incident window.
10. Compute recommendations and pass proposed actions to the simulator only.
11. Verify evidence references and append audit records.
12. Return an execution summary with actual counts, timings, warnings, and verification results.

Idempotent reruns must not duplicate normalized events, chains, alerts, feedback records, or audit entries. New event data must change the actual findings and metrics when appropriate.

## 1.2 Remove all hardcoded scenario values

Remove any target-specific constants from `src/pipeline.py`, `src/synthetic_generator.py`, `src/graph.py`, `src/harness.py`, and supporting modules, including:

- Sample usernames used as logic branches.
- Preselected factor values such as 90/40/95/85/90.
- Fixed alert `what`/`why` text unrelated to the evidence.
- Evidence IDs, line IDs, incident IDs, and timestamps fabricated for a particular identity.
- Chains, identity links, risk scores, alert records, or policy actions directly written by the generator as though they had been inferred.
- Attack labels derived from a username substring such as `"contractor" in identity`.
- Fixed latency values, pre-assigned rubric scores, fixed `PASS`/`VERIFIED` claims, or fixed metric deltas.

It is permitted to have synthetic users/resources in fixtures, known configuration values, configurable default thresholds, baseline weights, and test expectations. It is not permitted to use those values to bypass detection logic.

## 1.3 Risk factors: explicit, calculable definitions

Retain the five named factors from the current model and define each on a documented 0–100 scale:

1. `behavioral_anomaly`: based on detector findings, severity/confidence, event context, and deviation from the identity's own history or a suitable peer baseline. Use robust statistics where possible; handle insufficient samples and zero variance explicitly. Do not use detector labels to produce this score.
2. `privilege_level`: based on identity metadata, role/clearance, and the effective privilege tier before the observed event. Define the mapping in configuration. Do not infer an identity's privileges from its username.
3. `privilege_delta`: based on the incremental permissions/policies/actions gained by the identity during the investigated window relative to its previous effective permissions. Use a configurable IAM action/policy risk taxonomy.
4. `resource_sensitivity`: based on a configurable resource catalog and metadata (resource class, data classification, environment, and access scope). Match structured resource identifiers/patterns; do not scatter literal checks such as `"pii-vault" in resource` through rule code.
5. `sequence_stage`: based on the furthest valid stage in a reconstructed, ordered chain and whether required earlier stages are supported by evidence. Do not score a chain stage simply because an arbitrary string appears in an action.

Risk aggregation requirements:

- Store default factor weights in one configuration location. The default set can retain the existing relative weights, but configuration must validate weights, normalise as designed, and reject invalid/negative values.
- Every factor must include its raw value, active weight, contribution, calculation method/version, evidence references, and a reason for zero/unknown values.
- The final score is a bounded 0–100 result derived from the weighted values. Document rounding/clamping behavior.
- A missing factor must not be silently assigned a high value. Make missing data visible as unknown/low-confidence where appropriate.
- Every identity/session score must be reproducible from the same events, metadata, configuration, and model version.
- An analyst weight update must not retrospectively rewrite historical alert evidence without recording the model/config version used at decision time.

Add unit tests for each factor formula, boundary cases, empty/insufficient history, weight validation, contribution arithmetic, and score stability on identical input.

## 1.4 Build explanations from observations

Create alerts from the calculated score and the detector findings/chains that actually support them. `what`, `why`, `impact`, and evidence references must be generated from observed event fields and detector messages. They should identify concrete actions, resource names, relevant times, actor/session mapping confidence, and relevant IP/ASN/certificate differences when present.

Do not include personally identifying or sensitive data unnecessarily in the UI. Mask identities according to the existing dashboard control, but preserve precise evidence internally for audit purposes.

## 1.5 Evidence reference model and verification

Every finding/factor/alert reference must resolve to a real raw record and should include:

- Dataset-relative/source file path.
- Exact line number or stable record identifier.
- Raw `event_id`.
- SHA-256 hash of the exact raw record (excluding newline conventions consistently).
- Optional matched field names/values that explain why the record supports the claim.

Evidence verification must reopen the referenced source safely, confirm the record exists, recompute its hash, and verify the quoted fields actually match. It must not report 100% merely because reference strings are non-empty. Path validation must prevent traversal outside configured evidence roots. If evidence is missing or altered, fail the check and expose the exact failure reason.

---

# PHASE 2 — DETECTORS DET-01 THROUGH DET-06

Build detectors against the normalized event contract, identity metadata, baselines, and event/session context. Thresholds and allowlists must be configurable. Each detector result uses a consistent schema:

`rule_id`, `detected`, `status` (`DETECTED`, `NOT_DETECTED`, or `INCONCLUSIVE`), `attack_type`, `severity`, `confidence`, `event_id`, `evidence`, `evidence_refs`, and a concise rationale. Confidence is not the same thing as probability unless calibrated and documented.

A detector must not claim it detected an attack type it does not cover. A detector's evaluation must be scored against its own attack type, not all attacks in the data.

## DET-01 — Dormant-account reactivation

- Detect a successful login/session-start or relevant authentication event after a gap that exceeds the configured absolute and/or per-identity baseline threshold.
- Derive last-active time from historical events and identity metadata where available; define source precedence and timestamp semantics.
- Handle service accounts, scheduled automation, approved leave, known maintenance windows, and explicit reactivation exceptions via metadata/policy rather than username string checks.
- Include last active timestamp, gap duration, configured threshold, event timestamp, and the selected baseline in evidence.
- Do not fire on a non-authentication API call alone unless the rule specification explicitly supports it.

**Required tests:** dormant account positive; recently active negative; threshold equality; out-of-order event; missing last-active time; service-account/maintenance exception; timezone boundaries.

## DET-02 — Token/session abuse

- Evaluate session/token continuity across any applicable API call in the session window, not only `AssumeRole`.
- Compare prior observations for the same verified identity/session against the current IP, ASN, user-agent, certificate fingerprint, token/session ID, and timing.
- Detect suspicious reuse when signals change in a context that is inconsistent with policy. Use composite logic or calibrated confidence rather than treating every IP difference as malicious.
- Support benign roaming rules such as same `/24` plus same ASN, configured VPN egress changes, known device transitions, and approved session reauthentication.
- If session identity cannot be established, return `INCONCLUSIVE` or a lower-confidence identity-level finding instead of pretending the correlation is certain.
- Record both the baseline event and the new event as evidence.

**Required tests:** new IP within the session window; IP/ASN/UA/cert change on a later non-`AssumeRole` API call; same `/24` and ASN benign roam; same IP no finding; different ASN plus new UA; outside the window; missing session ID; multiple concurrent sessions; stable deterministic ordering.

## DET-03 — Privilege-escalation behavior and chain stages

- Use a configurable IAM action taxonomy covering at least `AttachUserPolicy`, `AttachRolePolicy`, `PutUserPolicy`, `PutRolePolicy`, `CreateAccessKey`, `UpdateAssumeRolePolicy`, `CreateLoginProfile`, and relevant policy/role operations present in the schema.
- Assess the effect of the permission change, the principal's prior privilege, the newly granted effective permissions, resource/environment, approval context, and prior chain stages.
- Distinguish a suspicious escalation from an expected authorized admin change using policy metadata, role duties, approved change windows, and available approval records.
- Multi-step chain detection must join separate events in time order and not require the exact literal `AdministratorAccess` string if structured permissions imply equivalent privilege.

**Required tests:** low-privilege identity gains admin permission; permission change using a different equivalent policy; benign approved admin change; action in taxonomy with no actual privilege delta; escalation sequence in and out of order; each newly supported IAM action.

## DET-04 — Unusual API calls

- Use per-identity and, where useful, peer-group baselines for action frequency, resource class, user-agent, and time-of-day patterns.
- Use a configurable sensitive-resource catalog with metadata for classification/environment/criticality. Do not rely on a fixed list of sample resource strings.
- Model novelty and frequency separately; a rare call to a low-sensitivity resource is not automatically equivalent to a high-impact call to a critical data store.
- Include whether the action or user-agent is novel, expected baseline, resource sensitivity, and observed record references in the explanation.

**Required tests:** sensitive resource access with a novel UA; common expected call; rare but low-impact action; a different sensitive resource configured without code changes; approved automation UA; insufficient baseline history.

## DET-05 — Impossible travel

- Compare authentication/login observations for the same identity/session using the previous relevant observation that has valid geo coordinates. Do not let an intervening CloudTrail event with no geo erase the prior login location.
- If geo may be carried forward within a session, mark it `INFERRED`/`CARRIED_FORWARD`, keep the source event reference, and reduce confidence accordingly. Never make inferred geo look like observed geo.
- Compute distance via the haversine formula and speed using a strictly positive elapsed time. Make minimum-distance, maximum-speed, and time-window thresholds configurable.
- Support configured known VPN egresses, approved travel, or geo uncertainty. Do not silently whitewash suspicious travel simply because a VPN is possible.
- If geo is missing, return `INCONCLUSIVE` with a reason, not a false negative masquerading as a completed geo check.

**Required tests:** London-to-Tokyo 15 minutes apart is detected when both endpoints have valid geo; same-city login is not; a no-geo intervening CloudTrail event does not hide the prior geo login; a zero-latitude/zero-longitude coordinate is processed; missing geo is inconclusive; zero/negative elapsed time; VPN allowlist; distance threshold boundary; timestamp ordering.

## DET-06 — Certificate-binding violation (extension)

- At session establishment, bind the verified certificate fingerprint to the appropriate identity/session key. The fingerprint must come from a trusted TLS-terminating component or verified TLS peer certificate, not arbitrary caller JSON.
- Detect use of the same session/token with a different certificate fingerprint, an unexpected disappearance of a required certificate, or use of an unbound/expired binding according to policy.
- A mismatch invalidates cached risk decisions immediately and triggers full risk evaluation / simulated step-up or revocation recommendation. Never let a mismatched fingerprint retrieve a previous low-risk cache entry.
- Support explicitly authorized certificate rotation, new session establishment, and documented renewal overlap. Benign certificate rotation must not trigger an attack alert when policy confirms it.
- Return both expected and observed fingerprints in appropriately masked UI form; preserve exact values in audit/evidence only where necessary.
- Add the chain stage `SESSION_HIJACK_OR_REPLAY` with correct provenance when supported by observed data. Do not fabricate an attack chain because a benchmark requested a mismatch test.

**Required tests:** matching fingerprint; mismatched fingerprint; missing required certificate; unbound session; benign approved rotation; a new session with a new certificate; stale cache invalidated on mismatch; no certificate value accepted directly from an untrusted HTTP body/header.

---

# PHASE 3 — REAL OKTA ↔ CLOUDTRAIL IDENTITY CORRELATION

The present implementation is reported to rely heavily on an exact `identity_key`/email join and nested event pairing. Replace that with explainable identity resolution while preserving uncertainty.

## 3.1 Identity candidate extraction

Extract and retain available identifiers from Okta events, such as actor ID, actor alternate ID, user ID, session ID, and relevant client/context fields. Extract and retain relevant CloudTrail fields, including `userIdentity.userName`, `userIdentity.arn`, `principalId`, `sessionContext`, assumed-role ARN/session name, access-key ID where safe, source IP, and request/event IDs.

Do not collapse all candidates into one lossy string. Normalize known identifier formats and preserve the original values for evidence.

## 3.2 Typed links with provenance

Use explicit link types and provenance, for example:

- `EXACT_ID` / `SESSION_ID`: strongest links only when the underlying source identifiers really match.
- `ROLE_SESSION_NAME`: a derived mapping based on an assumed-role session name and a documented identity mapping.
- `IP_TIME_WINDOW`: an inference from source IP and time proximity, never equivalent to a validated identity match.

Every link should record source event IDs, link method/type, confidence, time delta if applicable, evidence fields, and provenance (`VALIDATED_OBSERVATION`, `DERIVED`, or `INFERENCE`, or equivalent backward-compatible enum values). Do not call a link “validated” only because two heuristic fields happen to match.

## 3.3 Efficient correlation

- Build inverted indexes by normalized identity candidate, session ID, role-session name, and time bucket/IP as appropriate.
- Avoid a full Okta-by-CloudTrail nested cross product. Aim for approximately `O(n log n)` processing or document a measured, justified complexity bound.
- Confidence for weak links must account for timestamp separation, identifier ambiguity, and signal quality. Define the decay formula and unit-test it.
- Allow one-to-many identity/session relationships where legitimate. Avoid creating every possible edge without pruning.

## 3.4 Chain reconstruction

- Build stages from event semantics and detections, not labels.
- Sort by normalized UTC event time with deterministic tie handling.
- Deduplicate repeated observations of the same stage without deleting meaningful repetitions.
- Validate expected stage ordering and required transitions. Record `unresolved` gaps when evidence is insufficient.
- Keep provenance and supporting event references on each stage and link.
- Do not mark a chain correct merely because the subject has any chain. Evaluation must compare stage sequence and stage evidence to ground truth.

**Required fixture:** an Okta event using an `alternateId` such as `bob@corp.internal` must correlate with CloudTrail whose `userName` differs (for example `bob-c`) through a supported role/session/principal mapping. That test must fail when the relevant mapping field is removed. This fixture demonstrates genuine cross-source correlation rather than an exact email join.

---

# PHASE 4 — SYNTHETIC DATASET THAT DOES NOT WRITE THE ANSWERS

## 4.1 Refactor the current synthetic demo generator

The current generator reportedly creates chains, scores, alerts, and weight updates directly while generating events. Remove that behavior. Synthetic generation must create **raw Okta-shaped and CloudTrail-shaped records only**, plus a separate evaluation label file. Then run the same ingestion, detectors, stitching, scoring, alerting, simulator, and evidence-verification pipeline used for normal input.

Generated labels must not be embedded into the detector-visible fields in a way that reveals the outcome. Keep attack-generation metadata/labels outside the normalized event signal path.

## 4.2 Reproducible dataset generator

Provide `scripts/generate_dataset.py` with arguments such as:

`--seed 42 --identities 60 --days 30 --events 5000 --attacks 40 --noise <level> --difficulty <level> --output <directory>`.

Required behavior:

- The same seed and configuration produce the same raw dataset and labels.
- Generate at least 5,000 events across many identities and sessions for the default full profile, unless a documented resource constraint requires a configurable smaller test profile.
- Include benign background activity: normal logins, ordinary API requests, approved admin changes, service-account/CI/CD activity, normal retries, failed MFA that is not automatically malicious, VPN egress changes, new-device logins, occasional geo gaps, and varying event density.
- Include at least 40 attack episodes spread across the five original attack patterns and the DET-06 certificate-binding replay extension. Define per-pattern minimum counts and assert the generated dataset meets them.
- Include hard negatives: legitimate privileged administrators, approved sensitive-resource access, benign travel, expected UA changes, legitimate certificate renewal, and session re-authentication.
- Write raw event files plus a separate labels file with event-level labels, `attack_type`, session-level truth, identity-level truth, and ordered chain-stage truth. Preserve a stable event ID mapping between raw records and labels.
- Record the seed, generator version, configuration, dataset hashes, counts, and generation timestamp in a metadata manifest.
- Provide `--quick` or an equivalent smaller deterministic profile for CI and demos.

Do not tune a detector or weight on the held-out test labels. Generator metadata is for evaluation and reproducibility only.

## 4.3 Generated demo path

When the UI's “generate synthetic incident” action runs, it must write/ingest the synthetic raw records, invoke the real pipeline, and display the resulting model output. It must not directly insert a pre-scored `Alert` and `IncidentChain` and then imply that the detector discovered them.

If an intentionally scripted demo wants a guaranteed attack, record the attack pattern in a separate demo label/manifest but still pass all actual events through the engine.

---

# PHASE 5 — EVALUATION THAT A STRICT JUDGE CAN REPRODUCE

## 5.1 Correct label semantics

Create a single documented evaluation label schema, for example:

- `event_id -> benign or one/more attack_type labels`.
- Session labels derived from explicit session ground truth.
- Identity labels derived from whether an identity is compromised in the labelled window.
- Chain labels containing the expected ordered stages and event IDs supporting each stage.

Do not evaluate every detector against a global “any attack” flag. DET-01 is scored against dormant-reactivation truth, DET-02 against token/session-abuse truth, etc. For multi-label events, document whether the evaluation is multi-label or chooses one primary type.

## 5.2 Leakage-safe split

- Split by whole identity, not random individual events. No events from one identity may leak across train/calibration and held-out test partitions.
- Use a reproducible seed and persist the exact identity sets and dataset hashes in the report.
- Keep detector threshold/weight tuning separate from the final held-out test set.
- Include a check proving that a test identity has no representation in the training/calibration set.

## 5.3 Metrics required

Compute from actual predictions and labels, not constants:

- Event-level precision, recall, F1, false-positive rate, and confusion counts.
- Per-detector metrics against that detector's own attack type.
- Identity-level alert precision/recall/F1.
- Session-level alert precision/recall/F1.
- Chain stage precision/recall/F1 based on ordered stage alignment, with exact-chain match reported separately.
- Baseline metrics on precisely the same split, label schema, and evaluation protocol.
- Delta against baseline computed from measured values.
- Evidence-reference validation rate with valid/invalid counts.
- Explanation-quality checks with separate computed booleans/results and explicit failure details.
- Confidence intervals for key metrics (bootstrap or a documented appropriate method), including the sample size and seed. If the sample is too small to estimate an interval meaningfully, state that instead of fabricating one.

When a metric's denominator is zero or the metric is not computable, use a documented `null`/`NOT_COMPUTABLE` value rather than automatically reporting 1.0.

## 5.4 Ordered-chain metrics

Do not count a chain as recovered just because a chain exists for the expected subject. Align predicted and expected ordered stage sequences and calculate stage-level TP/FP/FN. Report:

- Ordered-stage precision/recall/F1.
- Exact sequence match rate.
- Missing stages, extra stages, duplicate stages, and out-of-order stages.
- Chain count and the number eligible for evaluation.

Add regression fixtures with a duplicate stage and with the correct stages in the wrong order; both must fail exact match.

## 5.5 Explanation rubric: execute actual assertions

For each evaluated alert, verify:

1. The top contributing factors are sorted from calculated contributions.
2. Each displayed contribution equals `weight * factor_value` within documented rounding tolerance.
3. The aggregate score equals the stated weighted calculation and clamping behavior.
4. Each counterfactual is recomputed by rerunning the scoring function without/with the factor change; it is not an authored arithmetic sentence.
5. Every evidence reference resolves to the raw data and its cited fields match the claim.
6. Each claimed chain stage has a real source event and provenance.
7. Explanations do not cite unrelated events.

Return the actual number of checks run, checks passed, checks failed, and failure details. Do not hardcode `PASS`, `VERIFIED`, or rubric score `1.0` in `src/harness.py`.

## 5.6 Latency and throughput methodology

Remove constant latency dictionaries from the evaluation path. Measure the real pipeline using a monotonic high-resolution clock and state which interval is being measured. Separate at least:

- Pure detector/score execution latency, if useful.
- End-to-end event processing latency (event accepted/arrival to emitted alert or completed decision).
- Total dataset replay time and throughput.
- mTLS HTTP/TLS timings (covered in Phase 7).

For pipeline replay, publish load profile: event count, number of identities/sessions, replay rate or arrival schedule, worker count/concurrency, warm-up, number of runs, seed, operating system, Python/runtime version, and relevant machine information. Report p50/p95/p99 and mean from observed samples. Do not treat looping the same 11 records 2,500 times as a 2,500-distinct-event representative workload; generated events must have realistic distinct IDs, times, identities, and distributions.

## 5.7 Evaluation harness commands and report

Update the existing `src/harness.py` / CLI without breaking useful public behavior. Provide reproducible commands to generate the dataset, evaluate it, export JSON, and run mutation tests. Suggested outputs:

- `docs/EVAL_RESULTS.md` — human-readable summary plus known weaknesses.
- `eval_report.json` or a versioned JSON report with raw counts and settings.
- A script such as `scripts/make_report.py` to generate docs from saved, real command outputs.

Mutation tests must show metrics change when labels or predictions are deliberately changed. Add tests that fail if a constant metric is returned regardless of the labels/events.

---

# PHASE 6 — ANALYST FEEDBACK, RESPONSE POLICY, AND ATTACK GRAPH

## 6.1 Analyst feedback must be genuinely analyst-driven

Remove `autonomous_tune_from_attack` from the normal synthetic generation flow. A synthetic attack must never train the model simply because the generator knows that it created an attack.

The feedback workflow should accept:

- Alert ID and immutable alert/model version.
- Analyst verdict such as true positive / false positive / benign-but-policy-relevant.
- Required rationale or reason code.
- Analyst identifier (use a configured identity in local demo mode; do not trust a client-supplied analyst name as proof of authentication in a deployed system).
- Optional factor-level correction when an analyst knows which factor is over/underweighted.

Requirements:

- Persist feedback, prior weights, new weights, rationale, actor, timestamp, model/config versions, and audit-chain linkage to the configured database.
- Reload current weights and history at startup. Restarting the API must not reset feedback.
- Apply bounded, documented weight adjustments and preserve valid weight normalization. Reject unknown factors and malformed verdicts.
- Revert must create an auditable compensating action; it must not erase prior records.
- A new feedback decision invalidates relevant risk-decision cache entries.
- Show before/after score for the affected evidence using the recorded historical model version and the current model version separately.
- Evaluate any claimed feedback benefit on a held-out/calibration slice. Do not report improvement merely because the weight moved in the expected direction.

**Required tests:** increase/decrease within bounds; invalid factor rejected; persistence after module/application restart; rollback leaves audit trail; feedback invalidates cache; synthetic generator does not tune weights; metrics on held-out data are computed before and after.

## 6.2 Simulator and protected identities

All action outcomes remain simulated. Update the simulator to load `is_protected` and other relevant identity policy metadata from `fixtures/identities.json` (and any configured metadata source), with defense-in-depth patterns for root/break-glass principal formats.

Requirements:

- Protected metadata must be authoritative for configured identities. Do not maintain a separate hand-written set that silently omits an identity marked protected in `identities.json`.
- `RESTRICT` and `REVOKE_SESSION` against a protected identity must be denied by policy. `STEP_UP`/`MONITOR` behavior must be explicit and tested.
- High-impact simulated action requires approval; API cannot bypass the approval state by editing a body field.
- Every preview, approval/denial, result, rollback plan, actor, and rationale is audit logged.
- Prevent duplicate execution on request retries using an idempotency key or stable action ID.
- The API and UI must use language such as `SIMULATED`, `PENDING_APPROVAL`, or `DENIED_PROTECTED_IDENTITY`; never claim a real IAM action occurred.

**Required tests:** every fixture identity marked `is_protected`; `diana.admin` specifically if present as protected in the metadata; root ARN; equivalent break-glass identifier; unapproved restriction; approved simulation; replayed request; malicious attempt to target a protected account by alternate identifier.

## 6.3 Risk-based action recommendations using expected loss

Replace fixed expected-loss numbers with a documented, configurable calculation. Input features can include:

- Current risk and confidence.
- Identity role criticality and privilege tier.
- Resource sensitivity and environment.
- Session age and current session/certificate state.
- Estimated compromise impact.
- Expected business interruption by action.
- Historical false-positive rate for this rule/identity segment.
- Availability of safer step-up authentication.

Estimate comparable expected loss for candidate simulated actions `MONITOR`, `STEP_UP`, `REVOKE_SESSION`, and `RESTRICT`, then choose the action with the lowest estimated loss subject to hard security invariants and approval requirements. Document formula, units, parameter sources, and uncertainty. Do not imply calibrated monetary losses if the inputs are only relative utility points.

Show the action trade-off in the API and dashboard: why the chosen action is preferred, expected security benefit, expected disruption, uncertainty, and the runner-up. Hard constraints (e.g. protected-account restrictions) override a low expected-loss score.

Test that changing a genuine input changes the expected-loss calculation and/or recommendation where mathematically appropriate, while protected identity constraints remain invariant.

## 6.4 Attack graph

Use the computed identity links, detector evidence, resource-sensitivity configuration, and ordered chain stages to create the graph. Nodes may represent identities, sessions, events, resources, roles, and permissions. Edges must have type, direction, confidence, provenance, and supporting evidence IDs.

- Remove hardcoded sensitive-resource dictionaries.
- Rank paths using a documented formula that accounts for privilege gain, resource sensitivity, number of transitions/hops, observed-vs-inferred edge confidence, and time coherence. Define whether a larger score means higher risk.
- Distinguish observed links from inferred links visually.
- Highlight certificate-binding/session replay branches from DET-06.
- Do not turn an inferred correlation into a solid “confirmed” edge.

Tests must cover graph node/edge provenance, deterministic ordering, the effect of configured resource sensitivity, path ranking, and the DET-06 branch.

---

# PHASE 7 — mTLS + RISK-ADAPTIVE DECISION CACHE

This feature must be genuine locally testable mTLS plus a correctly scoped decision cache, not just a dashboard animation.

## 7.1 Correct product claim

Use the following technical distinction consistently:

> **mTLS always validates the peer certificate according to policy. The fast path caches a short-lived risk decision for a verified, certificate-bound identity/session and avoids unnecessary repeated risk-analysis work. A certificate mismatch, high risk, policy change, or invalidated session forces the full decision path and simulated step-up/revocation policy.**

Do not claim “mTLS handshakes are eliminated,” “TLS is faster because risk is lower,” or “certificate validation is skipped.” Report separately the measured TLS handshake/request latency and the extra risk-engine decision overhead. Only claim TLS session-resumption benefits if the benchmark confirms that resumption actually occurred.

## 7.2 Certificate generation and local development setup

Add `scripts/gen_certs.py` using a supported cryptographic library or a clearly documented OpenSSL-based implementation. It should generate local-development-only materials:

- A local CA.
- A server certificate with `localhost` and `127.0.0.1` subject alternative names.
- At least two ordinary test client certificates and one separate attacker/replay client certificate.
- Modern, locally supported elliptic-curve keys (P-256 acceptable) and explicit short test validity.
- A printed SHA-256 certificate fingerprint for each client certificate.
- A non-interactive repeatable mode suitable for a clean clone.

Private keys and generated certificates must go under a git-ignored `certs/` directory and must never be included in the submission ZIP. Do not use production certificates or user secrets.

If a crypto dependency is added, declare it in `requirements.txt` with a supported version range and test installation from a clean environment. Document any platform/runtime requirements.

## 7.3 `src/mtls.py` service core

Implement separately testable primitives:

### Certificate fingerprint

- `cert_fingerprint(der_bytes) -> str`: SHA-256 fingerprint of the DER-encoded peer certificate, normalized to one canonical lowercase hex representation.
- Reject empty/malformed inputs as explicit errors; never fingerprint a string representation of a certificate in place of DER bytes.

### Verified peer identity

- Represent certificate fingerprint, validation result, issuer/CA context, validity state, and provenance as a trusted transport observation.
- Keep an explicit distinction between a fingerprint verified by the local TLS server, a fingerprint injected by a trusted reverse proxy, and a fingerprint supplied by a simulated demo.
- An ordinary client must not be able to set its own trusted fingerprint by submitting JSON or an arbitrary header directly to FastAPI.

### Certificate-binding store

- Bind an identity/session composite key to the certificate fingerprint established for that session, with created/last-seen timestamps and policy/version metadata.
- Return distinct states such as `MATCH`, `MISMATCH`, `UNBOUND`, and `NO_CERT`.
- Define session binding lifetime, identity change behavior, concurrency safety, and persistence/eviction requirements.
- Ensure two identities cannot collide merely because they reused the same textual `session_id`.
- `MISMATCH` must invalidate relevant cached decisions before any cache lookup can return a fast-path result.
- Support an explicit approved rotation/rebind workflow with audit evidence; do not silently overwrite the old fingerprint when a mismatch appears.

### Risk-adaptive policy

- Policy receives the **computed current risk score**, cert-binding state, current authentication/session validity, policy version, and cache status.
- Store the thresholds in `src/config.py` or dedicated config, not in scattered conditions. Defaults may follow the existing proposal: risk `<30` can qualify for `FAST_PATH`; `30–59` uses `ASYNC_RESCORE` or another explicitly implemented middle-band policy; risk `>=60` forces `FULL_VERIFY_STEP_UP`. Any certificate mismatch overrides the risk-band decision and forces the high-risk path.
- Name `ASYNC_RESCORE` only if asynchronous re-scoring is actually implemented with bounded queues, timeouts, failure handling, and a safe interim decision. Otherwise use an honest synchronous full-rescore policy name.
- A low score alone does not qualify for fast path: verified certificate, active identity/session, matching binding, unexpired decision, and unchanged policy version are also required.
- Define fail-closed behavior for cache errors, binding-store errors, stale events, and inability to compute risk.

### Decision cache

- TTL configurable; initial default can be 60 seconds.
- Bounded LRU or similarly bounded structure; thread-safe if accessed concurrently.
- Key includes identity, session, trusted certificate fingerprint, and any policy/model version needed to prevent stale decisions being reused under a changed model.
- Store decision, risk score, creation/expiry timestamp, and evidence/model-version references.
- Expose hit, miss, expiry, invalidation, and bypass counters.
- Invalidate on new relevant events for the identity/session, certificate mismatch/rotation, analyst feedback, policy/config/model changes, session expiration/revocation, or changed identity privilege metadata.
- Never cache a decision for a mismatched, unbound, unverified, or missing-required-certificate state.
- Do not claim cache correctness merely because a hit counter incremented; test the decision returned and its freshness.

## 7.4 API integration

Add and document routes consistent with the existing FastAPI conventions:

- `POST /api/mtls/decide` — evaluate an authenticated, certificate-bound identity/session. Return decision path, calculated risk, cache hit/miss, cert-binding result, evidence/reason references, decision latency measured by the server, model/policy version, and explicit label such as `SIMULATED_ENFORCEMENT` for actions that are only simulated.
- `GET /api/mtls/stats` — counters and measured latency distribution (sample count and window included), not fabricated percentiles.
- A narrowly scoped replay/demo endpoint or existing synthetic-demo integration to demonstrate the certificate mismatch. All injected fingerprints must be unmistakably synthetic and inaccessible as a production trust source.

Security rules:

- Prefer extracting the peer certificate directly from the TLS server connection. If using a reverse proxy, the proxy must terminate mTLS, validate the peer certificate, strip incoming client-supplied copies of the fingerprint header, and inject a fresh verified header.
- Trust `X-Client-Cert-Fingerprint` only when the request truly came from an explicitly configured trusted proxy address/interface. Reject or ignore the header for untrusted peers and log the rejected trust attempt without leaking secrets.
- Do not trust `cert_fingerprint` passed in JSON as a proof of certificate possession.
- Bind by verified identity/session and certificate, not by IP address alone.
- Do not bind the dev API to a public interface by default. The current API is a local development/demo service, not production-ready deployment.

Add explicit schema validation, rate/bounds protection for inputs, and tests for spoofing, missing TLS context, trusted proxy handling, malformed fingerprints, and cache invalidation.

## 7.5 Real local mTLS endpoint

Provide a local test server using a supported standard TLS stack (for example Python `ssl` with a small HTTPS server, or the existing FastAPI app behind a documented local TLS terminator). Enforce client certificate validation (`CERT_REQUIRED` or an equivalent explicit config), trust only the generated local CA, extract the actual peer certificate, and pass the verified fingerprint into the risk-policy service.

The demo must show:

1. A normal client with a valid certificate and low-risk session produces a risk-decision cache hit/eligible fast path after the first computed decision.
2. A token/session replay using a different generated client certificate is detected as `MISMATCH`, invalidates the cache, produces a real DET-06 finding with raw event references, and asks the simulator for step-up/revocation according to policy.
3. A certificate that does not chain to the configured CA is rejected by the TLS layer before a risk fast path can run.
4. A benign, explicitly approved certificate rotation can be handled without a false attack alert.

If the runtime makes actual TLS session resumption unavailable, the report must say `UNSUPPORTED` for that scenario and must not make up a resumption number. Test connection reuse/keep-alive separately from TLS session resumption: they are different mechanisms.

## 7.6 Reproducible mTLS benchmark

Add `scripts/bench_mtls.py`, a configurable request-count/concurrency benchmark with a small `--quick` mode for demo/CI and a larger full mode (target 2,000 or more requests per supported scenario). Use a fixed seed where randomness is involved. Use a monotonic high-resolution clock, explicit warm-up, repeat runs, bounded concurrency, and real requests through the actual local server/service.

Measure separately the supported cases:

1. Plain local HTTP request baseline.
2. TLS request without a client certificate where the test endpoint permits this comparison only.
3. mTLS with a new connection and full handshake per request.
4. mTLS keep-alive/persistent connection with requests reusing the established connection.
5. mTLS TLS session-resumption path, **only if the runtime reports actual session reuse**; record a reuse indicator and otherwise mark unsupported.
6. mTLS plus an uncached full risk decision.
7. mTLS plus a warm, valid risk-decision cache hit.
8. mTLS after certificate-binding mismatch and cache invalidation.
9. Optional cold-cache startup path, if distinct from case 6 in this implementation.

For every case report request count, successes/failures, concurrency, warm-up, p50/p95/p99/mean request latency, throughput, decision overhead where measurable, TLS handshake timing where measurable, and cache counters. Capture OS, Python, TLS/OpenSSL version, CPU/memory best-effort, server mode, dataset/seed, and benchmark flags. Save both machine-readable and human-readable output:

- `docs/MTLS_BENCHMARK.json`
- `docs/MTLS_BENCHMARK.md`

The report must be generated from measured results, include failed requests and uncertainty, and describe the limitations of localhost benchmarking. Do not hide scenarios in which mTLS or the risk engine is slower. Distinguish request latency from handshake latency and throughput. Do not claim general production performance from a localhost result.

## 7.7 Required mTLS tests

Create `tests/test_mtls.py` or a suitable set of focused files for:

- Deterministic certificate fingerprint from the same DER bytes.
- Invalid/empty DER handling.
- `MATCH`, `MISMATCH`, `UNBOUND`, `NO_CERT` binding states.
- Identity/session key isolation.
- Cache TTL expiry, LRU bound, hit/miss counters, concurrent access if supported.
- Invalidation on new event, cert mismatch, session expiry, analyst feedback, and policy/model version change.
- Threshold boundaries exactly below/at/above configured limits.
- Mismatch always overrides a low risk score and never returns a cached `FAST_PATH`.
- Valid low-risk session can use cached **risk decision** but still requires a valid TLS certificate.
- Unknown/invalid/untrusted certificate cannot qualify for fast path.
- Untrusted caller cannot spoof a fingerprint through JSON/header.
- Trusted proxy and direct TLS peer extraction behavior.
- Protected-account policy still applies to any proposed simulated action.
- Benchmark quick mode yields one actual result record for every supported scenario and explicit `UNSUPPORTED` records where appropriate.

## 7.8 Dashboard integration

Integrate with the existing SOC visual language; do not replace the dashboard with a separate mock page. Use component extraction where practical instead of making `web/src/App.tsx` even harder to maintain.

Add an **mTLS / Risk Decision** panel showing:

- Recent decisions and timestamps.
- Decision path (`FAST_PATH`, `FULL_RESCORING`, `FULL_VERIFY_STEP_UP`, etc.).
- Masked identity and session display.
- Certificate-binding state (`MATCH`, `MISMATCH`, `UNBOUND`, `NO_CERT`).
- Calculated risk score, cache hit/miss, evidence references, and reason.
- Measured cache hit ratio with denominator/sample count.
- Measured p50/p95/p99 decision latency with time window.
- A chart/table of the benchmark cases and their actual results.
- A **Replay certificate-bound session** action that drives the real local simulated flow and displays the resulting DET-06 evidence and proposed simulator action.

UI rules:

- Never show fake live measurements as if they were measured.
- Distinguish benchmark data from the current live demo feed.
- Keep log/event strings as text; do not use `dangerouslySetInnerHTML`.
- Preserve the existing mask-identities control, incident queue, factor details, provenance timeline, graph, model feedback panel, and simulator approval flow.
- Add loading, empty, stale-data, API-error, and unavailable benchmark states.
- Avoid hardcoded `localhost` URLs scattered through the app; centralize API base URL according to current project conventions.

---

# PHASE 8 — API, CONFIGURATION, OBSERVABILITY, AND SECURITY REVIEW

## 8.1 API model integrity

Use typed Pydantic request/response models for new and modified routes. Validate enums, numeric bounds, list lengths, string lengths, and expected structures. Avoid broad `Dict[str, Any]` at trust boundaries where a schema is known. Retain unknown source log fields only in the evidence-normalization layer with appropriate sanitization.

Ensure the API does not allow callers to:

- Set their own trusted certificate fingerprint.
- Mark an alert as verified or approved by submitting a string.
- Bypass simulator approval gates.
- Inject Mongo query operators through filters or request data.
- Request arbitrary file reads through evidence paths.
- Change risk/model/threshold configuration without an explicit administrative path and audit event.

## 8.2 Application-level logging and audit

- Add structured logs for pipeline execution IDs, counts, durations, rule IDs, cache invalidations, and failure reasons.
- Do not log private keys, secrets, full bearer tokens, or unnecessary sensitive personal data.
- Preserve the existing hash-chained audit log. Add records for analyst feedback, policy changes, simulated actions, certificate binding/mismatch, and cache invalidation where security-relevant.
- Make audit verification test alteration, deletion, reordering, and incorrect previous hashes.

## 8.3 Configuration layout

Use one documented configuration source for at least:

- Factor weights and alert thresholds.
- Per-rule distance/time/inactivity/session thresholds.
- IAM action-to-risk taxonomy.
- Resource sensitivity catalog.
- Known VPN/ASN/user-agent exceptions and certificate-rotation policy.
- Protected identity policy patterns.
- Risk-adaptive mTLS threshold bands, cache TTL/capacity, and trusted proxy addresses.
- Evaluation dataset size, seed defaults, and load profiles.

Provide safe defaults, schema validation, and clear startup errors for invalid configuration. Fixture-specific values belong in fixtures, not conditionals in core code.

---

# PHASE 9 — CLEAN UI/UX, TRUTHFUL DOCUMENTATION, AND PACKAGING

## 9.1 Keep the dashboard evidence-led

Review every metric, score, status, factor bar, alert, chain stage, cache number, and certificate state displayed in the UI. Each must originate from an API response that is computed or from a clearly labelled, previously generated benchmark report.

For each alert, the UI should be able to display:

- Risk score and factor contributions.
- Detector IDs and attack type(s).
- Evidence references that resolve to raw events.
- Chain stages with link provenance/confidence.
- Recommendation and expected-loss tradeoff.
- Simulated action status/approval state.
- Model/config version and label (`SYNTHETIC` / real source classification).

Avoid showing synthetic ground truth as if it were an engine prediction. In a demo, make it possible for judges to distinguish **ground truth label** from **detector prediction** without leaking labels into prediction generation.

## 9.2 Documentation refresh

Update:

- `README.md` — quick start from clean clone, requirements, commands, architecture, data flow, safety boundaries, evaluation instructions, mTLS demo, actual benchmark methodology, and known limitations.
- `docs/IMPLEMENTATION_MAP.md` — actual module/function route map.
- `docs/EVAL_RESULTS.md` and dataset report — generated results, per-detector weaknesses, baseline comparison, confidence intervals/sample counts, and split details.
- `docs/MTLS_BENCHMARK.md` / JSON — generated by the benchmark.
- `docs/DEMO_MTLS.md` — a 60–90 second truthful demo sequence: normal valid certificate, real decision cache hit, replay with different certificate, DET-06 evidence, simulator proposal, and benchmark table.
- `docs/LIMITATIONS.md` — at minimum: synthetic data limitations; no live cloud/Okta integrations; local benchmark limits; whether true session resumption was supported; proxy-header trust requirements; no claim of production readiness; missing geo/correlation uncertainty.
- `docs/TRACK2_FINAL_VERIFICATION.md` — commands and actual outputs only. Every numerical claim must be generated from a saved report or tied to a command output; no hand-written metrics that can drift.

Search existing documentation for contradicted statements such as “zero hardcoded usernames,” invented factor names, protected identities not represented in metadata, hand-typed F1/latency values, or claims that the current data volume proves broad accuracy. Correct or remove any claim not supported by the current code and recorded command output.

## 9.3 Packaging

Harden `scripts/package_submission.py`. It must create a clean distributable from an allowlist or carefully reviewed exclusion rules. Do not include:

- `.git/`, `__pycache__/`, `*.pyc`, `.pytest_cache/`, build caches, `node_modules/`, generated `dist/` unless explicitly required.
- Nested ZIP archives such as `zero_trust_track2_submission.zip`.
- Private keys, generated certs, `.env`, tokens, developer secrets, or local databases.
- Vibecoding/beginner guides, full skill packs, internal implementation prompts/build prompts, irrelevant duplicate PDFs, local scratch reports, or generated temporary artifacts unless the contest specifically requests them.

Keep source, relevant tests, core requirements/configuration, UI source/build instructions, fixtures necessary for the demo, relevant product documentation, and license/attribution files. Avoid deleting these files from the working repo; exclude them only from the generated package.

Requirements:

- Package the submission from a temporary staging tree or explicit inclusion list.
- Exclude the output ZIP itself and any prior ZIP archives.
- Run `ZipFile.testzip()` and inspect the final archive listing.
- Target a final archive below 15 MB if compatible with required dependencies/assets. If above target, report the real size and identify largest included files rather than silently omitting required components.
- Unpack into a fresh temporary directory and test the documented clean-clone quick start using only packaged files. Do not use local generated certs or untracked files that were not packaged.

---

# PHASE 10 — FINAL REGRESSION AND ACCEPTANCE MATRIX

Run every check that the environment permits and record exact results. At minimum, attempt:

```bash
python -m pytest tests -q
python -m src.cli run-all
python -m src.cli eval
python scripts/generate_dataset.py --seed 42 --identities 60 --days 30 --events 5000 --attacks 40 --output data/generated_eval
python -m src.cli eval --help
python scripts/gen_certs.py
python scripts/bench_mtls.py --quick
npm --prefix web run build
python scripts/package_submission.py
```

Adjust commands to the actual CLI/API implementation when needed, and document the exact supported commands. Do not claim a command succeeded if it was not run. If an optional service such as MongoDB is missing, use the project's supported mock/local test backend for tests; clearly separate service-unavailable commands from code failures.

## 10.1 Definition-of-done matrix

Mark each item `PASS`, `FAIL`, `PARTIAL`, or `NOT RUN` **only from observed evidence**. A pass must cite the test/report/command that proves it.

### Data integrity and pipeline

- [ ] Normal detection pipeline does not read ground-truth labels.
- [ ] Pipeline scores every eligible identity and session, not one hardcoded target.
- [ ] No username substring is used as attack ground truth.
- [ ] Generator creates raw events/labels only; detections, chains, risk scores, alerts, and actions are derived by the normal pipeline.
- [ ] Replays are deterministic and idempotent.
- [ ] Factor values, explanations, evidence IDs, timestamps, and metrics are data-derived.

### Detectors

- [ ] DET-01 positive/negative/edge-case tests pass.
- [ ] DET-02 detects suspicious session reuse on any relevant API event, not only `AssumeRole`.
- [ ] DET-02 allows configured benign roaming without losing the malicious case.
- [ ] DET-03 uses permission/action metadata and distinguishes approved admin changes from suspicious escalation.
- [ ] DET-04 uses configured resource sensitivity and per-identity/peer baselines rather than brittle sample strings.
- [ ] DET-05 detects London-to-Tokyo in 15 minutes with valid geo even when an intervening event has no geo.
- [ ] DET-05 treats missing geo as inconclusive and handles zero-valued coordinates.
- [ ] DET-06 detects certificate-bound session replay/mismatch and does not alert for policy-approved rotation.
- [ ] Each detector returns normalized rule/severity/confidence/evidence/event/attack-type output.

### Identity correlation and chains

- [ ] Okta alternate identity and AWS role/session identifiers are correlated in a fixture that would fail under exact-email-only matching.
- [ ] Link provenance distinguishes observed, derived, and inferred relationships.
- [ ] Correlation avoids an unbounded Okta-by-CloudTrail cross product; measured/runtime complexity is documented.
- [ ] Chains use ordered, deduplicated stages with unresolved gaps and stage evidence.
- [ ] Evaluation measures ordered-stage F1 and exact sequence match, not only chain existence.

### Scoring, explanations, evidence

- [ ] Every risk factor is calculated from event/identity/resource metadata using a documented method.
- [ ] Weights are validated and historical model/config versions are preserved.
- [ ] Explanation checks execute real assertions; no hardcoded `PASS`, `VERIFIED`, or `1.0` rubric result.
- [ ] Counterfactual is re-calculated by the score function.
- [ ] Every evidence reference resolves to a raw record; its hash and cited fields are verified.
- [ ] Broken or changed evidence produces a failure with a clear reason.

### Evaluation

- [ ] Dataset generator reproducibly emits the configured event/attack counts.
- [ ] Labels are independent of detector-visible data and never enter the detection path.
- [ ] Split is by whole identity with no identity leakage.
- [ ] Per-detector metrics use per-attack labels.
- [ ] Event/session/identity/chain metrics, counts, baseline comparison, and confidence intervals are actually computed.
- [ ] Changing a label or prediction changes the appropriate metrics.
- [ ] Pipeline latency/throughput is measured from actual execution with the load profile published.
- [ ] Weak recall and false positives are documented rather than hidden.

### Feedback, simulator, and graph

- [ ] Feedback requires a verdict/rationale and persists across restart.
- [ ] Synthetic generation does not update weights.
- [ ] Reverts are reversible and auditable without deleting history.
- [ ] Feedback invalidates affected cached decisions.
- [ ] Protected identities are loaded from metadata and cannot be automatically restricted or revoked contrary to policy.
- [ ] High-impact actions require simulator approval and are idempotent/audited.
- [ ] Recommendations derive expected loss from defined inputs and show uncertainty/tradeoff.
- [ ] Graph uses evidence/provenance/configuration and distinguishes inferred links.

### mTLS / fast risk path

- [ ] Local mTLS handshake requires a trusted client certificate.
- [ ] Certificate fingerprint comes from verified transport or an explicitly trusted proxy, not arbitrary body/header input.
- [ ] Valid low-risk session can reuse a fresh cached risk decision only after current certificate/session checks pass.
- [ ] Certificate mismatch invalidates cache before lookup and forces full risk decision path.
- [ ] Untrusted certificate is rejected before a fast-path decision.
- [ ] Cache TTL, LRU, isolation, versioning, counters, and invalidation tests pass.
- [ ] Benchmark includes all supported scenarios with real request counts/timings and honest unsupported states.
- [ ] Report lists host/runtime/load parameters and separates handshake, request, and risk-decision costs.
- [ ] UI shows measured data and a runnable replay demo without fake success values.

### Safety, UI, docs, packaging

- [ ] No live AWS/Okta calls or real enforcement actions are introduced.
- [ ] Existing API sanitization, CSP, XSS protections, audit chain, and simulator safeguards remain covered by tests.
- [ ] New UI preserves current SOC capabilities and renders untrusted log strings as plain text.
- [ ] README and final verification agree with current code and real output.
- [ ] Private certificates/keys and secrets are excluded from the ZIP.
- [ ] Submission archive has no nested ZIPs, caches, `.git`, skillpack, or internal build prompts.
- [ ] Archive integrity passes and a clean extracted copy can follow the quick start.

---

## 11. REQUIRED FINAL REPORT FORMAT

At completion, provide a concise but evidence-backed implementation report with these sections:

1. **Executive status:** what is genuinely complete and what remains incomplete.
2. **Repository changes:** grouped by pipeline/detectors/correlation/scoring/evaluation/feedback/simulator/mTLS/UI/docs/package.
3. **Acceptance matrix:** each requirement marked `PASS`, `FAIL`, `PARTIAL`, or `NOT RUN` with exact test/report/command evidence.
4. **Test commands and actual outputs:** include exit codes and important counts; never paraphrase a failed command as passing.
5. **Evaluation results:** dataset size, seed, attack counts, identity split, per-detector precision/recall/F1, event/session/identity/chain metrics, baseline, confidence intervals, evidence integrity, real measured pipeline latency and load profile.
6. **mTLS benchmark:** supported/unsupported scenarios; request count, concurrency, host/runtime details, p50/p95/p99/mean; separate handshake, request, and risk-decision overhead; actual cache hit/miss behavior; measured limitations.
7. **Safety review:** confirm all response behavior remains simulated and list trusted proxy / local cert limitations.
8. **Known limitations:** candid list of gaps that a strict evaluator can still find.
9. **Reproduction steps:** clean-clone setup, test commands, launch commands, and a short end-to-end demo walkthrough.
10. **Submission artifact:** final archive path/size and a summary of excluded files, verified from the actual archive listing.

Do not optimize for making every checkbox green. Optimize for a system a technical judge can inspect, reproduce, and trust. Correctness, evidence provenance, defensible evaluation, and safe behavior take precedence over cosmetic polish or inflated metrics.

**Begin with Phase 0 now. Inspect the real checkout, establish the baseline, and then implement the phases in order.**
