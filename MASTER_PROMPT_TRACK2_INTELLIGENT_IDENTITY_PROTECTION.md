# MASTER BUILD PROMPT — TRACK 2: ZERO TRUST FOR EVERYONE
## Intelligent Identity Protection — Strict Problem-Statement Scope Only

> **Purpose:** Use this prompt in Claude Code, Antigravity, Cursor, Codex, or another repository-aware coding agent. Open the actual project folder first, then paste the full prompt. Create a backup or Git branch before modifying code.
>
> **Source of truth:** The Track 2 problem statement and rubric supplied by the hackathon, followed by the actual repository and its provided datasets. This prompt is intentionally limited to that challenge. Do not broaden the product into a generic cybersecurity platform.

---

## 1. ROLE AND MISSION

Act as a senior identity-security engineer, defensive detection engineer, data engineer, full-stack developer, QA lead, and hackathon MVP architect.

Your job is to inspect, repair, complete, test, and document the existing **Track 2: Zero Trust for Everyone — Intelligent Identity Protection** project. Deliver a credible, locally runnable **demo and focused MVP** that solves the exact problem below. Make real code changes and run the available checks; do not stop after offering recommendations or producing a plan.

### The problem we are solving

Compromised identities can operate through legitimate access paths. Dormant-account reactivation, suspicious session reuse, privilege escalation, and unusual API calls can expose cloud environments even when authentication succeeds. Build an identity protection engine that:

1. Assigns a risk score to each identity or session using behaviour, privilege level, resource sensitivity, and event history.
2. Detects suspicious event sequences and multi-step privilege-escalation chains.
3. Correlates **AWS CloudTrail** and **Okta System Log** events across authentication, session, and API activity.
4. Explains what was flagged, why it matters, and which specific log evidence supports the finding.
5. Recommends risk-proportionate next steps and demonstrates step-up authentication, session revocation, or access restriction **only through the supplied/local policy simulator**.

### Core challenge

Reason about behaviour, privilege relationships, and ordered event sequences—not only failed logins, isolated rules, identity names, or individual events.

---

## 2. STRICT SCOPE LOCK — DO NOT EXPAND THE PRODUCT

This is an **intelligent identity protection engine**, not a general SOC suite.

### In scope — implement and verify these capabilities

- Ingest, validate, normalize, and retain source provenance for Okta System Log and AWS CloudTrail records.
- Link records to identities, sessions, principals, roles, resources, and event timelines using defensible evidence.
- Maintain transparent per-identity and per-session risk scores in the documented 0–100 range (if the repository's contract uses that scale).
- Implement and evaluate these five named detection families:
  1. **Impossible travel** — suspicious geographically inconsistent authentication, accounting for time gaps and known location uncertainty.
  2. **Dormant-account reactivation** — activity after a gap that is unusual for the identity and its peer group.
  3. **Privilege-escalation chains** — ordered events that increase permissions or enable elevated access, correlated to the same identity/session where evidence permits.
  4. **Unusual API calls** — cloud API behaviour that departs from role-, resource-, time-, or peer-group expectations, particularly sensitive actions.
  5. **Token/session abuse** — suspicious session reuse, token-related events, inconsistent session context, or cross-source activity associated with an anomalous session.
- Reconstruct multi-step incident chains with timestamps, identities, sessions, resources, stages, and source-evidence references.
- Explain alerts with contributing signals, severity/risk, score factors, uncertainty, and links to the exact underlying records.
- Recommend safe next steps and present simulated step-up authentication, session revocation, and access restriction through the supplied policy simulator only.
- Support analyst feedback that adjusts or records future risk assessment in an auditable, bounded way.
- Visualize identity-to-session-to-resource/privilege relationships and high-risk privilege paths.
- Measure event-level precision, recall, and F1 on the labelled evaluation set; separately evaluate identity/session alert precision; report false-positive rate, replay detection latency, evidence traceability, explanation quality, and multi-step chain reconstruction correctness.

### Explicitly out of scope — do not add these

- A generic SIEM/SOC platform unrelated to identity risk.
- Malware scanning, antivirus, EDR/XDR, ransomware detection, endpoint telemetry, vulnerability scanning, phishing detection, threat-intelligence feeds, packet inspection, or general network monitoring.
- A broad incident-management product, ticketing system, chat/assistant, RAG chatbot, report generator, or unrelated AI feature.
- Live Okta administration, real AWS API calls, production-tenant changes, real session revocation, real account suspension, or real access-policy enforcement.
- A new multi-tenant SaaS architecture, Kubernetes/cloud deployment, paid services, complex authentication service, or a wholesale framework rewrite unless strictly necessary to make an existing core flow work.
- Unsupported claims such as “prevents all account compromise,” “production-ready,” “AI-powered” without a real tested AI component, or “real-time” when the app only replays fixtures.

Do not add a feature merely because it is in a generic skill pack or appears impressive in a demo. Any proposed feature must directly improve one of the in-scope requirements or a stated evaluation metric.

---

## 3. PROJECT PRESERVATION AND OPERATING RULES

1. **Inspect the real repository first.** Read the README, challenge documents, `ponytail.md` if present, `MASTER_BUILD_PROMPT.md`, `TASKS.md`, `SECURITY.md`, `.env.example`, requirements, all core backend modules, frontend pages, tests, and dataset/fixture documentation. Treat the challenge statement and evaluation rubric as the product contract.
2. **Do not assume paths or claims.** Check which files actually exist. Avoid printing or reading `.git`, `node_modules`, virtual environments, generated build directories, secrets, and huge datasets wholesale.
3. **Preserve user work.** Check `git status`, create a branch when safe, and do not discard uncommitted changes. Keep existing core concepts and working features unless a verified defect requires a change.
4. **Evidence before assertions.** For each suspected issue, locate the relevant code, reproduce the failure when feasible, and classify it as `CONFIRMED`, `LIKELY`, `NOT VERIFIED`, or `IMPROVEMENT`. Include file paths and test evidence.
5. **Small root-cause fixes.** Prefer focused patches and tests over wholesale rewrites or unnecessary dependencies.
6. **No fake functionality.** No inert buttons, placeholder routes, hard-coded dashboard counters presented as live, swallowed exceptions, fake success states, or invented dataset provenance.
7. **Do not conflate simulation with enforcement.** Every response action must clearly state that it is simulated. Do not configure cloud credentials or make live changes.
8. **Treat logs as untrusted input.** Validate field types and sizes, normalize timestamps safely, prevent MongoDB operator injection, avoid unsafe deserialization/shell execution, and keep secrets out of logs and UI.
9. **No arbitrary ML.** Prefer explainable, testable detection rules and transparent calibration. Add a model only if an appropriate labelled dataset, leakage-safe evaluation, and meaningful improvement can be demonstrated.
10. **Do not pause for routine questions.** Make safe assumptions, document them, and continue. Do not bypass an authorization boundary, access gated data without permission, or invent a workaround for an actual license restriction.

---

## 4. REQUIRED TECHNICAL WORKFLOW

### Phase A — Establish the actual baseline

Before changing code:

- Map the backend, API endpoints, frontend, database collections, ingest formats, event-normalization pipeline, detector interfaces, identity/session stitching, scoring, alert generation, policy simulator, audit trail, tests, and demo/evaluation commands.
- Trace at least one expected benign sequence and one labelled suspicious sequence from raw source records through to the final UI.
- Inspect the provided challenge resources and repository fixtures before searching for other data.
- Run current backend tests, relevant CLI commands, API smoke checks, and frontend build/type checks where the environment allows. Record exact commands and results.
- Find hard-coded usernames, identity-derived rules, fixed scores, fabricated geolocation, fixed IP-to-user mappings, event-count constants, precomputed alerts, stale frontend state, timestamp assumptions, duplicate ingestion, and cross-source joins based on weak evidence.
- Create or update `docs/TRACK2_AUDIT.md` with a concise architecture map and findings graded P0–P3. Do not create redundant documentation if an equivalent file already exists.

### Phase B — Dataset discovery, provenance, and safe integration

**Dataset work is part of the task. Finding a URL is not integration.**

#### B1. Inspect supplied resources first

Find all files that the hackathon supplied, including hidden/attached files available to the agent, repository fixtures, archive contents, sample logs, labels, identity/privilege metadata, normal-activity examples, baseline detectors, optional simulator definitions, and evaluation instructions. The screenshot states that labelled sample AWS CloudTrail and Okta System Log datasets and an evaluation/hidden dataset may be supplied.

For every dataset/file, document:

- Exact path or source URL and the file actually present.
- Provenance category: `HACKATHON-PROVIDED`, `ORIGINAL-PUBLIC`, `SYNTHETIC-DEMO`, or `DERIVED`.
- Format, schema, number of records, number of distinct identities/sessions where measurable, timestamp range, labels available, file size, license/usage terms, and any missing fields.
- Whether it was actually parsed and used; do not report downloaded/loaded unless verified.
- SHA-256 checksum for acquired source files where practical, without altering the original file.

Preserve original source files read-only. Put converted files in a separate generated-data/output location. Record transformation steps and record-level source references.

#### B2. Keep the evaluation clean

- Never use hidden evaluation labels to tune thresholds, detectors, or weights.
- Keep development fixtures, tuning/validation data, and hidden/final evaluation data separate.
- If the challenge provides fixed labelled sample files, use them for reproducible functional checks; do not claim their results are generalizable to real production traffic.
- If no hidden set is actually available locally, state `NOT PROVIDED/NOT ACCESSIBLE`. Build a deterministic split from available labelled data using time- and identity-aware separation where practical, and clearly label the result as an internal validation estimate—not the hidden-set score.
- Prevent train/test leakage through duplicate records, shared synthetic templates, identity overlap, or sequence fragments crossing the split.

#### B3. Find an authentic, relevant source only if required

Prefer the exact hackathon-provided datasets. If supplementation is needed, search for original, owner-maintained sources that materially support **identity authentication risk or cloud identity/API activity**. Verify the link, schema, labels, license, size, terms, and access procedure before choosing. Do not treat a general cybersecurity dataset as equivalent to Okta + CloudTrail.

Candidate references to assess (not automatic substitutes):

- LANL Comprehensive Multi-Source Cyber-Security Events: https://csr.lanl.gov/data/cyber1/ — includes authentication and other enterprise events with red-team events; it is large and not native Okta or AWS CloudTrail data.
- Login Data Set for Risk-Based Authentication: https://zenodo.org/records/6782156 — useful for risk-based authentication methodology, but the feature records are synthesized and are **not raw Okta logs**. The published archive is large; do not download blindly.
- CLUE-LDS Cloud User Entity Behaviour Analytics Log Data Set: https://zenodo.org/records/7119953 — cloud-storage audit events that may help explore behavioural analysis, but it is not a native CloudTrail+Okta paired dataset and the unpacked data is large.
- Okta System Log reference: https://developer.okta.com/docs/reference/system-log-query/
- AWS CloudTrail event record reference: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html

Use official source docs to understand schemas. Do not scrape private systems, use leaked data/credentials, or use untraceable re-uploads. Do not download multi-gigabyte data unless the benefit, disk budget, terms, and time justify it. Prefer an official small sample, bounded subset, or streaming importer permitted by the terms.

**Hard rule:** If no lawful and practical public paired dataset exists, do not fabricate one or pretend separate datasets are a single original dataset. Use the supplied labelled Okta/CloudTrail files as the primary challenge dataset; document any external dataset as a separate adapter/secondary experiment. If supplied files are unavailable, implement tested import support and use clearly labelled synthetic fixtures only for demo/test coverage, reporting that authentic integration is blocked. Never stop the whole code-repair task over this limitation.

#### B4. Integrate instead of merely listing

- Build or fix schema adapters for supported Okta System Log and AWS CloudTrail JSON/JSONL formats based on actual data.
- Preserve raw events and source identifiers; store normalized fields plus provenance, parser version, and raw-record hash as appropriate.
- Handle missing/optional fields, invalid records, timezone-aware timestamps, duplicate events, out-of-order arrival, oversized inputs, and partial imports safely.
- Provide a CLI or UI workflow that visibly imports a file, reports records read/accepted/rejected/duplicate, and identifies the reason for rejected records.
- Do not hard-code a user's name or event ID to trigger a detector. Fixture labels may drive evaluation expectations, never runtime detector decisions.
- Provide at least one end-to-end test per supported input format using representative records from the supplied data.

### Phase C — Repair the core data path

Make the smallest required fixes across this path:

`Okta / CloudTrail raw record → validate and parse → normalize → persist/deduplicate → identity/session/principal correlation → detectors → evidence-backed event/chain graph → explainable risk score → alert/recommendation → simulated policy action → audit event → dashboard`.

Acceptance requirements:

- Every stage has an explicit input/output contract and useful error messages.
- UTC timestamps are parsed consistently; events are ordered by event time with tie-breaking that does not destroy source identity.
- Event ingestion is idempotent; replaying the same file should not create duplicate events or multiply risk solely because of duplicate records.
- Missing cross-source linkage must remain `UNKNOWN` or `INFERRED` with confidence/provenance—not a false `VALIDATED` join.
- Alerts cite exact original record IDs and source files. Evidence links must resolve back to stored raw records and their hashes where implemented.
- Identity and session scores update from current data; the UI must not show stale or hard-coded totals.
- All errors are observable; no broad exception handler silently converts failure into “success.”
- Database absence is shown clearly. If a supported local demo fallback exists, label it, document it, and test it rather than pretending MongoDB is connected.

### Phase D — Implement and validate only the five challenge detector families

For each detector, define expected fields, logic, limitations, evidence payload, false-positive cases, and deterministic tests.

1. **Impossible travel**
   - Require defensible geolocation evidence and elapsed-time logic; do not invent country/city based on arbitrary IPs.
   - If geolocation is missing, the detector must return insufficient evidence/unknown rather than flagging purely on absent data.
   - Account for VPN/proxy/mobile-network uncertainty where known.

2. **Dormant-account reactivation**
   - Compare inactivity gap to configured policy and, when available, individual/peer-group normality metadata.
   - Use the actual event chronology and metadata; do not identify a dormant identity from its username or domain suffix.

3. **Privilege-escalation chain**
   - Detect a sequence of supported events showing a role/policy change, privilege acquisition, elevated API usage, or other challenge-defined stage progression.
   - Correlate steps through validated or explicitly inferred identity/session/principal relationships.
   - Report missing/ambiguous stages honestly; don't fabricate a complete chain from one suspicious API event.

4. **Unusual API calls**
   - Use configured sensitivity and available identity/role/peer baselines; distinguish high-impact operations from unusual but expected behaviour.
   - Handle legitimate administrators and approved automation as possible benign explanations without automatic allowlisting by name.

5. **Token/session abuse**
   - Use real source fields where present, including relevant session, transaction, principal, token-event, IP/device/context, and time fields.
   - Never assume two events share a session merely because they are close in time. Expose correlation method and provenance.

Do not add unrelated detector families. A detector may use common shared features, but its finding must map to one of the five challenge patterns.

### Phase E — Transparent risk scoring and analyst feedback

- Calculate risk per **identity and session**, using the problem statement's factors: behaviour/anomaly, privilege level, resource sensitivity, event history/stage, and available context.
- Keep the scoring contract transparent, bounded, and testable. If the repository already defines a weight model, validate it before changing it; document any necessary adjustment.
- Show each factor's contribution, score before/after, threshold, and supporting evidence. Ensure factor contributions reconcile with the displayed total, including caps and rounding.
- Do not double-count the same event/chain across repeated ingestion or overlapping detector outputs without an explicit reason.
- Treat confidence and risk as distinct concepts when feasible: a high-impact event can raise risk while weak identity stitching lowers confidence.
- Let analyst feedback record a disposition and rationale, and influence future calibration only through an explicit bounded and reversible rule. Record who/what changed, previous value, new value, time, and evidence in audit history. Do not let a single feedback click silently whitelist a user or override protected-account safeguards.
- If no authenticated analyst identity exists in the MVP, state the limitation and avoid claiming a verified human-approval system; the local demo can use a conspicuously labelled simulated analyst action.

### Phase F — Explainable incident chains and identity attack graph

Implement or repair a focused graph/timeline that answers:

- Which identity and session are involved?
- Which Okta event(s) and AWS API events are connected?
- What changed in privilege or access?
- Which sensitive resource or action was involved?
- What is the ordered chain and which expected stages are missing?
- Which links are source-validated, metadata-derived, or inferred?
- Why did the total risk change and what should an analyst consider next?

Use stable node/event IDs, not array positions. Make the graph deterministic for the same input. Provide a useful timeline/list fallback when graph rendering is unavailable. Do not draw unsupported links or conceal uncertainty with polished visuals.

### Phase G — Safe policy simulator only

Support the challenge's proposed actions through the supplied simulator or a clearly isolated local simulator:

- Step-up authentication recommendation/simulation.
- Session revocation simulation.
- Access restriction simulation.
- Explicit allow/deny result with reason.
- Approval/confirmation gate as appropriate to the existing design.
- Protected/break-glass/admin identity safeguards.
- Immutable-by-append or hash-chained tamper-evident local audit history if already in scope.

No action may call a live Okta or AWS API, alter real cloud accounts, revoke real sessions, change a production tenant, or require production credentials. Make that boundary visible in the UI and documentation. Treat the audit chain as tamper-evident, not tamper-proof. Test that protected identities cannot be restricted through any UI or API route, not just by hiding a button.

### Phase H — Focused frontend, not a generic SOC redesign

Retain the existing React/Vite/Tailwind architecture and current useful UI components. Improve the interface only to support this problem's workflow:

1. Identity/session risk overview with clearly sourced totals.
2. Alert queue filtered to the five target detector families.
3. Identity/session investigation view with factor breakdown and evidence.
4. Incident timeline and privilege-escalation chain graph.
5. Safe policy-simulator preview/result and audit trail.
6. Dataset ingestion/replay controls and visible Demo/Fixture/Imported-data status.
7. Benchmark/evaluation report showing metrics and sample counts.

UI rules:

- No decorative features that do not help understand identity risk or evidence.
- Do not use hard-coded counts, risk values, fake “live” indicators, or prewritten alerts as if they came from backend data.
- Loading, empty, error, and backend-disconnected states must be explicit.
- Use clear risk and severity labels; never label a suspicious event as a confirmed compromise unless the source ground truth supports it.
- Make every major alert traceable to the raw events and factor explanations that triggered it.

### Phase I — Evaluation aligned to the exact rubric

Implement/rework a reproducible evaluation command and export a machine-readable report (e.g., JSON plus concise Markdown/CSV as useful).

Measure and report:

- Event-level precision, recall, and F1 across the labelled evaluation data.
- Identity-level alert precision and session-level alert precision separately.
- False-positive rate, with the denominator and label assumptions stated.
- Detection/replay latency with a defined start/end point and sample count.
- Evidence traceability: fraction of alert evidence references successfully resolved to source records.
- Explanation quality: use a documented rubric/checklist, not an unsupported subjective score.
- Multi-step privilege-escalation-chain reconstruction: exact/partial/missed stages and chain-level success metric.
- Baseline comparison against the supplied/simple baseline detector, where available.
- Per-detector breakdown plus aggregate results; include TP/FP/FN/TN counts when the labels and evaluation design support them.

Do not score every event as benign merely because a detector did not fire. Define matching rules for event-, identity-, session-, and chain-level predictions. Handle classes with zero support transparently. Use a fixed random seed when relevant and document any limitations from small sample size or synthetic ground truth.

The final report must not fabricate a target score. Optimize against the actual evaluation results, investigate false positives and false negatives, and re-run after each material detector change.

### Phase J — Focused tests and reliability

Add or repair tests for at least:

- Parsing and schema validation for supplied Okta and CloudTrail records.
- Unknown fields/missing optional fields and malformed records.
- Timestamp parsing, timezone handling, out-of-order records, duplicate ingestion, and deterministic replay.
- Correct positive and negative examples for each of the five detectors.
- Cross-source linking: a valid link, ambiguous link, missing link, and conflicting identity evidence.
- Identity/session scoring, score boundaries, factor contribution math, and duplicate prevention.
- End-to-end multi-step privilege escalation chain reconstruction.
- Evidence-reference resolution and raw-record provenance.
- Protected-account guard on every response path; invalid and unauthorized simulator requests.
- Audit-chain validation and modification/reordering detection if the feature exists.
- API-to-frontend response contract and frontend production build.
- Hidden-set separation and metric calculation correctness.

Use the smallest realistic fixtures possible; avoid flaky wall-clock tests. Never use a detector's implementation function to generate the same expected label in a way that makes the test tautological.

---

## 5. REQUIRED DEMO AND MVP DELIVERABLES

### Demo Mode

The demo must run locally without credentials to real Okta/AWS services. It should replay the provided labelled sample records deterministically and let a judge observe this sequence:

1. Load or replay the sample events.
2. Display benign versus suspicious identity/session behaviour.
3. Open one suspicious identity and inspect the exact correlated Okta and CloudTrail evidence.
4. View its risk factors and a multi-step privilege-escalation chain where the provided data supports it.
5. Show the recommendation and execute a clearly labelled **simulated** response.
6. View the audit entry and run evidence/integrity verification.
7. Run the evaluation command and show actual computed metrics, sample counts, and limitations.
8. Reset or replay without duplicate alerts, stale counters, or leftover state.

### MVP Mode

At minimum, a user can:

- Import supported Okta System Log and CloudTrail JSON/JSONL files.
- Inspect parse/validation results and import statistics.
- Run the in-scope detectors and identity/session correlation pipeline.
- Inspect explainable risk and evidence-backed chains.
- Review safe simulated response recommendations and audit history.
- Run and export the evaluation report.

Document what is implemented but limited, what is simulated, and what remains unverified.

---

## 6. DEFINITION OF DONE — DO NOT CLAIM SUCCESS UNTIL VERIFIED

The project is acceptable only when these gates have evidence:

- **Gate 1 — Runability:** Documented local setup succeeds in a clean/reproducible environment, or exact blockers are documented.
- **Gate 2 — Data fidelity:** Supplied records parse correctly, labels/provenance are preserved, rejected records are accounted for, and duplicates are controlled.
- **Gate 3 — Core detection:** All five detector families have positive, negative, and edge-case tests.
- **Gate 4 — Correlation:** A labelled cross-source chain is reconstructed with field-level provenance and no fabricated links.
- **Gate 5 — Scoring:** Identity and session risk are computed from visible factors and reconcile with the displayed totals.
- **Gate 6 — Explainability:** Alerts show why the rule fired and resolve to the underlying source records.
- **Gate 7 — Response safety:** All actions are simulated, and protected identities cannot be restricted via API or UI.
- **Gate 8 — Evaluation:** Event, identity, session, false-positive, latency, traceability, and chain-reconstruction metrics are computed reproducibly where data allows.
- **Gate 9 — UI integration:** The frontend reflects actual API/database/pipeline state, including empty/error/disconnected states.
- **Gate 10 — No out-of-scope drift:** The solution remains focused on intelligent identity protection across Okta and AWS CloudTrail.

Use statuses `PASS`, `FAIL`, `PARTIAL`, `MOCKED/DEMO`, or `NOT RUN`. Attach command output, file references, or test names to every claim.

---

## 7. REQUIRED FINAL RESPONSE FROM THE CODING AGENT

At completion, return a concise but evidence-based report with:

1. **Scope confirmation:** State explicitly that only the Track 2 identity protection problem was addressed and list excluded domains/features that were not added.
2. **Root-cause fixes:** Confirmed defects, why they occurred, changed files, and regression tests.
3. **Dataset report:** Every actual dataset used; source URL; licence/terms; record count/size; format; labels; schema adapter; provenance; checksum if computed; what was actually downloaded/parsed. Distinguish challenge-provided, authentic public, derived, and synthetic records. Say plainly if the hidden set or a suitable authentic dataset was not available.
4. **Detection report:** Five detector results and key false positives/negatives from the available evaluation.
5. **Metrics table:** Event-level P/R/F1, identity and session alert precision, false-positive rate, detection latency, evidence traceability, explanation-quality rubric, and chain reconstruction—with denominators and limitations.
6. **How to run:** Exact Windows PowerShell commands first and Unix equivalents if practical, including backend, frontend, tests, demo replay, evaluation, and evidence verification.
7. **Demo script:** A short deterministic judge walkthrough and expected outputs.
8. **Verification matrix:** Gates 1–10 with status and evidence.
9. **Known limitations:** Real-time streaming, geolocation uncertainty, external integrations, hidden-set availability, small/synthetic samples, and anything not tested.
10. **Next three priorities:** Only the highest-value in-scope items.

Never say that a dataset was acquired, tests passed, a build succeeded, metrics improved, a chain is fully reconstructed, or real actions are enforced unless you directly verified it. Do not call this production-ready without appropriate production security and operational validation.

---

## START NOW

Inspect the actual repository and challenge resources. Briefly report the highest-risk **confirmed** issues and then proceed to implement, test, and document fixes. Do not ask for permission for ordinary reversible code changes. Stay strictly within **Track 2: Zero Trust for Everyone — Intelligent Identity Protection**.
