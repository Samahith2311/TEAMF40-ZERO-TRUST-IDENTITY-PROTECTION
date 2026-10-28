# DATASET PROVENANCE AND INTEGRATION REPORT

**Track:** Track 2 — Zero Trust for Everyone (Intelligent Identity Protection)  
**Status:** Frozen & Verified  
**Date:** 2026-10-28  

---

## 1. Executive Summary

This report establishes the complete provenance, schema mappings, checksums, and evaluation status of all datasets and fixtures utilized in the Intelligent Identity Protection Engine.

### Core Provenance Statement
* **No authentic paired Okta System Log + AWS CloudTrail dataset was supplied** in the hackathon workspace repository root.
* **No external hidden evaluation set was accessible** in the local environment.
* In strict adherence to **Phase B3** of `MASTER_PROMPT_TRACK2_INTELLIGENT_IDENTITY_PROTECTION.md` (*"If no lawful and practical public paired dataset exists, do not fabricate one or pretend separate datasets are a single original dataset... use clearly labelled synthetic fixtures only for demo/test coverage"*), we constructed high-fidelity, schema-valid synthetic event feeds and identity metadata labeled explicitly as **`SYNTHETIC-DEMO`**.

---

## 2. Ingested Datasets Ledger

| Dataset File | Provenance | Format | Records | Size | SHA-256 Checksum | Schema Adapter |
|---|---|---|---|---|---|---|
| `fixtures/okta_sample.jsonl` | `SYNTHETIC-DEMO` | JSONL | 5 | 3,087 B | `0316b0d532e2acee081824206c4ea71d4640a0abfabcad03824697b2395d84d0` | `parse_okta_record()` |
| `fixtures/cloudtrail_sample.jsonl` | `SYNTHETIC-DEMO` | JSONL | 6 | 3,515 B | `f2aaeb5272dcaefe9777c41385d7d678ceaf8ea11de08988c1f9a8f69a812f28` | `parse_cloudtrail_record()` |
| `fixtures/identities.json` | `SYNTHETIC-DEMO` | JSON | 5 | 1,412 B | `65b67fc2fdcc3865b221aaadfbbbbf387013e47d26c4de9fb8b57e7c124d6514` | Direct JSON Load |
| `fixtures/ground_truth.json` | `SYNTHETIC-DEMO` | JSON | 22 | 1,114 B | `75c45052e9447879de1b1f9c1549446b23abb2de6d5449ef9772fbb338771060` | Evaluation Harness |

---

## 3. Schema Specifications & Field Normalization

### 3.1 Okta System Log (`fixtures/okta_sample.jsonl`)
* **Reference Standard:** [Okta System Log API Specification v1](https://developer.okta.com/docs/reference/system-log-query/)
* **Timestamp Span:** `2026-10-28T09:00:00Z` to `2026-10-28T11:00:00Z`
* **Distinct Identities (Actors):** 4 (`alice@corp.internal`, `bob.contractor@corp.internal`, `charlie.analyst@corp.internal`, `diana.admin@corp.internal`)
* **Distinct Sessions:** 4 (`sess-okta-alice-101`, `sess-okta-bob-202`, `sess-okta-bob-203`, `sess-charlie-301`)
* **Normalized Mappings:**
  * `actor.alternateId` $\to$ `identity_key`
  * `debugContext.session_id` $\to$ `session_id`
  * `published` $\to$ `ts_utc` (ISO 8601 UTC)
  * `eventType` $\to$ `action`
  * `client.ipAddress` $\to$ `ip`
  * `client.geographicalContext` $\to$ `geo` (`city`, `country`, `latitude`, `longitude`)
  * `client.userAgent` $\to$ `user_agent`
  * `target[0].displayName` $\to$ `resource`

### 3.2 AWS CloudTrail (`fixtures/cloudtrail_sample.jsonl`)
* **Reference Standard:** [AWS CloudTrail Event Reference Record Contents](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html)
* **Timestamp Span:** `2026-10-28T09:15:00Z` to `2026-10-28T11:05:00Z`
* **Distinct UserIdentities:** 4 principals
* **API Operations Captured:** `AssumeRole`, `AttachUserPolicy`, `GetObject`, `GetRole`
* **Normalized Mappings:**
  * `userIdentity.userName` $\to$ `identity_key`
  * `userIdentity.arn` $\to$ `principal_arn`
  * `eventTime` $\to$ `ts_utc` (ISO 8601 UTC)
  * `eventName` $\to$ `action`
  * `sourceIPAddress` $\to$ `ip`
  * `userAgent` $\to$ `user_agent`
  * `requestParameters.bucketName` / `policyArn` $\to$ `resource`

### 3.3 Identity Normality Metadata (`fixtures/identities.json`)
* **Purpose:** Provides organizational ground truth for role baselines, peer group comparisons, dormancy thresholds, and protected identity safeguards.
* **Entities:**
  1. `alice@corp.internal` (Developer, peer group: `engineering`, protected: `false`)
  2. `bob.contractor@corp.internal` (External Contractor, peer group: `contractor`, protected: `false`, dormancy: 30 days)
  3. `charlie.analyst@corp.internal` (Data Analyst, peer group: `analytics`, protected: `false`)
  4. `diana.admin@corp.internal` (Cloud Infrastructure Admin, peer group: `sysadmin`, protected: `true` — break-glass)
  5. `eve.attacker@corp.internal` (External actor / unverified identity)

---

## 4. Evaluation Split & Leakage Safeguards

### 4.1 Hidden Evaluation Set Status
* **Status:** `NOT PROVIDED / NOT ACCESSIBLE`
* Neither a separate holdout partition nor an official secret test key was delivered with the problem prompt.

### 4.2 Internal Validation Split Design
To satisfy Phase B2 and prevent evaluation leakage:
* **Partitioning Strategy:** **Whole-Identity Holdout (`WHOLE_IDENTITY_HOLDOUT`)**
* **Seed:** Deterministic fixed pseudo-random seed (`seed=42`)
* **Test Ratio:** 0.4 (40% holdout partition)
* **Leakage Prevention:**
  1. **Zero Entity Leakage:** All events belonging to a held-out identity reside strictly in the test partition; no events for that identity exist in training or baseline estimation.
  2. **Zero Sequence Fragmentation:** Complete temporal attack chains for held-out identities are evaluated intact.
  3. **Zero Label Exposure:** Detection rules operate purely on field evidence, timestamps, and identity normality metadata—never on event IDs, usernames, or label attributes.

---

## 5. Review of Authentic Public Candidate Datasets

In compliance with Phase B3, three candidate open-source datasets were evaluated:

1. **LANL Comprehensive Multi-Source Cyber-Security Events (Cyber1):**
   * *Source:* https://csr.lanl.gov/data/cyber1/
   * *Assessment:* Contains Windows event logs and authentication tickets from an internal enterprise network. Does not contain Okta System Log schemas or AWS CloudTrail API event structures. Rejected as non-conforming.
2. **Login Data Set for Risk-Based Authentication (Zenodo 6782156):**
   * *Source:* https://zenodo.org/records/6782156
   * *Assessment:* Contains synthesized web session features for risk-based authentication research. Does not provide raw Okta JSON event records or cross-source cloud logs. Rejected for lacking raw provenance.
3. **CLUE-LDS Cloud User Entity Behaviour Analytics Log Data Set (Zenodo 7119953):**
   * *Source:* https://zenodo.org/records/7119953
   * *Assessment:* Multi-gigabyte archive of cloud storage audit logs. Lacks paired Okta authentication sessions and AWS IAM privilege-escalation sequences. Rejected due to bandwidth, schema divergence, and lack of cross-source identity correlation.

**Conclusion:** Utilizing schema-conforming `SYNTHETIC-DEMO` fixtures is the only legally and technically defensible approach.

---

## 6. Data Ingestion & Storage Integrity

* **Idempotency Guarantee:** Ingestion into MongoDB is governed by a compound unique index on `(source, event_id)`. Re-ingesting any fixture produces zero duplicates.
* **Raw Cryptographic Provenance:** Each ingested event record stores `raw_hash` (SHA-256 of the raw unparsed JSON string).
* **Traceability:** 100% of generated alert evidence citations resolve directly to raw source records on disk.

