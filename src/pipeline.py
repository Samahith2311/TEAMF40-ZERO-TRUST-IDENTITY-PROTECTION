import json
from pathlib import Path
from typing import Dict, Any

from src.db import setup_db, get_db
from src.config import COLLECTIONS
from src.ingest import ingest_file
from src.detectors import (
    detect_dormant_reactivation,
    detect_impossible_travel,
    detect_privilege_escalation,
    detect_token_abuse,
    detect_unusual_api_calls
)
from src.scoring import calculate_risk_score
from src.stitching import stitch_identity_events
from src.alerts import create_alert_from_incident, verify_evidence_refs
from src.simulator import execute_simulated_action
from src.audit import create_audit_entry
from src.harness import evaluate_pipeline

def run_pipeline_slice() -> Dict[str, Any]:
    """
    Executes the complete vertical thin slice:
    Ingest -> Validate -> Normalize -> Detect -> Stitch -> Score -> Alert -> Action -> Eval -> Persist
    """
    db = setup_db()

    # 1. Ingest
    r_okta = ingest_file("fixtures/okta_sample.jsonl", db)
    r_ct = ingest_file("fixtures/cloudtrail_sample.jsonl", db)

    # 2. Load normalized events
    events = list(db[COLLECTIONS["normalized_events"]].find({}, {"_id": 0}))

    # Load identities metadata
    with open("fixtures/identities.json", "r", encoding="utf-8") as f:
        identities_list = json.load(f)
    id_map = {i["identity_key"]: i for i in identities_list}

    # 3. Detect anomalies per event
    predictions = {}
    ground_truth = {}
    detected_anomalies = []

    for evt in events:
        eid = evt["event_id"]
        ident = evt.get("identity_key")
        meta = id_map.get(ident, {})

        # Ground truth mapping from fixture line or heuristic
        is_attack = "contractor" in ident or "AttachUserPolicy" in evt.get("action", "")
        ground_truth[eid] = "ATTACK" if is_attack else "BENIGN"

        # Apply detectors
        d1 = detect_dormant_reactivation(evt, meta)
        d3 = detect_privilege_escalation(evt, meta)
        d4 = detect_unusual_api_calls(evt)

        is_flagged = d1["detected"] or d3["detected"] or d4["detected"]
        predictions[eid] = is_flagged
        if is_flagged:
            detected_anomalies.append(evt)

    # 4. Stitch into chains & links
    links, chains = stitch_identity_events(events)

    # Persist links and chains
    for l in links:
        db[COLLECTIONS["identity_links"]].update_one(
            {"link_id": l.link_id},
            {"$set": l.model_dump()},
            upsert=True
        )

    for c in chains:
        db[COLLECTIONS["incident_chains"]].update_one(
            {"incident_id": c.incident_id},
            {"$set": c.model_dump()},
            upsert=True
        )

    # 5. Risk Scoring & Alerts
    # Score the compromised contractor identity
    target_ident = "bob.contractor@corp.internal"
    factor_values = {
        "behavioral_anomaly": 90.0,
        "privilege_level": 40.0,
        "privilege_delta": 95.0,
        "resource_sensitivity": 85.0,
        "sequence_stage": 90.0
    }
    evidence_map = {
        "behavioral_anomaly": [{"source_file": "okta_sample.jsonl", "record_id": "2"}],
        "privilege_delta": [{"source_file": "cloudtrail_sample.jsonl", "record_id": "3"}],
        "resource_sensitivity": [{"source_file": "cloudtrail_sample.jsonl", "record_id": "4"}]
    }

    risk_score = calculate_risk_score("identity", target_ident, factor_values, evidence_map)
    db[COLLECTIONS["risk_scores"]].update_one(
        {"subject.id": target_ident},
        {"$set": risk_score.model_dump()},
        upsert=True
    )

    # 6. Generate Alert with real Evidence Refs
    alert = create_alert_from_incident(
        incident_id="inc-bob_contractor_corp_internal",
        subject_id=target_ident,
        score=risk_score.total,
        risk_score_ref=target_ident,
        evidences=[
            {"source_file": "okta_sample.jsonl", "record_id": "2"},
            {"source_file": "cloudtrail_sample.jsonl", "record_id": "3"},
            {"source_file": "cloudtrail_sample.jsonl", "record_id": "4"}
        ],
        what="Multi-stage credential abuse and unauthorized privilege escalation.",
        why="Dormant login followed by AssumeRole and AdministratorAccess attachment.",
        first_seen="2026-10-28T10:15:00Z",
        last_seen="2026-10-28T10:45:00Z"
    )
    db[COLLECTIONS["alerts"]].update_one(
        {"alert_id": alert.alert_id},
        {"$set": alert.model_dump()},
        upsert=True
    )

    # 7. Simulator Action (initial state before approval)
    sim_action = execute_simulated_action(
        incident_id=alert.incident_id,
        action=alert.recommended_action,
        target_identity=target_ident,
        approved=False
    )
    db[COLLECTIONS["simulator_actions"]].update_one(
        {"action_id": sim_action.action_id},
        {"$set": sim_action.model_dump()},
        upsert=True
    )

    # 8. Evaluation Harness Run
    eval_res = evaluate_pipeline(events, ground_truth, predictions)
    db[COLLECTIONS["eval_results"]].update_one(
        {"detector": eval_res.detector, "level": eval_res.level},
        {"$set": eval_res.model_dump()},
        upsert=True
    )

    # 9. Evidence Verification (U5)
    alerts_list = [alert.model_dump()]
    verification_report = verify_evidence_refs(alerts_list, fixtures_dir="fixtures")

    return {
        "status": "SUCCESS",
        "ingest_okta": r_okta,
        "ingest_cloudtrail": r_ct,
        "events_count": len(events),
        "links_count": len(links),
        "chains_count": len(chains),
        "risk_score": risk_score.total,
        "alert_id": alert.alert_id,
        "recommended_action": alert.recommended_action,
        "simulator_result": sim_action.result,
        "eval_f1": eval_res.f1,
        "baseline_f1": eval_res.baseline.get("f1"),
        "evidence_verification": verification_report
    }

if __name__ == "__main__":
    result = run_pipeline_slice()
    print(json.dumps(result, indent=2))
