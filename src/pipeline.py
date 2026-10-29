import json
import time
from pathlib import Path
from typing import Dict, Any, List, Optional

from src.db import setup_db, get_db
from src.config import COLLECTIONS
from src.ingest import ingest_file
from src.detectors import (
    detect_dormant_reactivation,
    detect_token_abuse,
    detect_privilege_escalation,
    detect_unusual_api_calls,
    detect_impossible_travel,
    detect_cert_binding_violation
)
from src.scoring import compute_identity_factors, calculate_risk_score
from src.stitching import stitch_identity_events
from src.alerts import create_alert_from_incident, verify_evidence_refs
from src.simulator import execute_simulated_action
from src.audit import create_audit_entry
from src.harness import evaluate_pipeline

ROOT_DIR = Path(__file__).resolve().parent.parent
DEFAULT_FIXTURES_DIR = ROOT_DIR / "fixtures"

def _find_fixture_file(path_str: str) -> Path:
    p = Path(path_str)
    if p.is_absolute() and p.exists():
        return p
    if p.exists():
        return p
    cand1 = DEFAULT_FIXTURES_DIR / p.name
    if cand1.exists():
        return cand1
    cand2 = ROOT_DIR / p
    if cand2.exists():
        return cand2
    return p

def run_pipeline(
    events: Optional[List[Dict[str, Any]]] = None,
    identities_path: str = "fixtures/identities.json",
    db: Any = None,
    execute_actions: bool = True
) -> Dict[str, Any]:
    """
    Executes the complete data-driven Zero Trust Identity Protection pipeline:
    Ingest -> Validate -> Detect -> Stitch -> Score -> Alert -> Action -> Verify -> Persist.
    No hardcoded usernames, factors, scores, or alert templates.
    """
    start_time = time.perf_counter()
    if db is None:
        db = setup_db()

    # 1. Ingest fixtures if no in-memory events provided
    r_okta = {"new_inserted": 0, "duplicates": 0, "invalid_quarantined": 0}
    r_ct = {"new_inserted": 0, "duplicates": 0, "invalid_quarantined": 0}
    if events is None:
        okta_file = _find_fixture_file("okta_sample.jsonl")
        ct_file = _find_fixture_file("cloudtrail_sample.jsonl")
        if okta_file.exists():
            r_okta = ingest_file(str(okta_file), db)
        if ct_file.exists():
            r_ct = ingest_file(str(ct_file), db)
        events = list(db[COLLECTIONS["normalized_events"]].find({}, {"_id": 0}))

    # 2. Load identities metadata
    id_map = {}
    id_file = _find_fixture_file(identities_path)
    if id_file.exists():
        with open(id_file, "r", encoding="utf-8") as f:
            id_list = json.load(f)
            id_map = {i["identity_key"]: i for i in id_list}

    # 3. Sort events chronologically and track state per identity
    sorted_events = sorted(events, key=lambda x: x.get("ts_utc", ""))
    last_geo: Dict[str, Dict[str, Any]] = {}
    prev_evt: Dict[str, Dict[str, Any]] = {}
    id_state = {k: dict(v) for k, v in id_map.items()}

    all_findings: List[Dict[str, Any]] = []
    findings_by_id: Dict[str, List[Dict[str, Any]]] = {}

    for evt in sorted_events:
        eid = evt["event_id"]
        ident = evt.get("identity_key", "")
        meta = id_state.get(ident, {})
        prev = prev_evt.get(ident)
        lg = last_geo.get(ident)

        # Apply DET-01
        d1 = detect_dormant_reactivation(evt, meta)
        if d1.get("detected"):
            all_findings.append(d1)
            findings_by_id.setdefault(ident, []).append(d1)
            meta["last_active_ts"] = evt.get("ts_utc")

        # Apply DET-02
        if prev:
            d2 = detect_token_abuse(evt, prev)
            if d2.get("detected"):
                all_findings.append(d2)
                findings_by_id.setdefault(ident, []).append(d2)

        # Apply DET-03
        d3 = detect_privilege_escalation(evt, meta)
        if d3.get("detected"):
            all_findings.append(d3)
            findings_by_id.setdefault(ident, []).append(d3)

        # Apply DET-04
        d4 = detect_unusual_api_calls(evt)
        if d4.get("detected"):
            all_findings.append(d4)
            findings_by_id.setdefault(ident, []).append(d4)

        # Apply DET-05
        if lg:
            d5 = detect_impossible_travel(lg, evt)
            if d5.get("detected"):
                all_findings.append(d5)
                findings_by_id.setdefault(ident, []).append(d5)

        # Apply DET-06
        expected_fp = prev.get("cert_fingerprint") if prev else None
        d6 = detect_cert_binding_violation(evt, expected_fp) if expected_fp else {"detected": False}
        if d6.get("detected"):
            all_findings.append(d6)
            findings_by_id.setdefault(ident, []).append(d6)

        prev_evt[ident] = evt
        if evt.get("geo") and evt["geo"].get("lat") is not None:
            last_geo[ident] = evt

    # 4. Stitch identity events into links and chains
    links, chains = stitch_identity_events(events)

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

    # 5. Score every identity present in events
    unique_identities = list(set(e.get("identity_key") for e in events if e.get("identity_key")))
    scored_identities: Dict[str, Any] = {}
    alerts: List[Any] = []
    sim_actions: List[Any] = []

    for ident in unique_identities:
        id_evts = [e for e in events if e.get("identity_key") == ident or ident in e.get("identity_candidates", [])]
        id_finds = findings_by_id.get(ident, [])
        meta = id_map.get(ident, {"clearance_level": 1, "is_protected": False})
        chain = next((c for c in chains if ident in getattr(c, "subject_ids", [])), None)

        factor_values, evidence_map = compute_identity_factors(ident, id_evts, id_finds, meta, chain)
        risk_score = calculate_risk_score("identity", ident, factor_values, evidence_map)
        scored_identities[ident] = risk_score

        db[COLLECTIONS["risk_scores"]].update_one(
            {"subject.id": ident},
            {"$set": risk_score.model_dump()},
            upsert=True
        )

        # 6. Generate Alert if score >= 60 or findings indicate CRITICAL/HIGH
        has_high_findings = any(f.get("severity") in ["CRITICAL", "HIGH"] for f in id_finds)
        if risk_score.total >= 60 or has_high_findings:
            attack_types = list(dict.fromkeys(f.get("attack_type", "") for f in id_finds if f.get("attack_type")))
            what_desc = f"Anomalous multi-stage behavior detected: {', '.join(attack_types)}." if attack_types else "Elevated risk score exceeding policy threshold."
            why_desc = "; ".join(f.get("rationale", "") for f in id_finds[:3]) if id_finds else "Composite risk factor accumulation."
            
            all_ev_refs = []
            for f in id_finds:
                all_ev_refs.extend(f.get("evidence_refs", []))
            if not all_ev_refs and id_evts:
                all_ev_refs.append({"source_file": id_evts[0].get("source_file", ""), "record_id": str(id_evts[0].get("record_ref", ""))})

            # Determine recommended action based on risk score (clamped to SimulatorAction literals)
            if risk_score.total > 80:
                rec_act = "RESTRICT"
            elif risk_score.total >= 60:
                rec_act = "REVOKE_SESSION"
            elif risk_score.total >= 40:
                rec_act = "STEP_UP"
            else:
                rec_act = "MONITOR"

            inc_id = chain.incident_id if chain else f"inc-{ident.replace('@', '_').replace('.', '_')}"
            first_ts = id_evts[0].get("ts_utc", "") if id_evts else ""
            last_ts = id_evts[-1].get("ts_utc", "") if id_evts else ""

            alert = create_alert_from_incident(
                incident_id=inc_id,
                subject_id=ident,
                score=risk_score.total,
                risk_score_ref=ident,
                evidences=all_ev_refs,
                what=what_desc,
                why=why_desc,
                first_seen=first_ts,
                last_seen=last_ts
            )
            # Override recommended action based on calibrated policy
            alert.recommended_action = rec_act
            alerts.append(alert)

            db[COLLECTIONS["alerts"]].update_one(
                {"alert_id": alert.alert_id},
                {"$set": alert.model_dump()},
                upsert=True
            )

            # 7. Simulator Action
            if execute_actions:
                sim_action = execute_simulated_action(
                    incident_id=alert.incident_id,
                    action=alert.recommended_action,
                    target_identity=ident,
                    approved=False
                )
                sim_actions.append(sim_action)
                db[COLLECTIONS["simulator_actions"]].update_one(
                    {"action_id": sim_action.action_id},
                    {"$set": sim_action.model_dump()},
                    upsert=True
                )

    # 8. Evidence Verification
    alerts_dump = [a.model_dump() for a in alerts]
    verification_report = verify_evidence_refs(alerts_dump, fixtures_dir=str(DEFAULT_FIXTURES_DIR if DEFAULT_FIXTURES_DIR.exists() else "fixtures"))

    elapsed_ms = (time.perf_counter() - start_time) * 1000.0

    return {
        "status": "SUCCESS",
        "ingest_okta": r_okta,
        "ingest_cloudtrail": r_ct,
        "events_count": len(events),
        "links_count": len(links),
        "chains_count": len(chains),
        "findings_count": len(all_findings),
        "scored_identities_count": len(scored_identities),
        "risk_scores": {k: v.total for k, v in scored_identities.items()},
        "alerts_count": len(alerts),
        "alerts": alerts,
        "sim_actions": sim_actions,
        "evidence_verification": verification_report,
        "elapsed_ms": round(elapsed_ms, 2)
    }

def run_pipeline_slice() -> Dict[str, Any]:
    """
    Backward-compatible entry point for vertical slice validation and tests.
    Executes the data-driven pipeline and extracts highest-severity results.
    """
    res = run_pipeline()
    alerts = res.get("alerts", [])
    sim_actions = res.get("sim_actions", [])
    risk_scores = res.get("risk_scores", {})

    # Sort alerts by risk score descending so highest-severity alert is selected
    sorted_alerts = sorted(alerts, key=lambda a: risk_scores.get(a.subject.get("id"), 0), reverse=True)
    top_alert = sorted_alerts[0] if sorted_alerts else None
    top_sim = None
    if top_alert:
        top_sim = next((s for s in sim_actions if s.incident_id == top_alert.incident_id), None)
    if not top_sim and sim_actions:
        top_sim = sim_actions[0]
    top_score = max(risk_scores.values()) if risk_scores else 0

    return {
        "status": "SUCCESS",
        "ingest_okta": res.get("ingest_okta"),
        "ingest_cloudtrail": res.get("ingest_cloudtrail"),
        "events_count": res.get("events_count", 0),
        "links_count": res.get("links_count", 0),
        "chains_count": res.get("chains_count", 0),
        "risk_score": top_score,
        "alert_id": top_alert.alert_id if top_alert else "none",
        "recommended_action": top_alert.recommended_action if top_alert else "ALLOW",
        "simulator_result": top_sim.result if top_sim else "NO_ACTION",
        "evidence_verification": res.get("evidence_verification", {})
    }

if __name__ == "__main__":
    result = run_pipeline()
    print(f"Pipeline executed in {result['elapsed_ms']} ms")
    print(f"Events: {result['events_count']}, Chains: {result['chains_count']}, Alerts: {result['alerts_count']}")
    print(f"Risk Scores: {json.dumps(result['risk_scores'], indent=2)}")
    print(f"Evidence Verification: {json.dumps(result['evidence_verification'], indent=2)}")
