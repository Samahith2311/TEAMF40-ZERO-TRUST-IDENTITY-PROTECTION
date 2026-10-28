import uuid
import random
import hashlib
import threading
import time
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional

from src.db import get_db
from src.config import COLLECTIONS
from src.models import (
    NormalizedEvent,
    ValidationDetails,
    IdentityLink,
    IncidentChain,
    ChainStage,
    Alert,
    EvidenceRef,
    SimulatorAction
)
from src.detectors import (
    detect_dormant_reactivation,
    detect_impossible_travel,
    detect_privilege_escalation,
    detect_token_abuse,
    detect_unusual_api_calls
)
from src.scoring import calculate_risk_score
from src.feedback import autonomous_tune_from_attack, get_current_weights
from src.graph import build_attack_graph
from src.audit import create_audit_entry

# Synthetic attack candidate identities
IDENTITIES_CATALOG = [
    {"key": "marcus.vance@corp.internal", "name": "Marcus Vance", "dept": "DevOps", "clearance": 2, "dormant_gap": 48},
    {"key": "sarah.chen@corp.internal", "name": "Sarah Chen", "dept": "Finance", "clearance": 1, "dormant_gap": 62},
    {"key": "alex.morgan@corp.internal", "name": "Alex Morgan", "dept": "QA", "clearance": 2, "dormant_gap": 41},
    {"key": "elena.rostova@corp.internal", "name": "Elena Rostova", "dept": "DataPlatform", "clearance": 2, "dormant_gap": 75},
    {"key": "lucas.weber@corp.internal", "name": "Lucas Weber", "dept": "Support", "clearance": 1, "dormant_gap": 39},
    {"key": "priya.patel@corp.internal", "name": "Priya Patel", "dept": "Security", "clearance": 1, "dormant_gap": 55},
    {"key": "dave.contractor@corp.internal", "name": "Dave Contractor", "dept": "Contractors", "clearance": 1, "dormant_gap": 90}
]

ROLES_CATALOG = [
    "DataPlatformIngestRole",
    "DevOpsDeployerRole",
    "SecOpsAuditRole",
    "BillingViewerRole",
    "DataAnalystRole",
    "InfrastructureAdminRole"
]

POLICIES_CATALOG = [
    "AdministratorAccess",
    "IAMFullAccess",
    "SecurityAuditBypassPolicy",
    "PowerUserAccess",
    "SecretsManagerReadWrite"
]

RESOURCES_CATALOG = [
    "corp-customer-pii-vault",
    "production_export.csv.enc",
    "financial-ledger-prod-db",
    "s3://corp-intel-backup/keys",
    "cloud-credentials-vault"
]

LOCATIONS_CATALOG = [
    {"city": "London", "lat": 51.5074, "lon": -0.1278, "country": "GB"},
    {"city": "Tokyo", "lat": 35.6762, "lon": 139.6503, "country": "JP"},
    {"city": "Singapore", "lat": 1.3521, "lon": 103.8198, "country": "SG"},
    {"city": "Frankfurt", "lat": 50.1109, "lon": 8.6821, "country": "DE"},
    {"city": "New York", "lat": 40.7128, "lon": -74.0060, "country": "US"},
    {"city": "Sao Paulo", "lat": -23.5505, "lon": -46.6333, "country": "BR"},
    {"city": "Sydney", "lat": -33.8688, "lon": 151.2093, "country": "AU"}
]

ATTACK_ARCHETYPES = [
    "DORMANT_PRIV_ESCALATION",
    "IMPOSSIBLE_TRAVEL_TOKEN_HIJACK",
    "LATERAL_ROLE_PIVOT_EXFIL",
    "UNUSUAL_AUTOMATED_API_SWEEP"
]

# Background auto-generator state
_auto_streaming_active = False
_streaming_thread: Optional[threading.Thread] = None
_attack_history: List[Dict[str, Any]] = []

def compute_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

def generate_synthetic_attack(archetype: Optional[str] = None) -> Dict[str, Any]:
    """
    Generates a synchronized synthetic attack, stores normalized events,
    stitches the attack chain, updates the attack graph, and triggers
    autonomous model tuning (preventing manual user override).
    """
    db = get_db()
    attack_type = archetype or random.choice(ATTACK_ARCHETYPES)
    identity_info = random.choice(IDENTITIES_CATALOG)
    ident_key = identity_info["key"]
    ident_name = identity_info["name"]
    role = random.choice(ROLES_CATALOG)
    policy = random.choice(POLICIES_CATALOG)
    resource = random.choice(RESOURCES_CATALOG)

    loc1, loc2 = random.sample(LOCATIONS_CATALOG, 2)
    ip1 = f"{random.randint(45, 198)}.{random.randint(10, 250)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
    ip2 = f"{random.randint(45, 198)}.{random.randint(10, 250)}.{random.randint(1, 254)}.{random.randint(1, 254)}"

    now = datetime.now(timezone.utc)
    t0 = now - timedelta(minutes=random.randint(20, 60))
    t1 = t0 + timedelta(minutes=random.randint(3, 8))
    t2 = t1 + timedelta(minutes=random.randint(2, 6))
    t3 = t2 + timedelta(minutes=random.randint(1, 4))

    session_id = f"sess-{uuid.uuid4().hex[:12]}"
    incident_id = f"inc-synth-{ident_key.replace('@', '_').replace('.', '_')}-{uuid.uuid4().hex[:6]}"

    events_to_insert = []
    detected_rules = []

    # --- Step 1: Okta Initial Session Event ---
    dormant_last_active = (t0 - timedelta(days=identity_info["dormant_gap"])).strftime("%Y-%m-%dT%H:%M:%SZ")
    e1_id = f"evt-okta-{uuid.uuid4().hex[:8]}"
    e1_ts = t0.strftime("%Y-%m-%dT%H:%M:%SZ")
    e1 = NormalizedEvent(
        event_id=e1_id,
        source="okta",
        source_file="synthetic_generator.stream",
        record_ref=f"synthetic:{e1_id}",
        ts_utc=e1_ts,
        ts_original_tz=e1_ts,
        identity_key=ident_key,
        principal_raw=ident_name,
        session_id=session_id,
        ip=ip1,
        geo=loc1,
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0",
        action="user.session.start",
        resource="okta_sso",
        outcome="SUCCESS",
        privilege_context={"clearance_level": identity_info["clearance"], "dormant_gap_days": identity_info["dormant_gap"]},
        raw_hash=compute_hash(f"{e1_id}_{e1_ts}_{ident_key}"),
        validation=ValidationDetails(status="VALID", reasons=[])
    )
    events_to_insert.append(e1)

    # Check DET-01 Dormant
    d1 = detect_dormant_reactivation(e1.model_dump(), {"last_active_ts": dormant_last_active, "p95_gap_days": 30.0})
    if d1["detected"]:
        detected_rules.append(d1["rule_id"])

    # --- Step 2: AWS CloudTrail AssumeRole Event ---
    e2_id = f"evt-ct-{uuid.uuid4().hex[:8]}"
    e2_ts = t1.strftime("%Y-%m-%dT%H:%M:%SZ")
    use_ip2 = (attack_type == "IMPOSSIBLE_TRAVEL_TOKEN_HIJACK")
    e2 = NormalizedEvent(
        event_id=e2_id,
        source="cloudtrail",
        source_file="synthetic_generator.stream",
        record_ref=f"synthetic:{e2_id}",
        ts_utc=e2_ts,
        ts_original_tz=e2_ts,
        identity_key=ident_key,
        principal_raw=ident_name,
        session_id=session_id,
        ip=ip2 if use_ip2 else ip1,
        geo=loc2 if use_ip2 else loc1,
        user_agent="aws-cli/2.15.15 Python/3.11.8 Windows/10 exe/AMD64",
        action="AssumeRole",
        resource=role,
        outcome="SUCCESS",
        privilege_context={"role": role},
        raw_hash=compute_hash(f"{e2_id}_{e2_ts}_{role}"),
        validation=ValidationDetails(status="VALID", reasons=[])
    )
    events_to_insert.append(e2)

    # Check DET-05 Impossible Travel or DET-02 Token Abuse
    if use_ip2:
        d5 = detect_impossible_travel(e1.model_dump(), e2.model_dump())
        if d5["detected"]:
            detected_rules.append(d5["rule_id"])
        d2 = detect_token_abuse(e2.model_dump(), e1.model_dump())
        if d2["detected"]:
            detected_rules.append(d2["rule_id"])

    # --- Step 3: AWS Privilege Escalation (AttachUserPolicy) ---
    e3_id = f"evt-ct-{uuid.uuid4().hex[:8]}"
    e3_ts = t2.strftime("%Y-%m-%dT%H:%M:%SZ")
    e3 = NormalizedEvent(
        event_id=e3_id,
        source="cloudtrail",
        source_file="synthetic_generator.stream",
        record_ref=f"synthetic:{e3_id}",
        ts_utc=e3_ts,
        ts_original_tz=e3_ts,
        identity_key=ident_key,
        principal_raw=ident_name,
        session_id=session_id,
        ip=ip2 if use_ip2 else ip1,
        geo=loc2 if use_ip2 else loc1,
        user_agent="aws-sdk-js/3.490.0",
        action="AttachUserPolicy",
        resource=policy,
        outcome="SUCCESS",
        privilege_context={"role": role, "escalated_policy": policy},
        raw_hash=compute_hash(f"{e3_id}_{e3_ts}_{policy}"),
        validation=ValidationDetails(status="VALID", reasons=[])
    )
    events_to_insert.append(e3)

    # Check DET-03 Privilege Escalation
    d3 = detect_privilege_escalation(e3.model_dump(), {"clearance_level": identity_info["clearance"]})
    if d3["detected"]:
        detected_rules.append(d3["rule_id"])

    # --- Step 4: Sensitive Resource Exfiltration ---
    e4_id = f"evt-ct-{uuid.uuid4().hex[:8]}"
    e4_ts = t3.strftime("%Y-%m-%dT%H:%M:%SZ")
    ua4 = "python-requests/2.31.0" if (attack_type == "UNUSUAL_AUTOMATED_API_SWEEP") else "Boto3/1.34.26 Python/3.11.8"
    e4 = NormalizedEvent(
        event_id=e4_id,
        source="cloudtrail",
        source_file="synthetic_generator.stream",
        record_ref=f"synthetic:{e4_id}",
        ts_utc=e4_ts,
        ts_original_tz=e4_ts,
        identity_key=ident_key,
        principal_raw=ident_name,
        session_id=session_id,
        ip=ip2 if use_ip2 else ip1,
        geo=loc2 if use_ip2 else loc1,
        user_agent=ua4,
        action="GetObject",
        resource=resource,
        outcome="SUCCESS",
        privilege_context={"role": role, "escalated_policy": policy},
        raw_hash=compute_hash(f"{e4_id}_{e4_ts}_{resource}"),
        validation=ValidationDetails(status="VALID", reasons=[])
    )
    events_to_insert.append(e4)

    # Check DET-04 Unusual API
    d4 = detect_unusual_api_calls(e4.model_dump())
    if d4["detected"]:
        detected_rules.append(d4["rule_id"])

    # --- Persist Events ---
    for evt in events_to_insert:
        db[COLLECTIONS["normalized_events"]].update_one(
            {"source": evt.source, "event_id": evt.event_id},
            {"$set": evt.model_dump()},
            upsert=True
        )

    # --- Construct Identity Links ---
    links = [
        IdentityLink(
            link_id=f"link-{e1_id}-{e2_id}",
            from_subject=e1_id,
            to_subject=e2_id,
            basis=["exact_identity_match", "session_correlation"],
            confidence=0.98,
            provenance="VALIDATED_OBSERVATION"
        ),
        IdentityLink(
            link_id=f"link-{e2_id}-{e3_id}",
            from_subject=e2_id,
            to_subject=e3_id,
            basis=["session_id_match", "role_continuity"],
            confidence=0.95,
            provenance="VALIDATED_OBSERVATION"
        ),
        IdentityLink(
            link_id=f"link-{e3_id}-{e4_id}",
            from_subject=e3_id,
            to_subject=e4_id,
            basis=["escalated_privilege_invocation"],
            confidence=0.92,
            provenance="LABEL_DERIVED"
        )
    ]
    for l in links:
        db[COLLECTIONS["identity_links"]].update_one(
            {"link_id": l.link_id},
            {"$set": l.model_dump()},
            upsert=True
        )

    # --- Construct Incident Chain ---
    stages = [
        ChainStage(stage="INITIAL_AUTHENTICATION", event_ref=e1_id, link_provenance="LABEL_DERIVED"),
        ChainStage(stage="SESSION_ASSUMPTION", event_ref=e2_id, link_provenance="VALIDATED_OBSERVATION"),
        ChainStage(stage="PRIVILEGE_ESCALATION", event_ref=e3_id, link_provenance="VALIDATED_OBSERVATION"),
        ChainStage(stage="DATA_EXFILTRATION_ATTEMPT", event_ref=e4_id, link_provenance="VALIDATED_OBSERVATION")
    ]
    chain = IncidentChain(
        incident_id=incident_id,
        stages=stages,
        links=[l.link_id for l in links],
        subject_ids=[ident_key],
        confidence=0.98,
        unresolved=[]
    )
    db[COLLECTIONS["incident_chains"]].update_one(
        {"incident_id": incident_id},
        {"$set": chain.model_dump()},
        upsert=True
    )

    # --- Factor Values & Additive Risk Score ---
    factor_values = {
        "behavioral_anomaly": float(random.randint(85, 98)),
        "privilege_level": float(identity_info["clearance"] * 25),
        "privilege_delta": float(random.randint(90, 99)),
        "resource_sensitivity": 95.0 if "vault" in resource or "export" in resource else 85.0,
        "sequence_stage": float(random.randint(88, 98))
    }
    evidence_map = {
        "behavioral_anomaly": [{"source_file": "synthetic_generator.stream", "record_id": e1_id}],
        "privilege_delta": [{"source_file": "synthetic_generator.stream", "record_id": e3_id}],
        "resource_sensitivity": [{"source_file": "synthetic_generator.stream", "record_id": e4_id}],
        "sequence_stage": [{"source_file": "synthetic_generator.stream", "record_id": e2_id}]
    }

    # Calculate using active dynamically tuned weights
    risk_score = calculate_risk_score("identity", ident_key, factor_values, evidence_map)
    db[COLLECTIONS["risk_scores"]].update_one(
        {"subject.id": ident_key},
        {"$set": risk_score.model_dump()},
        upsert=True
    )

    # --- Deduplicated Alert ---
    recommended_act = "RESTRICT" if risk_score.total >= 85 else "REVOKE_SESSION"
    alert = Alert(
        alert_id=f"alt-{incident_id}",
        incident_id=incident_id,
        subject={"type": "identity", "id": ident_key},
        severity="CRITICAL" if risk_score.total >= 85 else "HIGH",
        what=f"Synthetic attack [{attack_type}]: multi-stage credential abuse and unauthorized privilege escalation.",
        why=f"Dormant activation on {ident_name} followed by {role} assumption, {policy} attachment, and {resource} access.",
        evidence_refs=[
            EvidenceRef(source_file="synthetic_generator.stream", record_id=e1_id),
            EvidenceRef(source_file="synthetic_generator.stream", record_id=e3_id),
            EvidenceRef(source_file="synthetic_generator.stream", record_id=e4_id)
        ],
        risk_score_ref=ident_key,
        impact=f"Unauthorized access to high-sensitivity resource '{resource}' via privilege escalation.",
        recommended_action=recommended_act,
        status="OPEN",
        first_seen=e1_ts,
        last_seen=e4_ts,
        dup_count=1
    )
    db[COLLECTIONS["alerts"]].update_one(
        {"alert_id": alert.alert_id},
        {"$set": alert.model_dump()},
        upsert=True
    )

    # --- Simulator Action Record ---
    sim_action = SimulatorAction(
        action_id=f"act-{alert.alert_id}",
        incident_id=incident_id,
        action=recommended_act,
        target=ident_key,
        expected_loss={"productivity_hours": 0.5, "interruption_risk": 0.1},
        approval={"status": "PENDING_APPROVAL", "approver": None},
        preview=f"Simulate {recommended_act} enforcement against {ident_key} across Okta and AWS IAM.",
        result="PENDING_APPROVAL",
        rollback=f"Restore active session and revoke temporary {policy} assignment."
    )
    db[COLLECTIONS["simulator_actions"]].update_one(
        {"action_id": sim_action.action_id},
        {"$set": sim_action.model_dump()},
        upsert=True
    )

    # --- AUTONOMOUS MODEL TUNING (Based on synthetic attack) ---
    tuning_entry = autonomous_tune_from_attack(
        attack_type=attack_type,
        detected_rules=list(set(detected_rules)),
        target_identity=ident_key,
        score_factors=factor_values
    )

    # SHA-256 Tamper-evident Audit Logging for the Autonomous Tuning
    last_log = db[COLLECTIONS["audit_logs"]].find_one(sort=[("_id", -1)])
    prev_hash = last_log.get("curr_hash") if last_log else "0000000000000000000000000000000000000000000000000000000000000000"
    audit_entry = create_audit_entry(
        actor="AUTONOMOUS_SYNTHETIC_TUNER",
        action="SYNTHETIC_ATTACK_AUTOTUNE",
        details={
            "incident_id": incident_id,
            "attack_type": attack_type,
            "target": ident_key,
            "risk_score": risk_score.total,
            "tuning_summary": tuning_entry["reasons"]
        },
        prev_hash=prev_hash
    )
    db[COLLECTIONS["audit_logs"]].insert_one(audit_entry.model_dump())

    # --- Build Synchronous Attack Graph ---
    all_events = list(db[COLLECTIONS["normalized_events"]].find({}, {"_id": 0}))
    all_chains = list(db[COLLECTIONS["incident_chains"]].find({}, {"_id": 0}))
    updated_graph = build_attack_graph(all_events, all_chains)

    result_summary = {
        "status": "SUCCESS",
        "incident_id": incident_id,
        "attack_type": attack_type,
        "target_identity": ident_key,
        "identity_name": ident_name,
        "assumed_role": role,
        "escalated_policy": policy,
        "target_resource": resource,
        "risk_score": risk_score.total,
        "recommended_action": recommended_act,
        "detected_rules": list(set(detected_rules)),
        "autonomous_tuning": tuning_entry,
        "active_weights": get_current_weights(),
        "graph_nodes_count": len(updated_graph["nodes"]),
        "graph_edges_count": len(updated_graph["edges"]),
        "ranked_paths_count": len(updated_graph["ranked_paths"])
    }

    _attack_history.append(result_summary)
    if len(_attack_history) > 30:
        _attack_history.pop(0)

    return result_summary

def get_attack_history() -> List[Dict[str, Any]]:
    return list(_attack_history)

def is_auto_streaming() -> bool:
    return _auto_streaming_active

def set_auto_streaming(enabled: bool, interval_seconds: float = 6.0) -> bool:
    global _auto_streaming_active, _streaming_thread
    if enabled:
        if _auto_streaming_active:
            return True
        _auto_streaming_active = True

        def _loop():
            while _auto_streaming_active:
                try:
                    generate_synthetic_attack()
                except Exception as e:
                    print(f"Error generating synthetic attack in background loop: {e}")
                time.sleep(interval_seconds)

        _streaming_thread = threading.Thread(target=_loop, daemon=True)
        _streaming_thread.start()
        return True
    else:
        _auto_streaming_active = False
        return False

