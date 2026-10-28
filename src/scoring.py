from typing import List, Dict, Any, Optional, Tuple
from src.models import RiskScore, RiskFactor

FACTOR_WEIGHTS = {
    "behavioral_anomaly": 0.25,
    "privilege_level": 0.20,
    "privilege_delta": 0.25,
    "resource_sensitivity": 0.15,
    "sequence_stage": 0.15
}

def compute_identity_factors(
    identity_key: str,
    events: List[Dict[str, Any]],
    findings: List[Dict[str, Any]],
    identity_meta: Dict[str, Any],
    chain: Optional[Any] = None
) -> Tuple[Dict[str, float], Dict[str, List[Dict[str, str]]]]:
    """
    Computes data-driven 0-100 risk factor values and evidence mappings from actual observed telemetry.
    """
    # 1. Behavioral anomaly
    anomaly_score = 0.0
    evidence_map: Dict[str, List[Dict[str, str]]] = {}
    
    event_ids = {e.get("event_id") for e in events}
    id_findings = [f for f in findings if f.get("event_id") in event_ids and f.get("detected")]
    if id_findings:
        sev_weights = {"LOW": 20.0, "MEDIUM": 45.0, "HIGH": 75.0, "CRITICAL": 95.0}
        max_sev = max(sev_weights.get(f.get("severity", "LOW"), 20.0) for f in id_findings)
        count_boost = min(20.0, len(id_findings) * 5.0)
        anomaly_score = min(100.0, max_sev + count_boost)
        evidence_map["behavioral_anomaly"] = [
            {"source_file": str(f.get("evidence_refs", [{}])[0].get("source_file", "okta_sample.jsonl") if f.get("evidence_refs") else "okta_sample.jsonl"),
             "record_id": str(f.get("event_id", ""))}
            for f in id_findings[:3]
        ]
    
    # 2. Privilege level
    clearance = identity_meta.get("clearance_level", 1)
    priv_level = min(100.0, max(0.0, float(clearance) * 20.0))
    
    # 3. Privilege delta
    priv_delta = 0.0
    for e in events:
        action = e.get("action", "")
        res = e.get("resource", "")
        if "Attach" in action or "Put" in action or "CreateAccessKey" in action:
            if "AdministratorAccess" in res or "*:*" in res or "admin" in res.lower():
                priv_delta = max(priv_delta, 95.0)
                evidence_map.setdefault("privilege_delta", []).append({
                    "source_file": e.get("source_file", "cloudtrail_sample.jsonl"),
                    "record_id": str(e.get("record_ref", e.get("event_id", ""))).split(":")[-1]
                })
            else:
                priv_delta = max(priv_delta, 45.0)
        elif "AssumeRole" in action:
            priv_delta = max(priv_delta, 35.0)
            
    # 4. Resource sensitivity
    res_sens = 0.0
    for e in events:
        res = e.get("resource", "").lower()
        if "pii-vault" in res or "production_export" in res or "customer-pii" in res:
            res_sens = max(res_sens, 90.0)
            evidence_map.setdefault("resource_sensitivity", []).append({
                "source_file": e.get("source_file", "cloudtrail_sample.jsonl"),
                "record_id": str(e.get("record_ref", e.get("event_id", ""))).split(":")[-1]
            })
        elif "secret" in res or "credentials" in res:
            res_sens = max(res_sens, 85.0)
        elif "analytics" in res or "reports" in res:
            res_sens = max(res_sens, 30.0)
        elif "dev" in res or "builds" in res:
            res_sens = max(res_sens, 20.0)
            
    # 5. Sequence stage
    seq_stage = 0.0
    if chain and hasattr(chain, "stages") and chain.stages:
        stage_names = [s.stage for s in chain.stages]
        if "DATA_EXFILTRATION_ATTEMPT" in stage_names:
            seq_stage = 95.0
        elif "PRIVILEGE_ESCALATION" in stage_names:
            seq_stage = 75.0
        elif "SESSION_ASSUMPTION" in stage_names or "SESSION_HIJACK_OR_REPLAY" in stage_names:
            seq_stage = 50.0
        elif "INITIAL_AUTHENTICATION" in stage_names:
            seq_stage = 25.0
            
    factor_values = {
        "behavioral_anomaly": round(anomaly_score, 1),
        "privilege_level": round(priv_level, 1),
        "privilege_delta": round(priv_delta, 1),
        "resource_sensitivity": round(res_sens, 1),
        "sequence_stage": round(seq_stage, 1)
    }
    return factor_values, evidence_map

def calculate_risk_score(
    subject_type: str,
    subject_id: str,
    factor_values: Dict[str, float],
    evidence_map: Dict[str, List[Dict[str, str]]],
    weights: Optional[Dict[str, float]] = None
) -> RiskScore:
    """
    Computes additive factor risk score strictly clamped between 0 and 100.
    Explanation includes the top-3 contributing factors.
    Uses dynamically tuned model weights when available.
    """
    factors = []
    total_contribution = 0.0

    if weights is None:
        try:
            from src.feedback import get_current_weights
            active_weights = get_current_weights()
        except Exception:
            active_weights = FACTOR_WEIGHTS
    else:
        active_weights = weights

    for name, base_w in FACTOR_WEIGHTS.items():
        weight = active_weights.get(name, base_w)
        val = factor_values.get(name, 0.0)
        contrib = weight * val
        total_contribution += contrib
        factors.append(RiskFactor(
            name=name,
            weight=weight,
            value=val,
            contribution=round(contrib, 2),
            evidence_refs=evidence_map.get(name, [])
        ))

    clamped_total = max(0, min(100, int(round(total_contribution))))

    # Sort factors by contribution descending to extract top-3
    sorted_factors = sorted(factors, key=lambda f: f.contribution, reverse=True)
    top_factors = [f.name for f in sorted_factors[:3] if f.contribution > 0]

    return RiskScore(
        subject={"type": subject_type, "id": subject_id},
        total=clamped_total,
        factors=factors,
        explanation={
            "top_factors": top_factors,
            "counterfactual": f"Removing {top_factors[0]} reduces risk score by {sorted_factors[0].contribution:.1f}" if top_factors else "Baseline risk profile"
        }
    )
