import pytest
from src.scoring import calculate_risk_score, FACTOR_WEIGHTS
from src.stitching import stitch_identity_events
from src.alerts import create_alert_from_incident, verify_evidence_refs

def test_risk_score_breakdown_sums_to_total():
    """B4 requirement: Factor breakdown contributions sum to clamped total."""
    factor_values = {
        "behavioral_anomaly": 80.0,
        "privilege_level": 50.0,
        "privilege_delta": 90.0,
        "resource_sensitivity": 70.0,
        "sequence_stage": 80.0
    }
    evidence_map = {
        "behavioral_anomaly": [{"source_file": "okta_sample.jsonl", "record_id": "2"}]
    }
    score = calculate_risk_score("identity", "bob@corp.internal", factor_values, evidence_map)
    
    # 0.25*80 + 0.20*50 + 0.25*90 + 0.15*70 + 0.15*80 = 20 + 10 + 22.5 + 10.5 + 12 = 75
    sum_contrib = sum(f.contribution for f in score.factors)
    assert abs(sum_contrib - score.total) <= 1
    assert 0 <= score.total <= 100
    assert len(score.explanation["top_factors"]) <= 3

def test_stitching_reconstructs_sample_chain():
    """B5 requirement: Reconstructs known attack chain with provenance links."""
    events = [
        {
            "event_id": "ok-1", "source": "okta", "identity_key": "bob@corp.internal",
            "ip": "203.0.113.45", "action": "user.session.start", "ts_utc": "2026-10-28T10:00:00Z"
        },
        {
            "event_id": "ct-1", "source": "cloudtrail", "identity_key": "bob@corp.internal",
            "ip": "203.0.113.45", "action": "AssumeRole", "ts_utc": "2026-10-28T10:10:00Z"
        },
        {
            "event_id": "ct-2", "source": "cloudtrail", "identity_key": "bob@corp.internal",
            "ip": "203.0.113.45", "action": "AttachUserPolicy", "resource": "AdministratorAccess", "ts_utc": "2026-10-28T10:20:00Z"
        }
    ]
    links, chains = stitch_identity_events(events)
    assert len(links) >= 1
    assert any(l.provenance == "VALIDATED_OBSERVATION" for l in links)
    assert len(chains) == 1
    chain = chains[0]
    assert chain.incident_id == "inc-bob_corp_internal"
    stages = [s.stage for s in chain.stages]
    assert "INITIAL_AUTHENTICATION" in stages
    assert "PRIVILEGE_ESCALATION" in stages
