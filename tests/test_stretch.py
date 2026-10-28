import pytest
from src.graph import build_attack_graph
from src.feedback import (
    apply_analyst_feedback,
    revert_last_feedback,
    get_current_weights,
    FACTOR_WEIGHTS
)

def test_attack_graph_generation():
    events = [
        {"identity_key": "alice@corp.internal", "session_id": "s-1", "action": "AssumeRole", "resource": "RoleA", "privilege_context": {}},
        {"identity_key": "bob@corp.internal", "action": "AttachUserPolicy", "resource": "AdministratorAccess", "privilege_context": {}},
        {"identity_key": "bob@corp.internal", "session_id": "s-2", "action": "GetObject", "resource": "corp-customer-pii-vault", "privilege_context": {}}
    ]
    chains = [{
        "incident_id": "inc-bob",
        "stages": ["PRIVILEGE_ESCALATION", "DATA_EXFILTRATION_ATTEMPT"],
        "subject_ids": ["bob@corp.internal"]
    }]
    graph = build_attack_graph(events, chains)
    assert len(graph["nodes"]) >= 3
    assert len(graph["edges"]) >= 2
    assert len(graph["ranked_paths"]) >= 1
    assert graph["ranked_paths"][0]["target"] == "corp-customer-pii-vault"

def test_analyst_feedback_bounded_update():
    base_w = FACTOR_WEIGHTS["behavioral_anomaly"]
    res = apply_analyst_feedback("behavioral_anomaly", "INCREASE")
    assert res["new_weight"] == round(base_w * 1.10, 4)

    # Revert
    rev = revert_last_feedback()
    assert rev["status"] == "REVERTED"
    assert rev["weights"]["behavioral_anomaly"] == base_w

def test_analyst_feedback_clamping():
    base_w = FACTOR_WEIGHTS["privilege_delta"]
    max_w = round(base_w * 2.0, 4)
    min_w = round(base_w * 0.5, 4)

    # Apply 20 consecutive increases - must NOT exceed 2.0x baseline
    for _ in range(20):
        apply_analyst_feedback("privilege_delta", "INCREASE")
    weights = get_current_weights()
    assert weights["privilege_delta"] <= max_w

    # Apply 30 consecutive decreases - must NOT drop below 0.5x baseline
    for _ in range(30):
        apply_analyst_feedback("privilege_delta", "DECREASE")
    weights = get_current_weights()
    assert weights["privilege_delta"] >= min_w

    # Reset
    FACTOR_WEIGHTS["privilege_delta"] = base_w

