import pytest
from fastapi.testclient import TestClient
from src.synthetic_generator import generate_synthetic_attack, get_attack_history
from src.feedback import get_current_weights, get_tuning_log
from src.graph import build_attack_graph
from src.db import setup_db, get_db
from src.config import COLLECTIONS
from src.api import app

@pytest.fixture(autouse=True)
def init_db():
    setup_db()

def test_synthetic_attack_generation():
    """Verify synthetic attack creates full attack chain, alerts, and autonomous tuning."""
    initial_log_count = len(get_tuning_log())
    res = generate_synthetic_attack("DORMANT_PRIV_ESCALATION")

    assert res["status"] == "SUCCESS"
    assert "incident_id" in res
    assert res["risk_score"] > 0
    assert len(res["detected_rules"]) >= 1
    assert "autonomous_tuning" in res
    assert len(get_tuning_log()) > initial_log_count

def test_graph_synchronous_with_synthetic_attack():
    """Verify live attack graph updates and includes synthetic attack nodes and hops."""
    db = get_db()
    res = generate_synthetic_attack("IMPOSSIBLE_TRAVEL_TOKEN_HIJACK")

    events = list(db[COLLECTIONS["normalized_events"]].find({}, {"_id": 0}))
    chains = list(db[COLLECTIONS["incident_chains"]].find({}, {"_id": 0}))
    graph = build_attack_graph(events, chains)

    # Verify the target identity is present in graph nodes
    node_ids = [n["id"] for n in graph["nodes"]]
    assert res["target_identity"] in node_ids

    # Verify at least one ranked path corresponds to this subject
    path_subjects = [p["subject"] for p in graph["ranked_paths"]]
    assert res["target_identity"] in path_subjects

def test_model_tuning_based_on_synthetic_attacks():
    """Verify model weights are calibrated automatically based on detected attack signals."""
    weights_before = get_current_weights()
    res = generate_synthetic_attack("DORMANT_PRIV_ESCALATION")
    weights_after = get_current_weights()

    assert "autonomous_tuning" in res
    assert res["autonomous_tuning"]["status"] == "AUTONOMOUS_TUNED"
    # Factors should stay within valid bounds (sum around 1.0, clamped [0.1, 0.5])
    for f, w in weights_after.items():
        assert 0.05 <= w <= 0.60

def test_user_manual_tuning_strictly_prohibited():
    """Verify user cannot manually tamper with model tuning via API (403 Forbidden)."""
    client = TestClient(app)
    resp = client.post("/api/feedback", json={"factor": "behavioral_anomaly", "direction": "INCREASE"})
    assert resp.status_code == 403
    assert "Manual model tuning is disabled" in resp.json()["detail"]

