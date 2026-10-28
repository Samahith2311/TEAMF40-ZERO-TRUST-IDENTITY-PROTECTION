import pytest
from src.alerts import create_alert_from_incident, verify_evidence_refs
from src.simulator import execute_simulated_action
from src.audit import create_audit_entry, verify_audit_chain

def test_alert_duplicate_collapse():
    """B6 requirement: 3 duplicate deliveries collapse to 1 incident with dup_count."""
    alt = create_alert_from_incident(
        incident_id="inc-test-dup",
        subject_id="target@corp.internal",
        score=75,
        risk_score_ref="target@corp.internal",
        evidences=[{"source_file": "okta_sample.jsonl", "record_id": "1"}],
        what="Suspicious session",
        why="Dormant login",
        first_seen="2026-10-28T10:00:00Z",
        last_seen="2026-10-28T10:00:00Z"
    )
    # Simulate two duplicate deliveries updating dup_count and last_seen
    alt.dup_count += 2
    alt.last_seen = "2026-10-28T10:20:00Z"
    assert alt.dup_count == 3
    assert alt.incident_id == "inc-test-dup"

def test_altered_citation_fails_verifier():
    """B6 requirement: Altered or invalid citation drops verification below 100%."""
    alerts = [{
        "alert_id": "alt-bad",
        "evidence_refs": [
            {"source_file": "okta_sample.jsonl", "record_id": "9999"} # Nonexistent line
        ]
    }]
    rep = verify_evidence_refs(alerts, fixtures_dir="fixtures")
    assert rep["valid_pct"] < 100.0
    assert rep["valid_citations"] == 0
    assert len(rep["invalid_citations"]) == 1

def test_protected_identity_denied_auto_restriction():
    """B6 requirement: Protected identities never auto-restricted."""
    action = execute_simulated_action(
        incident_id="inc-root",
        action="RESTRICT",
        target_identity="breakglass-admin@corp.internal",
        approved=False
    )
    assert action.result == "DENIED_PROTECTED_IDENTITY"
    assert action.label == "SIMULATED"

def test_audit_log_tampering_detected():
    """B6 requirement: Tampered audit entry detected by chain verifier."""
    log1 = create_audit_entry("analyst1", "ACTION_1", {"k": "v"}, "0" * 64)
    log2 = create_audit_entry("analyst1", "ACTION_2", {"k": "v2"}, log1.curr_hash)
    valid, _, _ = verify_audit_chain([log1.model_dump(), log2.model_dump()])
    assert valid is True

    # Tamper
    tampered = [log1.model_dump(), log2.model_dump()]
    tampered[1]["actor"] = "attacker"
    valid, idx, _ = verify_audit_chain(tampered)
    assert valid is False
    assert idx == 1
