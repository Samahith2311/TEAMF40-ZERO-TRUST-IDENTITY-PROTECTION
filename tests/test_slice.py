import pytest
import json
import tempfile
from pathlib import Path
from src.db import setup_db, get_db
from src.config import COLLECTIONS
from src.ingest import ingest_file
from src.pipeline import run_pipeline_slice
from src.simulator import execute_simulated_action
from src.audit import create_audit_entry, verify_audit_chain
from src.alerts import verify_evidence_refs
from src.api import sanitize_query_param
from fastapi import HTTPException

def test_happy_path_pipeline():
    """Validates complete end-to-end slice execution."""
    result = run_pipeline_slice()
    assert result["status"] == "SUCCESS"
    assert result["events_count"] >= 7
    assert result["chains_count"] >= 1
    assert result["risk_score"] == 80
    assert result["recommended_action"] == "REVOKE_SESSION"
    assert result["evidence_verification"]["valid_pct"] == 100.0

def test_malformed_record_quarantined():
    """Negative test: Ingesting malformed JSON must quarantine record and not crash."""
    db = get_db()
    with tempfile.NamedTemporaryFile("w", delete=False, suffix="_okta.jsonl", dir="fixtures", encoding="utf-8") as f:
        f.write('{"event_id": "bad-01", "published": "invalid-time"\n') # malformed JSON
        temp_name = f.name

    try:
        res = ingest_file(temp_name, db)
        assert res["invalid_quarantined"] == 1
        assert res["new_inserted"] == 0
    finally:
        Path(temp_name).unlink(missing_ok=True)

def test_duplicate_reingest_idempotency():
    """Integrity test: Re-ingesting existing files must produce 0 new inserted records."""
    db = get_db()
    res = ingest_file("fixtures/okta_sample.jsonl", db)
    assert res["new_inserted"] == 0
    assert res["duplicates"] > 0

def test_mongo_operator_injection_denied():
    """Security test AC-01: Prohibits MongoDB query injection via dict or $-operators."""
    with pytest.raises(HTTPException) as exc1:
        sanitize_query_param({"$gt": ""})
    assert exc1.value.status_code == 400

    with pytest.raises(HTTPException) as exc2:
        sanitize_query_param("$where")
    assert exc2.value.status_code == 400

    # Benign string passes
    assert sanitize_query_param("alice@corp.internal") == "alice@corp.internal"

def test_protected_identity_restriction_denied():
    """Security test AC-03: Protected identities cannot be automatically restricted."""
    action = execute_simulated_action(
        incident_id="inc-breakglass",
        action="RESTRICT",
        target_identity="breakglass-admin@corp.internal",
        approved=False
    )
    assert action.result == "DENIED_PROTECTED_IDENTITY"
    assert action.approval["status"] == "DENIED"

def test_audit_chain_tamper_detection():
    """Security test AC-04: Hash chain must detect any modified or reordered audit entry."""
    e1 = create_audit_entry("analyst1", "LOGIN", {"ip": "127.0.0.1"}, "0000000000000000000000000000000000000000000000000000000000000000")
    e2 = create_audit_entry("analyst1", "APPROVE_ACTION", {"target": "bob"}, e1.curr_hash)

    logs = [e1.model_dump(), e2.model_dump()]
    valid, _, _ = verify_audit_chain(logs)
    assert valid is True

    # Tamper with entry 1
    tampered_logs = [e1.model_dump(), e2.model_dump()]
    tampered_logs[0]["action"] = "TAMPERED_ACTION"
    valid_tampered, fail_idx, reason = verify_audit_chain(tampered_logs)
    assert valid_tampered is False
    assert fail_idx == 0

def test_evidence_verifier_resolves_raw():
    """Verification test AC-06: Verifies citations against raw files."""
    alerts = [{
        "alert_id": "test-alt",
        "evidence_refs": [
            {"source_file": "okta_sample.jsonl", "record_id": "1"},
            {"source_file": "cloudtrail_sample.jsonl", "record_id": "2"}
        ]
    }]
    report = verify_evidence_refs(alerts, fixtures_dir="fixtures")
    assert report["valid_pct"] == 100.0
    assert report["valid_citations"] == 2
