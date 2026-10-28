import pytest
import tempfile
import json
from pathlib import Path
from src.db import get_db, setup_db
from src.config import COLLECTIONS
from src.ingest import ingest_file, run_ingest_all, validate_file_path

@pytest.fixture(autouse=True)
def init_db():
    setup_db()

def test_ingest_path_traversal_denied():
    """Security test: Reject files outside allowed data/fixtures roots."""
    with pytest.raises(PermissionError):
        validate_file_path("../../Windows/System32/drivers/etc/hosts")

def test_ingest_malformed_json_quarantine():
    """Integrity test: Malformed JSON lines must be quarantined, not crash ingest."""
    db = get_db()
    with tempfile.NamedTemporaryFile("w", delete=False, suffix="_okta.jsonl", dir="fixtures", encoding="utf-8") as f:
        f.write('{"event_id": "malformed_1", "published": "2026-10-28T00:00:00Z", \n') # unclosed JSON
        temp_name = f.name

    try:
        rep = ingest_file(temp_name, db)
        assert rep["invalid_quarantined"] == 1
        assert rep["new_inserted"] == 0
    finally:
        Path(temp_name).unlink(missing_ok=True)

def test_ingest_out_of_order_timestamps():
    """Validation test: Detects out-of-order timestamps across sequential log records."""
    db = get_db()
    with tempfile.NamedTemporaryFile("w", delete=False, suffix="_okta.jsonl", dir="fixtures", encoding="utf-8") as f:
        f.write('{"event_id": "ord_1", "published": "2026-10-28T12:00:00Z", "actor": {"id": "user1"}}\n')
        f.write('{"event_id": "ord_2", "published": "2026-10-28T10:00:00Z", "actor": {"id": "user1"}}\n') # backwards
        temp_name = f.name

    try:
        rep = ingest_file(temp_name, db)
        assert rep["order_anomalies"] >= 1
    finally:
        Path(temp_name).unlink(missing_ok=True)

def test_ingest_inert_mongo_operator_storage():
    """Security test: A log field containing Mongo operators is stored as inert data."""
    import uuid
    uid = uuid.uuid4().hex[:8]
    eid = f"sec_op_{uid}"
    db = get_db()
    with tempfile.NamedTemporaryFile("w", delete=False, suffix="_cloudtrail.jsonl", dir="fixtures", encoding="utf-8") as f:
        f.write(f'{{"event_id": "{eid}", "eventTime": "2026-10-28T12:00:00Z", "userIdentity": {{"userName": "user1"}}, "userAgent": "{{\\"$where\\": \\"sleep(1000)\\"}}"}}\n')
        temp_name = f.name

    try:
        rep = ingest_file(temp_name, db)
        assert rep["new_inserted"] == 1
        # Retrieve and verify stored as inert string
        stored = db[COLLECTIONS["normalized_events"]].find_one({"event_id": eid})
        assert stored is not None
        assert stored["user_agent"] == '{"$where": "sleep(1000)"}'
    finally:
        Path(temp_name).unlink(missing_ok=True)

def test_m1_acceptance_report_separation():
    """M1 Acceptance check: Separates failed validation from suspicious security candidates."""
    rep = run_ingest_all()
    assert rep["status"] == "M1_INGEST_COMPLETE"
    assert "failed_validation_quarantined" in rep
    assert "suspicious_security_candidates" in rep
    assert rep["sources_processed"] >= 2
