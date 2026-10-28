import json
import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Tuple, Optional, List
from pymongo.collection import Collection
from pymongo.errors import DuplicateKeyError, BulkWriteError
from pymongo import UpdateOne

from src.config import COLLECTIONS
from src.db import get_db
from src.models import NormalizedEvent, ValidationDetails, ValidationResult

# Security bounds
MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024  # 50 MB
MAX_LINE_LENGTH_BYTES = 1024 * 1024       # 1 MB
ALLOWED_ROOTS = [Path("fixtures").resolve(), Path("data").resolve()]

def validate_file_path(file_path: str) -> Path:
    """Path traversal prevention: must resolve strictly inside allowed directories."""
    path = Path(file_path).resolve()
    is_allowed = any(root in path.parents or path == root for root in ALLOWED_ROOTS)
    if not is_allowed:
        # Also allow if relative path is inside current working directory fixtures
        cwd_fixtures = (Path.cwd() / "fixtures").resolve()
        cwd_data = (Path.cwd() / "data").resolve()
        if not (cwd_fixtures in path.parents or cwd_data in path.parents):
            raise PermissionError(f"Access denied: path '{file_path}' resolves outside allowed directories.")
    
    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    
    if path.stat().st_size > MAX_FILE_SIZE_BYTES:
        raise ValueError(f"File size {path.stat().st_size} exceeds max allowed {MAX_FILE_SIZE_BYTES} bytes.")
    
    return path

def compute_raw_hash(raw_bytes_or_str) -> str:
    if isinstance(raw_bytes_or_str, str):
        raw_bytes_or_str = raw_bytes_or_str.encode("utf-8")
    return hashlib.sha256(raw_bytes_or_str).hexdigest()

def normalize_timestamp(ts_str: str) -> Tuple[str, Optional[str], bool]:
    """Converts timestamp to ISO8601 UTC and validates datetime sanity."""
    if not ts_str:
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        return now_utc, None, False
    try:
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        dt_utc = dt.astimezone(timezone.utc)
        return dt_utc.strftime("%Y-%m-%dT%H:%M:%SZ"), ts_str, True
    except Exception:
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        return now_utc, ts_str, False

def parse_okta_record(raw: Dict[str, Any], source_file: str, line_no: int, raw_hash: str) -> Tuple[NormalizedEvent, ValidationResult]:
    event_id = str(raw.get("event_id") or raw.get("uuid") or f"okta-{line_no}-{raw_hash[:8]}")
    ts_raw = raw.get("published") or raw.get("timestamp") or ""
    ts_utc, ts_orig, ts_valid = normalize_timestamp(ts_raw)

    actor = raw.get("actor", {})
    identity_key = actor.get("alternateId") or actor.get("id") or raw.get("userId") or "unknown"
    client = raw.get("client", {})
    geo = client.get("geographicalContext") or client.get("geo") or {}
    
    outcome_raw = str(raw.get("outcome", {}).get("result") or raw.get("result", "UNKNOWN")).upper()
    outcome = "SUCCESS" if outcome_raw in ["SUCCESS", "ALLOW"] else ("FAILURE" if outcome_raw in ["FAILURE", "DENY", "DENIED"] else "UNKNOWN")

    target = raw.get("target") or [{}]
    target_obj = target[0] if isinstance(target, list) and target else (target if isinstance(target, dict) else {})
    resource = target_obj.get("displayName") or target_obj.get("id") or "okta_sso"
    action = raw.get("eventType") or raw.get("action") or "unknown_action"
    debug = raw.get("debugContext", {})
    session_id = debug.get("session_id") or client.get("session_id")

    reasons = []
    structural_ok = True
    if not ts_valid:
        structural_ok = False
        reasons.append("Malformed or missing published timestamp")
    if identity_key == "unknown":
        structural_ok = False
        reasons.append("Missing actor identity alternateId/id")

    status = "VALID" if structural_ok else "INVALID"

    norm = NormalizedEvent(
        event_id=event_id,
        source="okta",
        source_file=source_file,
        record_ref=f"{source_file}:{line_no}",
        ts_utc=ts_utc,
        ts_original_tz=ts_orig,
        identity_key=identity_key,
        principal_raw=actor.get("displayName") or identity_key,
        session_id=session_id,
        ip=client.get("ipAddress") or client.get("ip") or "0.0.0.0",
        geo=geo,
        user_agent=client.get("userAgent") or client.get("user_agent") or "unknown",
        action=action,
        resource=resource,
        outcome=outcome,
        privilege_context={"role": "user", "clearance": 1, "admin": False},
        raw_hash=raw_hash,
        validation=ValidationDetails(status=status, reasons=reasons)
    )

    val_res = ValidationResult(
        record_ref=f"{source_file}:{line_no}",
        structural_ok=structural_ok,
        timestamp_ok=ts_valid,
        order_ok=True,
        identity_ref_ok=(identity_key != "unknown"),
        reasons=reasons
    )
    return norm, val_res

def parse_cloudtrail_record(raw: Dict[str, Any], source_file: str, line_no: int, raw_hash: str) -> Tuple[NormalizedEvent, ValidationResult]:
    event_id = str(raw.get("event_id") or raw.get("eventID") or f"ct-{line_no}-{raw_hash[:8]}")
    ts_raw = raw.get("eventTime") or raw.get("timestamp") or ""
    ts_utc, ts_orig, ts_valid = normalize_timestamp(ts_raw)

    user_ident = raw.get("userIdentity", {})
    identity_key = user_ident.get("userName") or user_ident.get("principalId") or raw.get("userId") or "unknown"
    if ":" in identity_key and not identity_key.startswith("arn:"):
        identity_key = identity_key.split(":")[-1]

    req_params = raw.get("requestParameters") or {}
    resource = (
        req_params.get("policyArn") or 
        req_params.get("bucketName") or 
        raw.get("eventSource") or 
        "aws_resource"
    )
    action = raw.get("eventName") or raw.get("action") or "unknown_action"
    error_code = raw.get("errorCode")
    outcome = "FAILURE" if error_code else "SUCCESS"

    session_ctx = user_ident.get("sessionContext", {})
    session_issuer = session_ctx.get("sessionIssuer", {})
    role_arn = session_issuer.get("arn", "")

    reasons = []
    structural_ok = True
    if not ts_valid:
        structural_ok = False
        reasons.append("Malformed or missing eventTime")
    if identity_key == "unknown":
        structural_ok = False
        reasons.append("Missing userIdentity")

    status = "VALID" if structural_ok else "INVALID"

    is_admin = "Administrator" in role_arn or "admin" in identity_key.lower()
    clearance = 4 if is_admin else (2 if "Developer" in role_arn else 1)

    norm = NormalizedEvent(
        event_id=event_id,
        source="cloudtrail",
        source_file=source_file,
        record_ref=f"{source_file}:{line_no}",
        ts_utc=ts_utc,
        ts_original_tz=ts_orig,
        identity_key=identity_key,
        principal_raw=user_ident.get("arn") or identity_key,
        session_id=req_params.get("roleSessionName") or user_ident.get("sessionContext", {}).get("sessionIssuer", {}).get("userName"),
        ip=raw.get("sourceIPAddress") or raw.get("ip") or "0.0.0.0",
        geo={},
        user_agent=raw.get("userAgent") or "aws-cli",
        action=action,
        resource=resource,
        outcome=outcome,
        privilege_context={"role": role_arn or "IAMUser", "clearance": clearance, "admin": is_admin},
        raw_hash=raw_hash,
        validation=ValidationDetails(status=status, reasons=reasons)
    )

    val_res = ValidationResult(
        record_ref=f"{source_file}:{line_no}",
        structural_ok=structural_ok,
        timestamp_ok=ts_valid,
        order_ok=True,
        identity_ref_ok=(identity_key != "unknown"),
        reasons=reasons
    )
    return norm, val_res

def ingest_file(file_path: str, db=None) -> Dict[str, Any]:
    if db is None:
        db = get_db()
    
    path = validate_file_path(file_path)
    filename = path.name.lower()
    is_okta = "okta" in filename
    is_cloudtrail = "cloudtrail" in filename

    col_events: Collection = db[COLLECTIONS["normalized_events"]]
    col_val: Collection = db[COLLECTIONS["validation_results"]]

    total_read = 0
    new_inserted = 0
    duplicates = 0
    invalid_count = 0

    bulk_ops = []
    val_records = []

    last_ts = None
    order_failures = 0

    with open(path, "r", encoding="utf-8") as f:
        for idx, line in enumerate(f, start=1):
            if len(line) > MAX_LINE_LENGTH_BYTES:
                raise ValueError(f"Line {idx} in {path.name} exceeds max length {MAX_LINE_LENGTH_BYTES} bytes.")

            line_str = line.strip()
            if not line_str:
                continue
            total_read += 1
            raw_hash = compute_raw_hash(line_str)
            try:
                raw_json = json.loads(line_str)
            except Exception as e:
                val_res = ValidationResult(
                    record_ref=f"{path.name}:{idx}",
                    structural_ok=False,
                    timestamp_ok=False,
                    order_ok=False,
                    identity_ref_ok=False,
                    reasons=[f"Malformed JSON: {str(e)}"]
                )
                col_val.insert_one(val_res.model_dump())
                invalid_count += 1
                continue

            if is_okta:
                norm_evt, val_res = parse_okta_record(raw_json, path.name, idx, raw_hash)
            elif is_cloudtrail:
                norm_evt, val_res = parse_cloudtrail_record(raw_json, path.name, idx, raw_hash)
            else:
                norm_evt, val_res = parse_okta_record(raw_json, path.name, idx, raw_hash)

            # Check timestamp ordering
            if last_ts and norm_evt.ts_utc < last_ts:
                val_res.order_ok = False
                val_res.reasons.append("Out of order timestamp relative to preceding log line")
                order_failures += 1
            last_ts = norm_evt.ts_utc

            val_records.append(val_res.model_dump())
            if not val_res.structural_ok or not val_res.timestamp_ok:
                invalid_count += 1

            doc = norm_evt.model_dump()
            bulk_ops.append(
                UpdateOne(
                    {"source": doc["source"], "event_id": doc["event_id"]},
                    {"$setOnInsert": doc},
                    upsert=True
                )
            )

    if val_records:
        col_val.insert_many(val_records, ordered=False)

    if bulk_ops:
        try:
            bulk_res = col_events.bulk_write(bulk_ops, ordered=False)
            new_inserted = bulk_res.upserted_count
            duplicates = bulk_res.matched_count
        except BulkWriteError as bwe:
            new_inserted = bwe.details.get("nUpserted", 0)
            duplicates = bwe.details.get("nMatched", 0)

    return {
        "source_file": path.name,
        "total_read": total_read,
        "new_inserted": new_inserted,
        "duplicates": duplicates,
        "invalid_quarantined": invalid_count,
        "order_anomalies": order_failures
    }

def run_ingest_all(sources: Optional[List[str]] = None, db=None) -> Dict[str, Any]:
    if db is None:
        db = get_db()
    default_sources = ["fixtures/okta_sample.jsonl", "fixtures/cloudtrail_sample.jsonl"]
    target_sources = sources or default_sources

    summary = []
    total_valid = 0
    total_invalid = 0

    for s in target_sources:
        rep = ingest_file(s, db)
        summary.append(rep)
        total_valid += rep["new_inserted"] + rep["duplicates"]
        total_invalid += rep["invalid_quarantined"]

    # In M1 acceptance report: separate "failed validation" from "suspicious"
    col_events = db[COLLECTIONS["normalized_events"]]
    suspicious_count = col_events.count_documents({
        "$or": [
            {"action": {"$regex": "Attach|AssumeRole|Put"}},
            {"resource": {"$regex": "pii-vault|production_export"}}
        ]
    })

    report = {
        "status": "M1_INGEST_COMPLETE",
        "sources_processed": len(summary),
        "files": summary,
        "failed_validation_quarantined": total_invalid,
        "suspicious_security_candidates": suspicious_count,
        "total_normalized_stored": total_valid
    }
    return report

if __name__ == "__main__":
    import sys
    sources = sys.argv[1:] if len(sys.argv) > 1 else None
    res = run_ingest_all(sources)
    print(json.dumps(res, indent=2))
