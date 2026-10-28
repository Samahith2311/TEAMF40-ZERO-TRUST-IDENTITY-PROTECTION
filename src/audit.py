import hashlib
import json
from datetime import datetime, timezone
from typing import Dict, Any, List, Tuple
from src.models import AuditLog

GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"

def sanitize_log_string(val: str) -> str:
    """Neutralizes newline and control characters to prevent log injection."""
    if not isinstance(val, str):
        val = str(val)
    return val.replace("\r", " ").replace("\n", " ").strip()

def compute_entry_hash(prev_hash: str, ts_utc: str, actor: str, action: str, details_canonical_json: str) -> str:
    payload = f"{prev_hash}|{ts_utc}|{actor}|{action}|{details_canonical_json}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()

def create_audit_entry(actor: str, action: str, details: Dict[str, Any], prev_hash: str = GENESIS_HASH) -> AuditLog:
    clean_actor = sanitize_log_string(actor)
    clean_action = sanitize_log_string(action)
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    canonical_details = json.dumps(details, sort_keys=True)
    curr_hash = compute_entry_hash(prev_hash, now_utc, clean_actor, clean_action, canonical_details)
    log_id = f"aud-{curr_hash[:12]}"

    return AuditLog(
        log_id=log_id,
        prev_hash=prev_hash,
        curr_hash=curr_hash,
        ts_utc=now_utc,
        actor=clean_actor,
        action=clean_action,
        details=details
    )

def verify_audit_chain(logs: List[Dict[str, Any]]) -> Tuple[bool, int, str]:
    """
    Verifies hash chain integrity across all entries.
    Returns (is_valid, failing_index, reason).
    """
    if not logs:
        return True, -1, "Empty log"

    expected_prev = GENESIS_HASH
    for idx, log in enumerate(logs):
        if log.get("prev_hash") != expected_prev:
            return False, idx, f"Prev hash mismatch at index {idx}: expected {expected_prev}, got {log.get('prev_hash')}"
        
        details_str = json.dumps(log.get("details", {}), sort_keys=True)
        recomputed = compute_entry_hash(
            log["prev_hash"],
            log["ts_utc"],
            log["actor"],
            log["action"],
            details_str
        )
        if recomputed != log.get("curr_hash"):
            return False, idx, f"Entry hash mismatch at index {idx}: calculated {recomputed}, recorded {log.get('curr_hash')}"
        
        expected_prev = log["curr_hash"]

    return True, -1, "Chain valid"
