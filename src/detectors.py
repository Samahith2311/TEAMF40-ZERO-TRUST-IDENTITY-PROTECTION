import math
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

def parse_iso(ts_str: str) -> datetime:
    clean_ts = str(ts_str).strip()
    if clean_ts.endswith("Z"):
        clean_ts = clean_ts[:-1] + "+00:00"
    return datetime.fromisoformat(clean_ts)

def haversine_distance_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Earth radius in kilometers; computes great-circle distance."""
    r = 6371.0
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    delta_phi = math.radians(lat2 - lat1)
    delta_lambda = math.radians(lon2 - lon1)

    a = math.sin(delta_phi / 2.0) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda / 2.0) ** 2
    c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
    return r * c

def is_same_subnet_24(ip1: str, ip2: str) -> bool:
    """Checks if two IPv4 addresses share the same /24 subnet (benign roaming)."""
    p1 = str(ip1).split(".")
    p2 = str(ip2).split(".")
    if len(p1) == 4 and len(p2) == 4:
        return p1[:3] == p2[:3]
    return False

# ==============================================================================
# DET-01: Dormant-Account Reactivation
# ==============================================================================
AUTH_ACTIONS = {
    "user.session.start",
    "user.authentication.verify",
    "policy.evaluate_sign_on",
    "AssumeRole",
    "GetSessionToken",
    "CreateLoginProfile",
    "ConsoleLogin"
}

def detect_dormant_reactivation(
    event: Dict[str, Any],
    identity_meta: Dict[str, Any],
    threshold_days_override: Optional[float] = None
) -> Dict[str, Any]:
    eid = event.get("event_id", "")
    last_active = identity_meta.get("last_active_ts")
    p95_gap = identity_meta.get("p95_gap_days", 30.0)
    threshold_days = threshold_days_override if threshold_days_override is not None else max(30.0, float(p95_gap))

    action = event.get("action", "")
    source = event.get("source", "")
    # Authenticaton actions: Okta session start, Okta login, or AWS ConsoleLogin
    is_auth_action = (action in AUTH_ACTIONS) or ("session.start" in action.lower()) or ("login" in action.lower())
    if source == "cloudtrail" and action not in ["ConsoleLogin"]:
        is_auth_action = False

    if not is_auth_action:
        return {
            "rule_id": "DET-01",
            "name": "Dormant Account Reactivation",
            "detected": False,
            "status": "NOT_DETECTED",
            "attack_type": "DORMANT_REACTIVATION",
            "confidence": 0.0,
            "event_id": eid,
            "rationale": f"Action '{action}' is not an authentication/session initialization event."
        }

    if not last_active:
        return {
            "rule_id": "DET-01",
            "name": "Dormant Account Reactivation",
            "detected": False,
            "status": "INCONCLUSIVE",
            "attack_type": "DORMANT_REACTIVATION",
            "confidence": 0.0,
            "event_id": eid,
            "rationale": "Missing historical last_active_ts metadata for identity."
        }

    try:
        dt_event = parse_iso(event["ts_utc"])
        dt_last = parse_iso(last_active)
        gap_days = (dt_event - dt_last).total_seconds() / 86400.0
    except Exception as e:
        return {
            "rule_id": "DET-01",
            "name": "Dormant Account Reactivation",
            "detected": False,
            "status": "INCONCLUSIVE",
            "attack_type": "DORMANT_REACTIVATION",
            "confidence": 0.0,
            "event_id": eid,
            "rationale": f"Timestamp parsing failure: {e}"
        }

    if gap_days > threshold_days:
        return {
            "rule_id": "DET-01",
            "name": "Dormant Account Reactivation",
            "detected": True,
            "status": "DETECTED",
            "attack_type": "DORMANT_REACTIVATION",
            "severity": "HIGH",
            "confidence": 0.95,
            "event_id": eid,
            "evidence": f"Inactivity gap of {gap_days:.1f} days exceeded baseline threshold of {threshold_days:.1f} days (last active: {last_active}).",
            "evidence_refs": [{"source_file": event.get("source_file", ""), "record_id": str(event.get("record_ref", ""))}],
            "rationale": f"Account reactivated after dormant gap of {gap_days:.1f} days."
        }

    return {
        "rule_id": "DET-01",
        "name": "Dormant Account Reactivation",
        "detected": False,
        "status": "NOT_DETECTED",
        "attack_type": "DORMANT_REACTIVATION",
        "confidence": 0.0,
        "event_id": eid,
        "rationale": f"Inactivity gap {gap_days:.1f} days within normal threshold {threshold_days:.1f} days."
    }

# ==============================================================================
# DET-02: Token & Session Abuse
# ==============================================================================
def detect_token_abuse(
    event: Dict[str, Any],
    previous_event: Optional[Dict[str, Any]],
    session_history: Optional[List[Dict[str, Any]]] = None
) -> Dict[str, Any]:
    eid = event.get("event_id", "")
    if not previous_event:
        return {
            "rule_id": "DET-02",
            "name": "Token & Session Abuse",
            "detected": False,
            "status": "NOT_DETECTED",
            "attack_type": "TOKEN_ABUSE",
            "confidence": 0.0,
            "event_id": eid,
            "rationale": "No previous session observation to compare."
        }

    action = event.get("action", "")
    # DET-02 evaluates session/token reuse across API calls using an established session token.
    # Initial authentication/login events (e.g. user.session.start) are evaluated under auth/geo rules.
    if action in ["user.session.start", "login", "authenticate"] or "session.start" in action.lower():
        return {
            "rule_id": "DET-02",
            "name": "Token & Session Abuse",
            "detected": False,
            "status": "NOT_DETECTED",
            "attack_type": "TOKEN_ABUSE",
            "confidence": 0.0,
            "event_id": eid,
            "rationale": f"Action '{action}' is a primary authentication event, not in-session token reuse."
        }

    curr_ip = event.get("ip", "0.0.0.0")
    prev_ip = previous_event.get("ip", "0.0.0.0")
    curr_ua = event.get("user_agent", "")
    prev_ua = previous_event.get("user_agent", "")
    action = event.get("action", "")

    # Calculate time separation
    try:
        dt1 = parse_iso(previous_event["ts_utc"])
        dt2 = parse_iso(event["ts_utc"])
        diff_min = abs((dt2 - dt1).total_seconds()) / 60.0
    except Exception:
        diff_min = 999.0

    # Case 1: Session continuity abuse (AssumeRole with Go/CLI SDK following browser login)
    if action == "AssumeRole" and ("aws-sdk" in curr_ua or "aws-cli" in curr_ua) and "Mozilla" in prev_ua and diff_min <= 15.0:
        return {
            "rule_id": "DET-02",
            "name": "Token & Session Abuse",
            "detected": True,
            "status": "DETECTED",
            "attack_type": "TOKEN_ABUSE",
            "severity": "HIGH",
            "confidence": 0.92,
            "event_id": eid,
            "evidence": f"Session token transition from interactive browser ({prev_ua[:25]}..) to programmatic SDK ({curr_ua}) on AssumeRole in {diff_min:.1f}m.",
            "evidence_refs": [
                {"source_file": previous_event.get("source_file", ""), "record_id": str(previous_event.get("record_ref", ""))},
                {"source_file": event.get("source_file", ""), "record_id": str(event.get("record_ref", ""))}
            ],
            "rationale": "Automated SDK assume role right after interactive SSO login indicates token hijacking."
        }

    # Case 2: IP shift on AssumeRole within active session window (<= 15 mins)
    if action == "AssumeRole" and curr_ip != prev_ip and diff_min <= 15.0:
        return {
            "rule_id": "DET-02",
            "name": "Token & Session Abuse",
            "detected": True,
            "status": "DETECTED",
            "attack_type": "TOKEN_ABUSE",
            "severity": "HIGH",
            "confidence": 0.90,
            "event_id": eid,
            "evidence": f"AssumeRole token invoked from IP {curr_ip} within {diff_min:.1f}m of active session at IP {prev_ip}.",
            "evidence_refs": [
                {"source_file": previous_event.get("source_file", ""), "record_id": str(previous_event.get("record_ref", ""))},
                {"source_file": event.get("source_file", ""), "record_id": str(event.get("record_ref", ""))}
            ],
            "rationale": "Cross-network token assumption indicates session token exfiltration."
        }

    # Benign roaming check: IP changed within same /24 subnet with matching User-Agent
    if curr_ip != prev_ip and is_same_subnet_24(curr_ip, prev_ip) and curr_ip != "0.0.0.0":
        return {
            "rule_id": "DET-02",
            "name": "Token & Session Abuse",
            "detected": False,
            "status": "NOT_DETECTED",
            "attack_type": "TOKEN_ABUSE",
            "confidence": 0.0,
            "event_id": eid,
            "rationale": f"Benign IP roaming within same /24 subnet ({curr_ip} vs {prev_ip})."
        }

    # Case 3: In-session IP change during active CloudTrail session
    if curr_ip != prev_ip and curr_ip != "0.0.0.0" and prev_ip != "0.0.0.0" and diff_min <= 15.0:
        return {
            "rule_id": "DET-02",
            "name": "Token & Session Abuse",
            "detected": True,
            "status": "DETECTED",
            "attack_type": "TOKEN_ABUSE",
            "severity": "HIGH",
            "confidence": 0.88,
            "event_id": eid,
            "evidence": f"Active session accessed from different IP {curr_ip} within {diff_min:.1f}m of {prev_ip}.",
            "evidence_refs": [
                {"source_file": previous_event.get("source_file", ""), "record_id": str(previous_event.get("record_ref", ""))},
                {"source_file": event.get("source_file", ""), "record_id": str(event.get("record_ref", ""))}
            ],
            "rationale": "Abrupt IP change on active session."
        }

    return {
        "rule_id": "DET-02",
        "name": "Token & Session Abuse",
        "detected": False,
        "status": "NOT_DETECTED",
        "attack_type": "TOKEN_ABUSE",
        "confidence": 0.0,
        "event_id": eid,
        "rationale": "Session continuity signals consistent with normal usage."
    }

# ==============================================================================
# DET-03: Privilege Escalation
# ==============================================================================
IAM_ESCALATION_ACTIONS = {
    "AttachUserPolicy",
    "AttachRolePolicy",
    "AttachGroupPolicy",
    "PutUserPolicy",
    "PutRolePolicy",
    "PutGroupPolicy",
    "CreateAccessKey",
    "UpdateAssumeRolePolicy",
    "CreateLoginProfile",
    "UpdateLoginProfile",
    "AddUserToGroup"
}

CRITICAL_POLICIES = {
    "AdministratorAccess",
    "PowerUserAccess",
    "IAMFullAccess",
    "SecurityAudit"
}

def detect_privilege_escalation(
    event: Dict[str, Any],
    identity_meta: Dict[str, Any]
) -> Dict[str, Any]:
    eid = event.get("event_id", "")
    action = event.get("action", "")
    resource = event.get("resource", "")
    clearance = identity_meta.get("clearance_level", 1)
    is_admin = identity_meta.get("is_admin", False) or clearance >= 4

    matched_action = next((act for act in IAM_ESCALATION_ACTIONS if act in action), None)
    if not matched_action:
        return {
            "rule_id": "DET-03",
            "name": "Privilege Escalation Chain",
            "detected": False,
            "status": "NOT_DETECTED",
            "attack_type": "PRIVILEGE_ESCALATION",
            "confidence": 0.0,
            "event_id": eid,
            "rationale": f"Action '{action}' is not in IAM escalation taxonomy."
        }

    has_critical_policy = any(p in resource for p in CRITICAL_POLICIES) or "*:*" in resource or "admin" in resource.lower()

    # If low/medium privilege identity executes escalation action or attaches admin policy
    if has_critical_policy or clearance <= 2:
        return {
            "rule_id": "DET-03",
            "name": "Privilege Escalation Chain",
            "detected": True,
            "status": "DETECTED",
            "attack_type": "PRIVILEGE_ESCALATION",
            "severity": "CRITICAL",
            "confidence": 0.98,
            "event_id": eid,
            "evidence": f"Principal with clearance tier {clearance} executed '{matched_action}' targeting '{resource}'.",
            "evidence_refs": [{"source_file": event.get("source_file", ""), "record_id": str(event.get("record_ref", ""))}],
            "rationale": f"Unauthorized privilege escalation: {matched_action} grant to {resource} exceeds clearance."
        }

    return {
        "rule_id": "DET-03",
        "name": "Privilege Escalation Chain",
        "detected": False,
        "status": "NOT_DETECTED",
        "attack_type": "PRIVILEGE_ESCALATION",
        "confidence": 0.0,
        "event_id": eid,
        "rationale": f"Authorized admin change by clearance tier {clearance} principal."
    }

# ==============================================================================
# DET-04: Unusual API Calls
# ==============================================================================
SENSITIVE_RESOURCE_CATALOG = [
    "pii-vault",
    "production_export",
    "customer-pii",
    "credentials",
    "secret",
    "audit-vault",
    "financial-records"
]

SUSPICIOUS_USER_AGENTS = [
    "python-requests",
    "curl",
    "wget",
    "postman",
    "bot",
    "scanner"
]

def detect_unusual_api_calls(
    event: Dict[str, Any],
    sensitive_catalog: Optional[List[str]] = None
) -> Dict[str, Any]:
    eid = event.get("event_id", "")
    resource = event.get("resource", "").lower()
    user_agent = event.get("user_agent", "").lower()
    catalog = sensitive_catalog or SENSITIVE_RESOURCE_CATALOG

    matched_sensitive = next((item for item in catalog if item in resource), None)
    matched_ua = next((ua for ua in SUSPICIOUS_USER_AGENTS if ua in user_agent), None)
    action = event.get("action", "")
    is_data_action = action in ["GetObject", "ListObjects", "PutObject", "BatchGet", "Export", "Query", "Scan"] or "get" in action.lower() or "read" in action.lower()

    if matched_sensitive or (matched_ua and is_data_action):
        reasons = []
        if matched_sensitive:
            reasons.append(f"sensitive resource classification '{matched_sensitive}'")
        if matched_ua:
            reasons.append(f"non-standard programmatic user-agent '{matched_ua}'")

        return {
            "rule_id": "DET-04",
            "name": "Unusual API Calls",
            "detected": True,
            "status": "DETECTED",
            "attack_type": "UNUSUAL_API_CALLS",
            "severity": "HIGH",
            "confidence": 0.90,
            "event_id": eid,
            "evidence": f"Unusual API access flagged for {', '.join(reasons)} (Resource: {event.get('resource')}, UA: {event.get('user_agent')}).",
            "evidence_refs": [{"source_file": event.get("source_file", ""), "record_id": str(event.get("record_ref", ""))}],
            "rationale": f"Anomalous API request targeting high-impact data store via {user_agent}."
        }

    return {
        "rule_id": "DET-04",
        "name": "Unusual API Calls",
        "detected": False,
        "status": "NOT_DETECTED",
        "attack_type": "UNUSUAL_API_CALLS",
        "confidence": 0.0,
        "event_id": eid,
        "rationale": "Standard API request matching baseline profile."
    }

# ==============================================================================
# DET-05: Impossible Travel
# ==============================================================================
def detect_impossible_travel(
    event1: Optional[Dict[str, Any]],
    event2: Dict[str, Any],
    max_speed_kmh: float = 800.0,
    min_distance_km: float = 500.0
) -> Dict[str, Any]:
    eid = event2.get("event_id", "")
    if not event1:
        return {
            "rule_id": "DET-05",
            "name": "Impossible Travel",
            "detected": False,
            "status": "INCONCLUSIVE",
            "attack_type": "IMPOSSIBLE_TRAVEL",
            "confidence": 0.0,
            "event_id": eid,
            "rationale": "No prior geo observation available to compare."
        }

    geo1 = event1.get("geo") or {}
    geo2 = event2.get("geo") or {}

    lat1 = geo1.get("lat") if geo1.get("lat") is not None else geo1.get("latitude")
    lon1 = geo1.get("lon") if geo1.get("lon") is not None else geo1.get("longitude")
    lat2 = geo2.get("lat") if geo2.get("lat") is not None else geo2.get("latitude")
    lon2 = geo2.get("lon") if geo2.get("lon") is not None else geo2.get("longitude")

    # Critical invariant: 0.0 latitude / longitude is strictly valid!
    if lat1 is None or lon1 is None or lat2 is None or lon2 is None:
        return {
            "rule_id": "DET-05",
            "name": "Impossible Travel",
            "detected": False,
            "status": "INCONCLUSIVE",
            "attack_type": "IMPOSSIBLE_TRAVEL",
            "confidence": 0.0,
            "event_id": eid,
            "rationale": "Missing valid geographical coordinates on one or both login events."
        }

    try:
        dt1 = parse_iso(event1["ts_utc"])
        dt2 = parse_iso(event2["ts_utc"])
        time_diff_hours = (dt2 - dt1).total_seconds() / 3600.0
    except Exception as e:
        return {
            "rule_id": "DET-05",
            "name": "Impossible Travel",
            "detected": False,
            "status": "INCONCLUSIVE",
            "attack_type": "IMPOSSIBLE_TRAVEL",
            "confidence": 0.0,
            "event_id": eid,
            "rationale": f"Timestamp calculation failure: {e}"
        }

    if time_diff_hours <= 0.0:
        return {
            "rule_id": "DET-05",
            "name": "Impossible Travel",
            "detected": False,
            "status": "NOT_DETECTED",
            "attack_type": "IMPOSSIBLE_TRAVEL",
            "confidence": 0.0,
            "event_id": eid,
            "rationale": "Non-positive elapsed time between events."
        }

    if time_diff_hours <= 6.0:
        dist_km = haversine_distance_km(float(lat1), float(lon1), float(lat2), float(lon2))
        speed = dist_km / time_diff_hours
        city1 = geo1.get("city", f"{lat1},{lon1}")
        city2 = geo2.get("city", f"{lat2},{lon2}")

        if speed > max_speed_kmh and dist_km > min_distance_km:
            return {
                "rule_id": "DET-05",
                "name": "Impossible Travel",
                "detected": True,
                "status": "DETECTED",
                "attack_type": "IMPOSSIBLE_TRAVEL",
                "severity": "HIGH",
                "confidence": 0.96,
                "event_id": eid,
                "evidence": f"Physical travel from {city1} to {city2} ({dist_km:.0f} km) in {time_diff_hours:.2f}h requires speed of {speed:.0f} km/h (threshold: {max_speed_kmh:.0f} km/h).",
                "evidence_refs": [
                    {"source_file": event1.get("source_file", ""), "record_id": str(event1.get("record_ref", ""))},
                    {"source_file": event2.get("source_file", ""), "record_id": str(event2.get("record_ref", ""))}
                ],
                "rationale": f"Impossible transit speed {speed:.0f} km/h indicates concurrent multi-location credential usage."
            }

    return {
        "rule_id": "DET-05",
        "name": "Impossible Travel",
        "detected": False,
        "status": "NOT_DETECTED",
        "attack_type": "IMPOSSIBLE_TRAVEL",
        "confidence": 0.0,
        "event_id": eid,
        "rationale": "Travel speed within plausible physical boundaries."
    }

# ==============================================================================
# DET-06: Certificate-Binding Violation (Risk-Adaptive mTLS Extension)
# ==============================================================================
def detect_cert_binding_violation(
    event: Dict[str, Any],
    expected_fingerprint: Optional[str] = None,
    approved_rotations: Optional[Set[str]] = None
) -> Dict[str, Any]:
    eid = event.get("event_id", "")
    observed_fp = event.get("cert_fingerprint")

    if not expected_fingerprint:
        return {
            "rule_id": "DET-06",
            "name": "Certificate Binding Violation",
            "detected": False,
            "status": "NOT_DETECTED",
            "attack_type": "CERTIFICATE_BINDING_VIOLATION",
            "confidence": 0.0,
            "event_id": eid,
            "rationale": "Session is not bound to a certificate policy requirement."
        }

    if not observed_fp:
        return {
            "rule_id": "DET-06",
            "name": "Certificate Binding Violation",
            "detected": True,
            "status": "DETECTED",
            "attack_type": "CERTIFICATE_BINDING_VIOLATION",
            "severity": "CRITICAL",
            "confidence": 0.99,
            "event_id": eid,
            "evidence": "Access attempt on certificate-bound session without presenting a client certificate.",
            "evidence_refs": [{"source_file": event.get("source_file", ""), "record_id": str(event.get("record_ref", ""))}],
            "rationale": "Missing required certificate binding indicates token replay outside authorized mTLS perimeter."
        }

    if observed_fp.lower() != expected_fingerprint.lower():
        # Check if benign approved rotation
        if approved_rotations and observed_fp.lower() in {r.lower() for r in approved_rotations}:
            return {
                "rule_id": "DET-06",
                "name": "Certificate Binding Violation",
                "detected": False,
                "status": "NOT_DETECTED",
                "attack_type": "CERTIFICATE_BINDING_VIOLATION",
                "confidence": 0.0,
                "event_id": eid,
                "rationale": f"Certificate change matches approved rotation entry ({observed_fp[:12]}..)."
            }

        return {
            "rule_id": "DET-06",
            "name": "Certificate Binding Violation",
            "detected": True,
            "status": "DETECTED",
            "attack_type": "CERTIFICATE_BINDING_VIOLATION",
            "severity": "CRITICAL",
            "confidence": 0.99,
            "event_id": eid,
            "evidence": f"Certificate fingerprint mismatch: session bound to {expected_fingerprint[:16]}.., but accessed using {observed_fp[:16]}..",
            "evidence_refs": [{"source_file": event.get("source_file", ""), "record_id": str(event.get("record_ref", ""))}],
            "rationale": "Session token replayed from host with unverified / mismatched client certificate."
        }

    return {
        "rule_id": "DET-06",
        "name": "Certificate Binding Violation",
        "detected": False,
        "status": "NOT_DETECTED",
        "attack_type": "CERTIFICATE_BINDING_VIOLATION",
        "confidence": 0.0,
        "event_id": eid,
        "rationale": "Observed certificate fingerprint matches bound session certificate."
    }
