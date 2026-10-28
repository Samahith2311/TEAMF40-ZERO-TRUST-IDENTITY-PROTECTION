import math
from datetime import datetime, timezone
from typing import List, Dict, Any

def parse_iso(ts_str: str) -> datetime:
    return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))

def haversine_distance_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    # Earth radius in kilometers
    r = 6371.0
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    delta_phi = math.radians(lat2 - lat1)
    delta_lambda = math.radians(lon2 - lon1)

    a = math.sin(delta_phi / 2.0) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda / 2.0) ** 2
    c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
    return r * c

def detect_dormant_reactivation(event: Dict[str, Any], identity_meta: Dict[str, Any]) -> Dict[str, Any]:
    # Rule DET-01
    last_active = identity_meta.get("last_active_ts")
    p95_gap = identity_meta.get("p95_gap_days", 30.0)
    threshold_days = max(30.0, float(p95_gap))

    if last_active and event.get("action") in ["user.session.start", "AssumeRole"]:
        dt_event = parse_iso(event["ts_utc"])
        dt_last = parse_iso(last_active)
        gap_days = (dt_event - dt_last).total_seconds() / 86400.0
        if gap_days > threshold_days:
            return {
                "detected": True,
                "rule_id": "DET-01",
                "name": "Dormant Account Reactivation",
                "severity": "HIGH",
                "evidence": f"Inactivity gap of {gap_days:.1f} days exceeded threshold {threshold_days:.1f} days",
                "event_id": event["event_id"]
            }
    return {"detected": False}

def detect_impossible_travel(event1: Dict[str, Any], event2: Dict[str, Any]) -> Dict[str, Any]:
    # Rule DET-05
    geo1 = event1.get("geo") or {}
    geo2 = event2.get("geo") or {}
    if not (geo1.get("lat") and geo2.get("lat")):
        return {"detected": False}

    dt1 = parse_iso(event1["ts_utc"])
    dt2 = parse_iso(event2["ts_utc"])
    time_diff_hours = abs((dt2 - dt1).total_seconds()) / 3600.0

    if 0.0 < time_diff_hours <= 4.0:
        dist_km = haversine_distance_km(geo1["lat"], geo1["lon"], geo2["lat"], geo2["lon"])
        speed = dist_km / time_diff_hours
        if speed > 800.0:
            return {
                "detected": True,
                "rule_id": "DET-05",
                "name": "Impossible Travel",
                "severity": "HIGH",
                "evidence": f"Traveled {dist_km:.0f} km in {time_diff_hours:.2f} hours (speed: {speed:.0f} km/h > 800 km/h)",
                "event_id": event2["event_id"]
            }
    return {"detected": False}

def detect_privilege_escalation(event: Dict[str, Any], identity_meta: Dict[str, Any]) -> Dict[str, Any]:
    # Rule DET-03
    action = event.get("action", "")
    resource = event.get("resource", "")
    clearance = identity_meta.get("clearance_level", 1)

    if any(act in action for act in ["AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy"]):
        if "AdministratorAccess" in resource or clearance <= 2:
            return {
                "detected": True,
                "rule_id": "DET-03",
                "name": "Privilege Escalation Chain",
                "severity": "CRITICAL",
                "evidence": f"Principal with clearance {clearance} attached policy {resource}",
                "event_id": event["event_id"]
            }
    return {"detected": False}

def detect_token_abuse(event: Dict[str, Any], previous_event: Dict[str, Any]) -> Dict[str, Any]:
    # Rule DET-02
    if event.get("action") == "AssumeRole" and previous_event:
        if event.get("ip") != previous_event.get("ip"):
            dt1 = parse_iso(previous_event["ts_utc"])
            dt2 = parse_iso(event["ts_utc"])
            diff_min = abs((dt2 - dt1).total_seconds()) / 60.0
            if diff_min <= 15.0:
                return {
                    "detected": True,
                    "rule_id": "DET-02",
                    "name": "Token & Session Abuse",
                    "severity": "HIGH",
                    "evidence": f"AssumeRole issued from IP {event.get('ip')} within {diff_min:.1f}m of session at IP {previous_event.get('ip')}",
                    "event_id": event["event_id"]
                }
    return {"detected": False}

def detect_unusual_api_calls(event: Dict[str, Any]) -> Dict[str, Any]:
    # Rule DET-04
    resource = event.get("resource", "")
    user_agent = event.get("user_agent", "")
    if "pii-vault" in resource or "production_export" in resource or "python-requests" in user_agent:
        return {
            "detected": True,
            "rule_id": "DET-04",
            "name": "Unusual API Calls",
            "severity": "HIGH",
            "evidence": f"Access to sensitive resource '{resource}' via non-standard user-agent '{user_agent}'",
            "event_id": event["event_id"]
        }
    return {"detected": False}
