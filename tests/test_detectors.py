import pytest
from src.detectors import (
    detect_dormant_reactivation,
    detect_token_abuse,
    detect_privilege_escalation,
    detect_unusual_api_calls,
    detect_impossible_travel
)

def test_dormant_reactivation_positive_benign_edge():
    meta = {
        "last_active_ts": "2026-08-01T00:00:00Z",
        "p95_gap_days": 15.0
    }
    # Positive case: 88 days gap > 30 days
    event_pos = {
        "event_id": "d-pos",
        "ts_utc": "2026-10-28T00:00:00Z",
        "action": "user.session.start"
    }
    res_pos = detect_dormant_reactivation(event_pos, meta)
    assert res_pos["detected"] is True
    assert res_pos["rule_id"] == "DET-01"

    # Benign case: 2 days gap
    meta_recent = {
        "last_active_ts": "2026-10-26T00:00:00Z",
        "p95_gap_days": 10.0
    }
    res_benign = detect_dormant_reactivation(event_pos, meta_recent)
    assert res_benign["detected"] is False

    # Edge case: exactly at boundary
    meta_edge = {
        "last_active_ts": "2026-09-28T00:00:00Z",
        "p95_gap_days": 30.0
    }
    # 30 days gap -> not greater than threshold
    res_edge = detect_dormant_reactivation(event_pos, meta_edge)
    assert res_edge["detected"] is False

def test_token_abuse_positive_benign_edge():
    evt_prev = {
        "event_id": "prev-1",
        "ts_utc": "2026-10-28T10:00:00Z",
        "ip": "198.51.100.1"
    }
    # Positive: IP mismatch within 10 min
    evt_pos = {
        "event_id": "curr-1",
        "ts_utc": "2026-10-28T10:10:00Z",
        "ip": "203.0.113.99",
        "action": "AssumeRole"
    }
    res_pos = detect_token_abuse(evt_pos, evt_prev)
    assert res_pos["detected"] is True
    assert res_pos["rule_id"] == "DET-02"

    # Benign: same IP
    evt_same_ip = {
        "event_id": "curr-2",
        "ts_utc": "2026-10-28T10:05:00Z",
        "ip": "198.51.100.1",
        "action": "AssumeRole"
    }
    res_same = detect_token_abuse(evt_same_ip, evt_prev)
    assert res_same["detected"] is False

    # Edge: elapsed > 15m (e.g. 20m)
    evt_edge = {
        "event_id": "curr-3",
        "ts_utc": "2026-10-28T10:25:00Z",
        "ip": "203.0.113.99",
        "action": "AssumeRole"
    }
    res_edge = detect_token_abuse(evt_edge, evt_prev)
    assert res_edge["detected"] is False

def test_privilege_escalation_positive_benign_edge():
    meta_low = {"clearance_level": 1}
    # Positive: clearance 1 attaching AdministratorAccess
    evt_pos = {
        "event_id": "pe-pos",
        "action": "AttachUserPolicy",
        "resource": "arn:aws:iam::aws:policy/AdministratorAccess"
    }
    res_pos = detect_privilege_escalation(evt_pos, meta_low)
    assert res_pos["detected"] is True
    assert res_pos["rule_id"] == "DET-03"

    # Benign: ReadOnly access
    evt_read = {
        "event_id": "pe-read",
        "action": "GetRole",
        "resource": "DeveloperRole"
    }
    res_read = detect_privilege_escalation(evt_read, meta_low)
    assert res_read["detected"] is False

def test_unusual_api_calls_positive_benign_edge():
    # Positive: automated tool accessing customer vault
    evt_pos = {
        "event_id": "api-pos",
        "resource": "corp-customer-pii-vault",
        "user_agent": "python-requests/2.28.1"
    }
    res_pos = detect_unusual_api_calls(evt_pos)
    assert res_pos["detected"] is True
    assert res_pos["rule_id"] == "DET-04"

    # Benign: normal dev build artifact
    evt_benign = {
        "event_id": "api-benign",
        "resource": "corp-dev-builds",
        "user_agent": "aws-cli/2.11.0"
    }
    assert detect_unusual_api_calls(evt_benign)["detected"] is False

def test_impossible_travel_positive_benign_edge():
    # London
    evt1 = {
        "event_id": "geo-1",
        "ts_utc": "2026-10-28T10:00:00Z",
        "geo": {"lat": 51.5074, "lon": -0.1278}
    }
    # Tokyo 1 hour later (~9,500 km -> 9500 km/h)
    evt2_pos = {
        "event_id": "geo-2",
        "ts_utc": "2026-10-28T11:00:00Z",
        "geo": {"lat": 35.6762, "lon": 139.6503}
    }
    res_pos = detect_impossible_travel(evt1, evt2_pos)
    assert res_pos["detected"] is True
    assert res_pos["rule_id"] == "DET-05"

    # Benign: London to Cambridge (80 km in 2 hours -> 40 km/h)
    evt2_benign = {
        "event_id": "geo-3",
        "ts_utc": "2026-10-28T12:00:00Z",
        "geo": {"lat": 52.2053, "lon": 0.1218}
    }
    assert detect_impossible_travel(evt1, evt2_benign)["detected"] is False
