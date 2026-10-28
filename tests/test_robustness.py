import pytest
import json
import copy
from pathlib import Path

from src.ingest import parse_okta_record, parse_cloudtrail_record, compute_raw_hash
from src.detectors import (
    detect_dormant_reactivation,
    detect_token_abuse,
    detect_privilege_escalation,
    detect_unusual_api_calls,
    detect_impossible_travel
)
from src.scoring import compute_identity_factors, calculate_risk_score, FACTOR_WEIGHTS
from src.stitching import stitch_identity_events
from src.harness import evaluate_ordered_chains, load_all_fixtures, run_detectors_on_events

def test_label_invariance():
    """
    Integrity test 2A.3: Engine detection and scoring are 100% invariant to ground-truth labels.
    Stripping, altering, or omitting labels must produce identical detector findings.
    """
    raw_okta = {
        "event_id": "okta-test-01",
        "published": "2026-10-28T10:15:00Z",
        "eventType": "user.session.start",
        "actor": {"id": "usr_test", "alternateId": "test.user@corp.internal"},
        "client": {"ipAddress": "203.0.113.45", "geographicalContext": {"city": "London", "latitude": 51.5074, "longitude": -0.1278}},
        "outcome": {"result": "SUCCESS"},
        "target": [{"id": "app_aws"}],
        "label": "DORMANT_REACTIVATION" # Present in raw
    }

    raw_hash1 = compute_raw_hash(json.dumps(raw_okta))
    norm1, _, extracted_label1 = parse_okta_record(raw_okta, "okta_test.jsonl", 1, raw_hash1)

    # Clone and change label to BENIGN or completely remove
    raw_okta_stripped = copy.deepcopy(raw_okta)
    del raw_okta_stripped["label"]
    raw_hash2 = compute_raw_hash(json.dumps(raw_okta_stripped))
    norm2, _, extracted_label2 = parse_okta_record(raw_okta_stripped, "okta_test.jsonl", 1, raw_hash2)

    assert extracted_label1 == "DORMANT_REACTIVATION"
    assert extracted_label2 is None
    # Both normalized events must be strictly identical in signal path
    assert norm1.model_dump(exclude={"raw_hash"}) == norm2.model_dump(exclude={"raw_hash"})

    meta = {"last_active_ts": "2026-08-01T00:00:00Z", "p95_gap_days": 15.0}
    d1 = detect_dormant_reactivation(norm1.model_dump(), meta)
    d2 = detect_dormant_reactivation(norm2.model_dump(), meta)
    assert d1["detected"] == d2["detected"]
    assert d1["detected"] is True

def test_metamorphic_identity_renaming():
    """
    Integrity test 2A.3: Renaming identity string must not affect anomaly detection or risk calculation.
    Ensures zero username hardcoding.
    """
    events, identities, _ = load_all_fixtures()

    # Original detection on fixtures
    orig_preds = run_detectors_on_events(events, identities)
    orig_bob_preds = {k: v.get("okta-evt-002", False) for k, v in orig_preds.items()}

    # Metamorphic transform: rename bob to arbitrary surrogate identity
    surrogate_key = "surrogate_user_xyz_9988@domain.external"
    renamed_events = copy.deepcopy(events)
    for e in renamed_events:
        if e.get("identity_key") == "bob.contractor@corp.internal":
            e["identity_key"] = surrogate_key
            if "bob.contractor" in e.get("resource", ""):
                e["resource"] = e["resource"].replace("bob.contractor@corp.internal", surrogate_key)

    renamed_identities = copy.deepcopy(identities)
    if "bob.contractor@corp.internal" in renamed_identities:
        renamed_identities[surrogate_key] = renamed_identities.pop("bob.contractor@corp.internal")

    transformed_preds = run_detectors_on_events(renamed_events, renamed_identities)
    transformed_bob_preds = {k: v.get("okta-evt-002", False) for k, v in transformed_preds.items()}

    # Detection flags must be identical
    assert orig_bob_preds == transformed_bob_preds

    # Score calculation must be identical
    orig_bob_evts = [e for e in events if e.get("identity_key") == "bob.contractor@corp.internal"]
    orig_finds = [{"event_id": eid, "detected": True, "severity": "HIGH", "evidence_refs": []} for eid, v in orig_preds["overall"].items() if v]
    _, orig_chains = stitch_identity_events(events)
    orig_chain = next((c for c in orig_chains if "bob.contractor@corp.internal" in c.subject_ids), None)
    f1, _ = compute_identity_factors("bob.contractor@corp.internal", orig_bob_evts, orig_finds, identities.get("bob.contractor@corp.internal", {}), orig_chain)
    score1 = calculate_risk_score("identity", "bob.contractor@corp.internal", f1, {})

    trans_bob_evts = [e for e in renamed_events if e.get("identity_key") == surrogate_key]
    trans_finds = [{"event_id": eid, "detected": True, "severity": "HIGH", "evidence_refs": []} for eid, v in transformed_preds["overall"].items() if v]
    _, trans_chains = stitch_identity_events(renamed_events)
    trans_chain = next((c for c in trans_chains if surrogate_key in c.subject_ids), None)
    f2, _ = compute_identity_factors(surrogate_key, trans_bob_evts, trans_finds, renamed_identities.get(surrogate_key, {}), trans_chain)
    score2 = calculate_risk_score("identity", surrogate_key, f2, {})

    assert score1.total == score2.total
    assert score1.total >= 75

def test_zero_coordinates_equator_prime_meridian():
    """
    Edge case test 2A.3: Latitude 0.0 and Longitude 0.0 (Gulf of Guinea) must be strictly valid coordinates,
    not treated as falsey / missing.
    """
    evt_equator = {
        "event_id": "evt-eq-1",
        "ts_utc": "2026-10-28T10:00:00Z",
        "geo": {"lat": 0.0, "lon": 0.0, "city": "Equator Point", "country": "Ocean"}
    }
    evt_far = {
        "event_id": "evt-far-2",
        "ts_utc": "2026-10-28T10:30:00Z",
        "geo": {"lat": 45.0, "lon": 45.0, "city": "Far Point", "country": "Country"}
    }

    res = detect_impossible_travel(evt_equator, evt_far)
    assert res["status"] != "INCONCLUSIVE"
    assert res["detected"] is True # 6000+ km in 0.5 hours

def test_intervening_cloudtrail_event_preserves_geo():
    """
    Regression test 2A.3: An intervening CloudTrail event without geo coordinates must NOT erase
    the previous login location for impossible travel detection.
    """
    events, ids, _ = load_all_fixtures()
    # In fixtures: okta-evt-002 (London, 10:15) -> ct-evt-002 (no geo, 10:20) -> okta-evt-003 (Tokyo, 10:30)
    preds = run_detectors_on_events(events, ids)
    assert preds["impossible_travel"]["okta-evt-003"] is True

def test_chain_out_of_order_and_duplicates_fail():
    """
    Phase 5.4 Ordered chain test:
    Out-of-order and duplicate chain stages must fail exact match assertion.
    """
    expected = [
        {"subject": "target@corp.internal", "expected_stages": ["INITIAL_AUTHENTICATION", "SESSION_ASSUMPTION", "PRIVILEGE_ESCALATION"]}
    ]

    # Case 1: Out of order
    class FakeStage:
        def __init__(self, stage): self.stage = stage
    class FakeChain:
        def __init__(self, stages):
            self.subject_ids = ["target@corp.internal"]
            self.stages = [FakeStage(s) for s in stages]

    out_of_order_chain = [FakeChain(["SESSION_ASSUMPTION", "INITIAL_AUTHENTICATION", "PRIVILEGE_ESCALATION"])]
    rep1 = evaluate_ordered_chains(expected, out_of_order_chain)
    assert rep1["exact_match_rate"] == 0.0
    assert rep1["details"][0]["out_of_order"] is True

    # Case 2: Duplicate stage
    dup_chain = [FakeChain(["INITIAL_AUTHENTICATION", "SESSION_ASSUMPTION", "INITIAL_AUTHENTICATION", "PRIVILEGE_ESCALATION"])]
    rep2 = evaluate_ordered_chains(expected, dup_chain)
    assert rep2["exact_match_rate"] == 0.0
    assert rep2["details"][0]["has_duplicates"] is True

def test_counterfactual_explanation_arithmetic():
    """
    Phase 5.5 assertion test: Counterfactual explanation statement must equal the exact
    recomputed reduction when the top factor is removed.
    """
    factor_values = {
        "behavioral_anomaly": 90.0,
        "privilege_level": 40.0,
        "privilege_delta": 95.0,
        "resource_sensitivity": 85.0,
        "sequence_stage": 90.0
    }
    score = calculate_risk_score("identity", "bob.contractor@corp.internal", factor_values, {})
    top_factor = score.explanation["top_factors"][0]

    # Find top factor contribution
    top_f = next(f for f in score.factors if f.name == top_factor)
    expected_reduction = top_f.contribution

    cf_text = score.explanation["counterfactual"]
    assert top_factor in cf_text
    assert f"{expected_reduction:.1f}" in cf_text or f"{round(expected_reduction)}" in cf_text
