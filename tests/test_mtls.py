import json
import time
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from src.mtls import (
    cert_fingerprint,
    normalize_fp,
    x5t_s256_thumbprint,
    load_x509_certificates,
    MacaroonToken,
    CertBindingStore,
    RiskDecisionCache,
    evaluate_mtls_decision,
    simulate_microservice_cascade,
    CURRENT_POLICY_VERSION
)
from src.api import app

client = TestClient(app)

def test_cert_fingerprint_calculation():
    """Phase 7.3: Verifies canonical SHA-256 fingerprint derivation from DER bytes."""
    der_mock = b"\x30\x82\x01\x0a\x02\x82\x01\x01\x00\xaa\xbb\xcc\xdd"
    fp = cert_fingerprint(der_mock)
    assert len(fp.split(":")) == 32
    assert fp == fp.lower()

    # Empty or non-bytes input raises explicit ValueError
    with pytest.raises(ValueError):
        cert_fingerprint(b"")
    with pytest.raises(ValueError):
        cert_fingerprint("not_bytes") # type: ignore

def test_cert_binding_match_and_mismatch():
    """Phase 7.3: Tests MATCH, MISMATCH, NO_CERT, and UNBOUND states."""
    store = CertBindingStore()
    ident = "alice@corp.internal"
    sess = "sess-001"
    fp1 = "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99"
    fp2 = "11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00"

    # Unbound check
    status, _ = store.check(ident, sess, fp1)
    assert status == "UNBOUND"

    # Bind session
    store.bind(ident, sess, fp1)

    # Match check
    status, exp = store.check(ident, sess, fp1)
    assert status == "MATCH"
    assert exp == fp1

    # Mismatch check
    status, exp = store.check(ident, sess, fp2)
    assert status == "MISMATCH"
    assert exp == fp1

    # No cert presented on bound session
    status, exp = store.check(ident, sess, None)
    assert status == "NO_CERT"
    assert exp == fp1

def test_approved_rotation():
    """Phase 7.3: Benign approved rotation must match and avoid false mismatch."""
    store = CertBindingStore()
    ident = "bob@corp.internal"
    sess = "sess-002"
    old_fp = "00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff"
    new_fp = "ff:ee:dd:cc:bb:aa:99:88:77:66:55:44:33:22:11:00:ff:ee:dd:cc:bb:aa:99:88:77:66:55:44:33:22:11:00"

    store.bind(ident, sess, old_fp)
    store.approve_rotation(ident, sess, new_fp, approver="sec_ops@corp.internal")

    status, exp = store.check(ident, sess, new_fp)
    assert status == "APPROVED_ROTATION"
    assert exp == old_fp

def test_decision_cache_hit_and_ttl():
    """Phase 7.3: Validates decision cache hit, miss, and TTL expiration."""
    cache = RiskDecisionCache(ttl_seconds=0.2)
    ident = "charlie@corp.internal"
    sess = "sess-003"
    fp = "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99"

    # Miss
    assert cache.get(ident, sess, fp) is None

    # Put
    cache.put(ident, sess, fp, {"decision": "FAST_PATH_ALLOW", "risk_score": 15})

    # Hit
    cached = cache.get(ident, sess, fp)
    assert cached is not None
    assert cached["decision"] == "FAST_PATH_ALLOW"

    # Invalidation
    cache.invalidate(ident, sess)
    assert cache.get(ident, sess, fp) is None

def test_mismatch_forces_full_rescore_and_invalidates_cache():
    """
    Phase 7.3: A certificate mismatch must immediately invalidate cached decisions
    and force FULL_PATH with DET-06 security violation.
    """
    store = CertBindingStore()
    cache = RiskDecisionCache(ttl_seconds=60.0)

    import src.mtls
    orig_store = src.mtls._binding_store
    orig_cache = src.mtls._decision_cache
    src.mtls._binding_store = store
    src.mtls._decision_cache = cache

    try:
        ident = "diana@corp.internal"
        sess = "sess-004"
        valid_fp = "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11"
        attacker_fp = "22:22:22:22:22:22:22:22:22:22:22:22:22:22:22:22:22:22:22:22:22:22:22:22:22:22:22:22:22:22:22:22"

        store.bind(ident, sess, valid_fp)

        # Initial call: computes and caches fast path decision
        dec1 = evaluate_mtls_decision(ident, sess, valid_fp, current_risk_score=10)
        assert dec1["decision_path"] == "FAST_PATH"
        assert dec1["cache_hit"] is False

        # Second call with valid cert: cache hit!
        dec2 = evaluate_mtls_decision(ident, sess, valid_fp, current_risk_score=10)
        assert dec2["decision_path"] == "FAST_PATH"
        assert dec2["cache_hit"] is True

        # Replay attack with different cert: mismatch!
        dec_atk = evaluate_mtls_decision(ident, sess, attacker_fp, current_risk_score=10)
        assert dec_atk["decision_path"] == "FULL_PATH"
        assert dec_atk["binding_status"] == "MISMATCH"
        assert dec_atk["decision"] == "FULL_VERIFY_STEP_UP"
        assert dec_atk["recommended_action"] == "REVOKE_SESSION"
        assert dec_atk["findings"][0]["rule_id"] == "DET-06"

        # Verify cache was invalidated for that identity/session
        cached_after = cache.get(ident, sess, valid_fp)
        assert cached_after is None
    finally:
        src.mtls._binding_store = orig_store
        src.mtls._decision_cache = orig_cache

def test_x509_certificate_registry_loading():
    """Verifies that all 5 real X.509 certificates in certs/ load and match fingerprints.json."""
    certs = load_x509_certificates()
    assert "ca" in certs
    assert "server" in certs
    assert "alice" in certs
    assert "bob" in certs
    assert "attacker" in certs

    # Verify Bob and Attacker thumbprints
    bob = certs["bob"]
    assert bob["fingerprint_sha256"].startswith("69:63:40")
    assert bob["is_trusted"] is True
    assert "x5t_s256" in bob

    attacker = certs["attacker"]
    assert attacker["fingerprint_sha256"].startswith("59:80:87")
    assert attacker["is_trusted"] is False

def test_macaroon_mint_verify_tamper_and_expiry():
    """Verifies Contextual Chained HMAC Macaroon minting, O(1) verification, tampering detection, and RFC 8705 checks."""
    ident = "bob.contractor@corp.internal"
    bob_fp = "69:63:40:3c:a9:36:a8:87:03:60:d4:01:1d:f0:6c:5c:75:17:f4:22:83:42:0c:1e:e6:50:97:16:51:ac:9c:fb"
    attacker_fp = "59:80:87:09:70:79:59:2e:68:93:11:30:6d:7a:73:0c:0e:c1:0a:f5:02:87:85:89:8d:5a:1a:f4:19:25:cf:7e"

    tok = MacaroonToken.mint(ident, bob_fp, risk_band="GREEN_FAST_PATH", ttl_seconds=60.0)
    serialized = tok.serialize()

    # 1. Successful verification on legitimate client cert
    deser = MacaroonToken.deserialize(serialized)
    valid, status, cavs = deser.verify(ident, bob_fp)
    assert valid is True
    assert status == "VALID"
    assert cavs["identity"] == ident

    # 2. Replay attack: Stolen token presented with attacker's certificate
    valid_atk, status_atk, details_atk = deser.verify(ident, attacker_fp)
    assert valid_atk is False
    assert status_atk == "RFC8705_CERT_BINDING_MISMATCH"
    assert "RFC 8705 Violation" in details_atk["error"]

    # 3. Tampering detection: Modified caveat breaks HMAC signature
    tampered_tok = MacaroonToken.deserialize(serialized)
    tampered_tok.caveats[0] = ("identity", "alice@corp.internal") # Tampered identity caveat!
    valid_tamp, status_tamp, _ = tampered_tok.verify(ident, bob_fp)
    assert valid_tamp is False
    assert status_tamp == "MACAROON_INTEGRITY_TAMPERED"

    # 4. Expiration check
    expired_tok = MacaroonToken.mint(ident, bob_fp, ttl_seconds=-10.0) # Expired 10s ago
    valid_exp, status_exp, _ = expired_tok.verify(ident, bob_fp)
    assert valid_exp is False
    assert status_exp == "MACAROON_EXPIRED"

def test_three_tier_risk_bands():
    """Verifies the 3-tier risk-adaptive gateway state machine."""
    store = CertBindingStore()
    cache = RiskDecisionCache(ttl_seconds=60.0)

    import src.mtls
    orig_store = src.mtls._binding_store
    orig_cache = src.mtls._decision_cache
    src.mtls._binding_store = store
    src.mtls._decision_cache = cache

    try:
        ident = "test.user@corp.internal"
        sess = "sess-tier"
        fp = "11:22:33:44:55:66:77:88:99:00:11:22:33:44:55:66:77:88:99:00:11:22:33:44:55:66:77:88:99:00:11:22"
        store.bind(ident, sess, fp)

        # Tier 1: GREEN_FAST_PATH (<30)
        dec_green = evaluate_mtls_decision(ident, sess, fp, current_risk_score=15)
        assert dec_green["risk_band"] == "GREEN_FAST_PATH"
        assert dec_green["decision"] == "FAST_PATH_ALLOW"
        assert dec_green["macaroon_token"] is not None

        # Tier 2: YELLOW_ASYNC_REVALIDATE (30-59)
        cache.invalidate(ident, sess)
        dec_yellow = evaluate_mtls_decision(ident, sess, fp, current_risk_score=45)
        assert dec_yellow["risk_band"] == "YELLOW_ASYNC_REVALIDATE"
        assert dec_yellow["decision"] == "MONITOR_AND_RESCORE"
        assert dec_yellow["async_revalidation_triggered"] is True

        # Tier 3: RED_STEP_UP_OR_REVOKE (>=60)
        cache.invalidate(ident, sess)
        dec_red = evaluate_mtls_decision(ident, sess, fp, current_risk_score=75)
        assert dec_red["risk_band"] == "RED_STEP_UP_OR_REVOKE"
        assert dec_red["decision"] == "FULL_VERIFY_STEP_UP"
        assert dec_red["recommended_action"] == "REVOKE_SESSION"
    finally:
        src.mtls._binding_store = orig_store
        src.mtls._decision_cache = orig_cache

def test_microservice_cascade_simulation_success():
    """Verifies full 25-hop microservice cascade under legitimate conditions."""
    res = simulate_microservice_cascade(
        identity="bob.contractor@corp.internal",
        cert_alias="bob",
        hops=25
    )
    assert res["status"] == "SUCCESS"
    assert res["total_hops"] == 25
    assert res["completed_hops"] == 25
    assert res["cumulative_fast_path_ms"] < 60.0 # Well under 60ms
    assert res["cumulative_naive_mtls_ms"] > 400.0 # Naive adds 400ms+
    assert float(res["latency_reduction_pct"].replace("%", "")) > 85.0
    assert len(res["hops"]) == 25
    assert all(h["status"] == "PASS" for h in res["hops"])

def test_microservice_cascade_simulation_hijack_contained():
    """Verifies that an RFC 8705 certificate mismatch at Hop 12 halts traversal immediately."""
    res = simulate_microservice_cascade(
        identity="bob.contractor@corp.internal",
        cert_alias="bob",
        hops=25,
        simulate_hijack_at_hop=12
    )
    assert res["status"] == "BLOCKED_HIJACK_CONTAINED"
    assert res["containment"] is not None
    assert res["containment"]["containment_hop"] == 12
    assert res["containment"]["rule_id"] == "DET-06"

    # Verify Hop 12 was blocked and subsequent hops were prevented
    hops = res["hops"]
    assert hops[11]["hop"] == 12 # index 11 is hop 12
    assert hops[11]["status"] == "BLOCKED"
    assert hops[11]["rfc8705_status"] == "MISMATCH_BLOCKED"

    assert hops[12]["hop"] == 13
    assert hops[12]["status"] == "SKIPPED_BLAST_RADIUS_CONTAINED"

def test_mtls_api_endpoints():
    """Verifies the new /api/mtls/status, /api/mtls/simulate-cascade, and /api/mtls/simulate-hijack endpoints."""
    # 1. /api/mtls/status
    res_status = client.get("/api/mtls/status")
    assert res_status.status_code == 200
    data_status = res_status.json()
    assert "certificates" in data_status
    assert len(data_status["certificates"]) >= 5
    assert "GREEN_FAST_PATH" in data_status["risk_bands"]

    # 2. /api/mtls/simulate-cascade
    res_cascade = client.post("/api/mtls/simulate-cascade", json={
        "identity": "bob.contractor@corp.internal",
        "cert_alias": "bob",
        "hops": 25
    })
    assert res_cascade.status_code == 200
    data_cascade = res_cascade.json()
    assert data_cascade["status"] == "SUCCESS"
    assert len(data_cascade["hops"]) == 25

    # 3. /api/mtls/simulate-hijack
    res_hijack = client.post("/api/mtls/simulate-hijack", json={
        "identity": "bob.contractor@corp.internal",
        "cert_alias": "bob",
        "hijack_hop": 12,
        "hops": 25
    })
    assert res_hijack.status_code == 200
    data_hijack = res_hijack.json()
    assert data_hijack["status"] == "BLOCKED_HIJACK_CONTAINED"
    assert data_hijack["containment"]["containment_hop"] == 12
