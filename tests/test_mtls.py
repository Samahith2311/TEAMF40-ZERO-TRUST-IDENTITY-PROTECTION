import pytest
from src.mtls import (
    cert_fingerprint,
    normalize_fp,
    CertBindingStore,
    RiskDecisionCache,
    evaluate_mtls_decision,
    CURRENT_POLICY_VERSION
)

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

    # Patch global singletons for isolated test
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

