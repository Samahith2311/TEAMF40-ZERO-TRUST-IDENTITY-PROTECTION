import hashlib
import threading
import time
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple, Set

# Model / Policy Version constant
CURRENT_POLICY_VERSION = "2.0.0"

def cert_fingerprint(der_bytes: bytes) -> str:
    """
    Computes normalized SHA-256 fingerprint from DER-encoded X.509 certificate bytes.
    Returns colon-separated lowercase hex string.
    """
    if not isinstance(der_bytes, (bytes, bytearray)) or len(der_bytes) == 0:
        raise ValueError("Invalid peer certificate DER bytes: must be non-empty bytes.")
    raw_hex = hashlib.sha256(der_bytes).hexdigest().lower()
    return ":".join(raw_hex[i:i+2] for i in range(0, len(raw_hex), 2))

def normalize_fp(fp: Optional[str]) -> str:
    if not fp:
        return ""
    clean = fp.replace(":", "").replace("-", "").strip().lower()
    return ":".join(clean[i:i+2] for i in range(0, len(clean), 2))

class CertBindingStore:
    """
    Thread-safe storage for identity-session to client certificate fingerprint bindings.
    """
    def __init__(self):
        self._lock = threading.Lock()
        # Key: (identity, session_id) -> Dict
        self._bindings: Dict[Tuple[str, str], Dict[str, Any]] = {}
        # Approved rotations: Key: (identity, session_id) -> Set[str]
        self._approved_rotations: Dict[Tuple[str, str], Set[str]] = {}

    def bind(self, identity: str, session_id: str, fingerprint: str, source: str = "LOCAL_TLS") -> Dict[str, Any]:
        with self._lock:
            key = (identity, session_id)
            norm_f = normalize_fp(fingerprint)
            record = {
                "identity": identity,
                "session_id": session_id,
                "fingerprint": norm_f,
                "bound_at": datetime.now(timezone.utc).isoformat(),
                "source": source
            }
            self._bindings[key] = record
            return record

    def check(self, identity: str, session_id: str, observed_fingerprint: Optional[str]) -> Tuple[str, Optional[str]]:
        """
        Returns (status, expected_fp):
        - MATCH: observed matches bound fingerprint
        - APPROVED_ROTATION: observed matches an approved rotation entry
        - MISMATCH: observed does not match bound fingerprint
        - UNBOUND: session has no certificate binding recorded
        - NO_CERT: session is bound but caller presented no certificate
        """
        with self._lock:
            key = (identity, session_id)
            record = self._bindings.get(key)
            if not record:
                return "UNBOUND", None

            expected_fp = record["fingerprint"]
            if not observed_fingerprint:
                return "NO_CERT", expected_fp

            norm_obs = normalize_fp(observed_fingerprint)
            if norm_obs == expected_fp:
                return "MATCH", expected_fp

            rotations = self._approved_rotations.get(key, set())
            if norm_obs in rotations:
                return "APPROVED_ROTATION", expected_fp

            return "MISMATCH", expected_fp

    def approve_rotation(self, identity: str, session_id: str, new_fingerprint: str, approver: str = "security_lead@corp.internal") -> bool:
        with self._lock:
            key = (identity, session_id)
            norm_new = normalize_fp(new_fingerprint)
            self._approved_rotations.setdefault(key, set()).add(norm_new)
            return True

    def invalidate(self, identity: str, session_id: Optional[str] = None):
        with self._lock:
            if session_id:
                self._bindings.pop((identity, session_id), None)
                self._approved_rotations.pop((identity, session_id), None)
            else:
                keys_to_remove = [k for k in self._bindings if k[0] == identity]
                for k in keys_to_remove:
                    self._bindings.pop(k, None)
                    self._approved_rotations.pop(k, None)

class RiskDecisionCache:
    """
    Thread-safe bounded LRU decision cache with configurable TTL (Phase 7.3).
    """
    def __init__(self, ttl_seconds: float = 60.0, max_size: int = 1000):
        self._lock = threading.Lock()
        self.ttl = ttl_seconds
        self.max_size = max_size
        self._cache: Dict[Tuple[str, str, str, str], Dict[str, Any]] = {}
        self._stats = {
            "hits": 0,
            "misses": 0,
            "evictions": 0,
            "invalidations": 0,
            "fast_path_count": 0,
            "full_path_count": 0,
            "latency_samples": []
        }

    def get(self, identity: str, session_id: str, fingerprint: str, policy_version: str = CURRENT_POLICY_VERSION) -> Optional[Dict[str, Any]]:
        with self._lock:
            key = (identity, session_id, normalize_fp(fingerprint), policy_version)
            entry = self._cache.get(key)
            if not entry:
                self._stats["misses"] += 1
                return None

            now = time.monotonic()
            if now > entry["expires_at"]:
                del self._cache[key]
                self._stats["misses"] += 1
                return None

            self._stats["hits"] += 1
            return dict(entry["data"])

    def put(self, identity: str, session_id: str, fingerprint: str, data: Dict[str, Any], policy_version: str = CURRENT_POLICY_VERSION):
        with self._lock:
            if len(self._cache) >= self.max_size:
                # Evict oldest
                oldest_key = min(self._cache.keys(), key=lambda k: self._cache[k]["created_at"])
                del self._cache[oldest_key]
                self._stats["evictions"] += 1

            key = (identity, session_id, normalize_fp(fingerprint), policy_version)
            now = time.monotonic()
            self._cache[key] = {
                "created_at": now,
                "expires_at": now + self.ttl,
                "data": dict(data)
            }

    def invalidate(self, identity: str, session_id: Optional[str] = None):
        with self._lock:
            keys_to_del = [
                k for k in self._cache.keys()
                if k[0] == identity and (session_id is None or k[1] == session_id)
            ]
            for k in keys_to_del:
                del self._cache[k]
                self._stats["invalidations"] += 1

    def record_decision_timing(self, path: str, latency_ms: float):
        with self._lock:
            if path == "FAST_PATH":
                self._stats["fast_path_count"] += 1
            else:
                self._stats["full_path_count"] += 1
            samples = self._stats["latency_samples"]
            samples.append(latency_ms)
            if len(samples) > 200:
                samples.pop(0)

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            samples = self._stats["latency_samples"]
            mean_lat = round(sum(samples) / len(samples), 3) if samples else 0.0
            return {
                "hits": self._stats["hits"],
                "misses": self._stats["misses"],
                "evictions": self._stats["evictions"],
                "invalidations": self._stats["invalidations"],
                "fast_path_count": self._stats["fast_path_count"],
                "full_path_count": self._stats["full_path_count"],
                "cached_entries": len(self._cache),
                "mean_latency_ms": mean_lat,
                "sample_count": len(samples)
            }

# Global singletons
_binding_store = CertBindingStore()
_decision_cache = RiskDecisionCache(ttl_seconds=60.0)

def get_binding_store() -> CertBindingStore:
    return _binding_store

def get_decision_cache() -> RiskDecisionCache:
    return _decision_cache

def evaluate_mtls_decision(
    identity: str,
    session_id: str,
    peer_fingerprint: Optional[str],
    current_risk_score: Optional[int] = None,
    trusted_transport: str = "LOCAL_TLS"
) -> Dict[str, Any]:
    """
    Evaluates mTLS certificate binding and risk-adaptive decision caching (Phase 7).
    - Certificate mismatch immediately invalidates cache and triggers FULL_PATH / step-up.
    - Low risk + matching verified cert qualifies for FAST_PATH.
    - Full measurement of real decision overhead.
    """
    t_start = time.perf_counter()
    b_store = get_binding_store()
    d_cache = get_decision_cache()

    binding_status, expected_fp = b_store.check(identity, session_id, peer_fingerprint)

    # 1. Certificate Mismatch: Security Violation!
    if binding_status == "MISMATCH":
        # Invalidate cache immediately
        d_cache.invalidate(identity, session_id)
        elapsed_ms = (time.perf_counter() - t_start) * 1000.0
        d_cache.record_decision_timing("FULL_PATH", elapsed_ms)
        return {
            "identity": identity,
            "session_id": session_id,
            "decision_path": "FULL_PATH",
            "decision": "FULL_VERIFY_STEP_UP",
            "binding_status": "MISMATCH",
            "expected_fingerprint": expected_fp,
            "observed_fingerprint": normalize_fp(peer_fingerprint),
            "cache_hit": False,
            "risk_score": max(90, current_risk_score if current_risk_score is not None else 90),
            "recommended_action": "REVOKE_SESSION",
            "findings": [{
                "rule_id": "DET-06",
                "attack_type": "CERTIFICATE_BINDING_VIOLATION",
                "severity": "CRITICAL",
                "evidence": f"Certificate mismatch: session {session_id} bound to {expected_fp[:16]}.., but accessed with {normalize_fp(peer_fingerprint)[:16]}.."
            }],
            "policy_version": CURRENT_POLICY_VERSION,
            "latency_ms": round(elapsed_ms, 3),
            "label": "SIMULATED_ENFORCEMENT"
        }

    # 2. Check Decision Cache for existing low-risk decision on matching cert
    if binding_status in ["MATCH", "APPROVED_ROTATION"] and peer_fingerprint:
        cached = d_cache.get(identity, session_id, peer_fingerprint, CURRENT_POLICY_VERSION)
        if cached:
            elapsed_ms = (time.perf_counter() - t_start) * 1000.0
            d_cache.record_decision_timing("FAST_PATH", elapsed_ms)
            cached["cache_hit"] = True
            cached["latency_ms"] = round(elapsed_ms, 3)
            return cached

    # 3. Cache Miss / Evaluation Path
    score = current_risk_score if current_risk_score is not None else 20

    if score < 30 and binding_status in ["MATCH", "APPROVED_ROTATION"]:
        decision = "FAST_PATH_ALLOW"
        path = "FAST_PATH"
        rec_act = "MONITOR"
    elif score < 60:
        decision = "MONITOR_AND_RESCORE"
        path = "FULL_PATH"
        rec_act = "STEP_UP"
    else:
        decision = "FULL_VERIFY_STEP_UP"
        path = "FULL_PATH"
        rec_act = "REVOKE_SESSION"

    elapsed_ms = (time.perf_counter() - t_start) * 1000.0
    d_cache.record_decision_timing(path, elapsed_ms)

    decision_res = {
        "identity": identity,
        "session_id": session_id,
        "decision_path": path,
        "decision": decision,
        "binding_status": binding_status,
        "expected_fingerprint": expected_fp,
        "observed_fingerprint": normalize_fp(peer_fingerprint),
        "cache_hit": False,
        "risk_score": score,
        "recommended_action": rec_act,
        "policy_version": CURRENT_POLICY_VERSION,
        "latency_ms": round(elapsed_ms, 3),
        "label": "SIMULATED_ENFORCEMENT"
    }

    # Only cache verified low-risk decisions
    if path == "FAST_PATH" and binding_status in ["MATCH", "APPROVED_ROTATION"] and peer_fingerprint:
        d_cache.put(identity, session_id, peer_fingerprint, decision_res, CURRENT_POLICY_VERSION)

    return decision_res

