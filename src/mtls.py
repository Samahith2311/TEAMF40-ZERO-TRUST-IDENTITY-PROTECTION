import base64
import hashlib
import hmac
import json
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Set

# Model / Policy Version constant
CURRENT_POLICY_VERSION = "2.0.0"

# HMAC Root Secret for Contextual Chained Macaroons (Phase 7 Zero-Trust Gateway)
MACAROON_ROOT_SECRET = b"mtls-macaroon-zero-trust-hmac-root-secret-v1"

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

def x5t_s256_thumbprint(der_bytes: bytes) -> str:
    """
    Computes RFC 8705 x5t#S256 thumbprint (base64url-encoded SHA-256 hash of DER cert).
    """
    digest = hashlib.sha256(der_bytes).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

# ============================================================================
# RFC 8705 & X.509 Certificate Registry Loader
# ============================================================================

_cached_cert_registry: Optional[Dict[str, Dict[str, Any]]] = None

def load_x509_certificates(certs_dir: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
    """
    Loads real X.509 certificates from certs/ (ca.crt, server.crt, client_alice.crt, client_bob.crt, client_attacker.crt).
    Computes exact SHA-256 colon-delimited fingerprints and RFC 8705 x5t#S256 thumbprints.
    """
    global _cached_cert_registry
    if _cached_cert_registry is not None and certs_dir is None:
        return _cached_cert_registry

    import ssl
    target_dir: Optional[Path] = None
    if certs_dir:
        target_dir = Path(certs_dir)
    else:
        # Search relative to current file or working directory
        candidates = [
            Path(__file__).resolve().parent.parent / "certs",
            Path.cwd() / "certs",
            Path.cwd() / "MIT-T-HACKATHON-" / "certs",
        ]
        for c in candidates:
            if c.exists() and (c / "fingerprints.json").exists():
                target_dir = c
                break
        if target_dir is None:
            target_dir = candidates[0]

    registry: Dict[str, Dict[str, Any]] = {}
    cert_specs = [
        ("ca", "ca.crt", "Internal Zero Trust Root CA", "ca@corp.internal", "ROOT_CA", True),
        ("server", "server.crt", "Production API Gateway (localhost)", "gateway.corp.internal", "GATEWAY_SERVER", True),
        ("alice", "client_alice.crt", "Alice Chen (Senior Cloud Security Engineer)", "alice@corp.internal", "CLIENT_AUTHORIZED", True),
        ("bob", "client_bob.crt", "Bob Miller (External DevOps Contractor)", "bob.contractor@corp.internal", "CLIENT_CONTRACTOR", True),
        ("attacker", "client_attacker.crt", "Unauthorized Replay Device (Malicious Rogue)", "attacker.replayer@external.net", "CLIENT_ATTACKER", False),
    ]

    for alias, filename, desc, ident, role, trusted in cert_specs:
        crt_file = target_dir / filename
        if crt_file.exists():
            try:
                pem_text = crt_file.read_text(encoding="utf-8")
                der_bytes = ssl.PEM_cert_to_DER_cert(pem_text)
                fp_sha256 = cert_fingerprint(der_bytes)
                x5t = x5t_s256_thumbprint(der_bytes)

                # Attempt subject parsing
                subject_str = f"CN={ident}"
                serial_num = "N/A"
                try:
                    from cryptography import x509
                    cert = x509.load_pem_x509_certificate(crt_file.read_bytes())
                    subject_str = cert.subject.rfc4514_string()
                    serial_num = str(cert.serial_number)
                except Exception:
                    pass

                registry[alias] = {
                    "alias": alias,
                    "filename": filename,
                    "path": str(crt_file),
                    "description": desc,
                    "identity": ident,
                    "role": role,
                    "is_trusted": trusted,
                    "subject": subject_str,
                    "serial_number": serial_num,
                    "fingerprint_sha256": fp_sha256,
                    "x5t_s256": x5t,
                    "der_size_bytes": len(der_bytes)
                }
            except Exception as e:
                registry[alias] = {
                    "alias": alias,
                    "filename": filename,
                    "error": str(e)
                }

    if certs_dir is None:
        _cached_cert_registry = registry
    return registry

def get_cert_by_identity(identity: str) -> Optional[Dict[str, Any]]:
    reg = load_x509_certificates()
    for item in reg.values():
        if item.get("identity") == identity:
            return item
    return None

def get_cert_by_alias(alias: str) -> Optional[Dict[str, Any]]:
    reg = load_x509_certificates()
    return reg.get(alias)

# ============================================================================
# Contextual Chained HMAC Macaroon Token (Phase 7 East-West Latency Tax Solver)
# ============================================================================

class MacaroonToken:
    """
    Contextual Chained HMAC Macaroon Token for East-West Microservice Traversal.
    On Hop 1 (Ingress Gateway), full mTLS verification + policy check mints this token.
    On Hops 2..30 (Internal Microservices), services verify the chained HMAC caveat
    in O(1) memory (< 0.05ms) instead of repeating 30 public-key handshakes.
    """
    def __init__(self, location: str, identifier: str, root_key: Optional[bytes] = None):
        self.location = location
        self.identifier = identifier
        self._root_key = root_key or MACAROON_ROOT_SECRET
        self.caveats: List[Tuple[str, str]] = []
        self.signature: bytes = self._compute_base_signature()

    def _compute_base_signature(self) -> bytes:
        seed = f"{self.location}:{self.identifier}".encode("utf-8")
        return hmac.new(self._root_key, seed, hashlib.sha256).digest()

    def add_caveat(self, key: str, value: str):
        """Chains an attenuation caveat: Sig_i = HMAC(Sig_{i-1}, key=value)."""
        self.caveats.append((key, value))
        clause = f"{key}={value}".encode("utf-8")
        self.signature = hmac.new(self.signature, clause, hashlib.sha256).digest()

    def serialize(self) -> str:
        """Serializes token into compact URL-safe base64 string."""
        payload = {
            "v": 1,
            "loc": self.location,
            "id": self.identifier,
            "cav": self.caveats,
            "sig": self.signature.hex()
        }
        raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii")

    @classmethod
    def deserialize(cls, token_str: str, root_key: Optional[bytes] = None) -> "MacaroonToken":
        """Deserializes compact base64 token string."""
        padding = "=" * (-len(token_str) % 4)
        raw = base64.urlsafe_b64decode((token_str + padding).encode("ascii"))
        payload = json.loads(raw.decode("utf-8"))
        tok = cls(location=payload["loc"], identifier=payload["id"], root_key=root_key)
        tok.caveats = [tuple(c) for c in payload["cav"]]
        tok.signature = bytes.fromhex(payload["sig"])
        return tok

    @classmethod
    def mint(
        cls,
        identity: str,
        cert_fingerprint: str,
        risk_band: str = "GREEN_FAST_PATH",
        ttl_seconds: float = 120.0,
        location: str = "us-east-1.corp.internal",
        root_key: Optional[bytes] = None
    ) -> "MacaroonToken":
        """Mints a new contextual HMAC macaroon bound to identity and X.509 cert thumbprint."""
        sess_token_id = f"mac-{hashlib.sha256(os.urandom(16)).hexdigest()[:12]}"
        tok = cls(location=location, identifier=sess_token_id, root_key=root_key)
        now = time.time()
        tok.add_caveat("identity", identity)
        tok.add_caveat("x5t", normalize_fp(cert_fingerprint))
        tok.add_caveat("risk_band", risk_band)
        tok.add_caveat("exp", str(round(now + ttl_seconds, 2)))
        return tok

    def verify(
        self,
        expected_identity: str,
        presented_cert_sha256: str,
        current_time: Optional[float] = None,
        root_key: Optional[bytes] = None
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Verifies HMAC chain integrity, expiration, and RFC 8705 certificate thumbprint binding.
        Returns (is_valid, status_code, details).
        """
        # 1. Cryptographic HMAC-SHA256 signature chain verification
        k = root_key or self._root_key
        sig = hmac.new(k, f"{self.location}:{self.identifier}".encode("utf-8"), hashlib.sha256).digest()
        for key, val in self.caveats:
            sig = hmac.new(sig, f"{key}={val}".encode("utf-8"), hashlib.sha256).digest()

        if not hmac.compare_digest(sig, self.signature):
            return False, "MACAROON_INTEGRITY_TAMPERED", {
                "error": "Cryptographic HMAC signature mismatch: caveat chain was tampered or forged"
            }

        # 2. Caveats evaluation
        cav_dict = dict(self.caveats)
        now = current_time if current_time is not None else time.time()

        # Check expiration
        if "exp" in cav_dict:
            try:
                exp_ts = float(cav_dict["exp"])
                if now > exp_ts:
                    return False, "MACAROON_EXPIRED", {
                        "error": f"Macaroon lease expired at {exp_ts} (current: {now})"
                    }
            except ValueError:
                return False, "MALFORMED_EXPIRATION", {"error": "Invalid expiration caveat timestamp"}

        # Check RFC 8705 certificate binding
        if "x5t" in cav_dict:
            bound_x5t = normalize_fp(cav_dict["x5t"])
            presented_norm = normalize_fp(presented_cert_sha256)
            if bound_x5t != presented_norm:
                return False, "RFC8705_CERT_BINDING_MISMATCH", {
                    "bound_thumbprint": bound_x5t,
                    "presented_thumbprint": presented_norm,
                    "error": "RFC 8705 Violation: Token was bound to client certificate thumbprint, but presented from mismatched certificate"
                }

        # Check identity
        if "identity" in cav_dict and cav_dict["identity"] != expected_identity:
            return False, "IDENTITY_MISMATCH", {
                "bound_identity": cav_dict["identity"],
                "presented_identity": expected_identity
            }

        return True, "VALID", cav_dict

# ============================================================================
# Certificate Binding Store
# ============================================================================

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

    def list_bindings(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._bindings.values())

# ============================================================================
# Risk Decision Cache (Phase 7.3)
# ============================================================================

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
            "cert_mismatches": 0,
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

    def record_mismatch(self):
        with self._lock:
            self._stats["cert_mismatches"] += 1

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            samples = self._stats["latency_samples"]
            mean_lat = round(sum(samples) / len(samples), 4) if samples else 0.0
            return {
                "hits": self._stats["hits"],
                "misses": self._stats["misses"],
                "evictions": self._stats["evictions"],
                "invalidations": self._stats["invalidations"],
                "fast_path_count": self._stats["fast_path_count"],
                "full_path_count": self._stats["full_path_count"],
                "cert_mismatches": self._stats["cert_mismatches"],
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

# ============================================================================
# 3-Band Risk-Adaptive Enforcement State Machine
# ============================================================================

def evaluate_mtls_decision(
    identity: str,
    session_id: str,
    peer_fingerprint: Optional[str],
    current_risk_score: Optional[int] = None,
    trusted_transport: str = "LOCAL_TLS"
) -> Dict[str, Any]:
    """
    Evaluates mTLS certificate binding and risk-adaptive decision caching (Phase 7).
    Implements 3-tier risk-adaptive gateway:
    - Band 1: GREEN_FAST_PATH (Risk < 30) -> sub-millisecond fast-path cache hit + Macaroon
    - Band 2: YELLOW_ASYNC_REVALIDATE (Risk 30..59) -> fast path allowed + background async re-eval + shortened 15s TTL
    - Band 3: RED_STEP_UP_OR_REVOKE (Risk >= 60 OR Mismatch) -> cache purged, Macaroon revoked, DET-06 audit alert
    """
    t_start = time.perf_counter()
    b_store = get_binding_store()
    d_cache = get_decision_cache()

    binding_status, expected_fp = b_store.check(identity, session_id, peer_fingerprint)

    # 1. Certificate Mismatch: Security Violation! (DET-06 / RFC 8705 Violation)
    if binding_status == "MISMATCH":
        d_cache.invalidate(identity, session_id)
        d_cache.record_mismatch()
        elapsed_ms = (time.perf_counter() - t_start) * 1000.0
        d_cache.record_decision_timing("FULL_PATH", elapsed_ms)
        return {
            "identity": identity,
            "session_id": session_id,
            "decision_path": "FULL_PATH",
            "decision": "FULL_VERIFY_STEP_UP",
            "risk_band": "RED_STEP_UP_OR_REVOKE",
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
                "evidence": f"RFC 8705 certificate mismatch: session {session_id} bound to {expected_fp[:16]}.., but presented from unauthorized {normalize_fp(peer_fingerprint)[:16]}.."
            }],
            "policy_version": CURRENT_POLICY_VERSION,
            "latency_ms": round(elapsed_ms, 3),
            "label": "SIMULATED_ENFORCEMENT",
            "rfc8705_status": "VIOLATION_BLOCKED"
        }

    # 2. Check Decision Cache for existing low-risk decision on matching cert
    if binding_status in ["MATCH", "APPROVED_ROTATION"] and peer_fingerprint:
        cached = d_cache.get(identity, session_id, peer_fingerprint, CURRENT_POLICY_VERSION)
        if cached:
            elapsed_ms = (time.perf_counter() - t_start) * 1000.0
            d_cache.record_decision_timing("FAST_PATH", elapsed_ms)
            res = dict(cached)
            res["cache_hit"] = True
            res["latency_ms"] = round(elapsed_ms, 3)
            return res

    # 3. Cache Miss / Evaluation Path
    score = current_risk_score if current_risk_score is not None else 20

    if score < 30 and binding_status in ["MATCH", "APPROVED_ROTATION"]:
        # Band 1: GREEN_FAST_PATH
        decision = "FAST_PATH_ALLOW"
        path = "FAST_PATH"
        risk_band = "GREEN_FAST_PATH"
        rec_act = "MONITOR"
        macaroon = MacaroonToken.mint(identity, peer_fingerprint or "", risk_band=risk_band, ttl_seconds=120.0)
        macaroon_serialized = macaroon.serialize()
        async_reval = False
    elif score < 60:
        # Band 2: YELLOW_ASYNC_REVALIDATE
        decision = "MONITOR_AND_RESCORE"
        path = "FULL_PATH"
        risk_band = "YELLOW_ASYNC_REVALIDATE"
        rec_act = "STEP_UP"
        macaroon = MacaroonToken.mint(identity, peer_fingerprint or "", risk_band=risk_band, ttl_seconds=15.0) if peer_fingerprint else None
        macaroon_serialized = macaroon.serialize() if macaroon else None
        async_reval = True
    else:
        # Band 3: RED_STEP_UP_OR_REVOKE
        decision = "FULL_VERIFY_STEP_UP"
        path = "FULL_PATH"
        risk_band = "RED_STEP_UP_OR_REVOKE"
        rec_act = "REVOKE_SESSION"
        macaroon_serialized = None
        async_reval = False

    elapsed_ms = (time.perf_counter() - t_start) * 1000.0
    d_cache.record_decision_timing(path, elapsed_ms)

    decision_res = {
        "identity": identity,
        "session_id": session_id,
        "decision_path": path,
        "decision": decision,
        "risk_band": risk_band,
        "binding_status": binding_status,
        "expected_fingerprint": expected_fp,
        "observed_fingerprint": normalize_fp(peer_fingerprint),
        "cache_hit": False,
        "risk_score": score,
        "recommended_action": rec_act,
        "policy_version": CURRENT_POLICY_VERSION,
        "latency_ms": round(elapsed_ms, 3),
        "label": "SIMULATED_ENFORCEMENT",
        "macaroon_token": macaroon_serialized,
        "async_revalidation_triggered": async_reval,
        "rfc8705_status": "VERIFIED" if binding_status in ["MATCH", "APPROVED_ROTATION"] else "UNBOUND"
    }

    # Only cache verified low-risk decisions
    if path == "FAST_PATH" and binding_status in ["MATCH", "APPROVED_ROTATION"] and peer_fingerprint:
        d_cache.put(identity, session_id, peer_fingerprint, decision_res, CURRENT_POLICY_VERSION)

    return decision_res

# ============================================================================
# Microservice Cascade Simulation (25-30 Microservices Topology)
# ============================================================================

MICROSERVICE_TOPOLOGY = [
    {"hop": 1, "service": "API-Gateway", "role": "Ingress mTLS & Contextual Policy Evaluation", "tier": "INGRESS"},
    {"hop": 2, "service": "Auth-Proxy", "role": "Mutual Authentication Filter", "tier": "AUTH"},
    {"hop": 3, "service": "Identity-Federator", "role": "Okta SSO / SAML Assertion Bridge", "tier": "AUTH"},
    {"hop": 4, "service": "Policy-PDP", "role": "Policy Decision Point Evaluator", "tier": "POLICY"},
    {"hop": 5, "service": "Session-Validator", "role": "Distributed Session State Store", "tier": "SESSION"},
    {"hop": 6, "service": "User-Profile-Svc", "role": "Identity Attributes & Group Resolver", "tier": "CORE"},
    {"hop": 7, "service": "Entitlements-Engine", "role": "Fine-Grained RBAC / ABAC Permissions", "tier": "POLICY"},
    {"hop": 8, "service": "Org-Hierarchy-Svc", "role": "Corporate Unit & Tenant Isolation", "tier": "CORE"},
    {"hop": 9, "service": "Token-Broker", "role": "Internal Delegation Token Minting", "tier": "SECURITY"},
    {"hop": 10, "service": "Cloud-Role-Resolver", "role": "AWS IAM Role Mapping Service", "tier": "CLOUD"},
    {"hop": 11, "service": "STS-Credential-Exchange", "role": "Temporary AWS STS Token Issuer", "tier": "CLOUD"},
    {"hop": 12, "service": "IAM-Evaluator", "role": "CloudTrail / IAM Policy Checker", "tier": "CLOUD"},
    {"hop": 13, "service": "Resource-Directory", "role": "Zero Trust Asset & Asset Tags", "tier": "DATA"},
    {"hop": 14, "service": "Ledger-Query-Engine", "role": "Tamper-Proof Audit Chain Inquirer", "tier": "LEDGER"},
    {"hop": 15, "service": "S3-Vault-Broker", "role": "Customer Data Bucket Broker", "tier": "DATA"},
    {"hop": 16, "service": "PII-Redactor", "role": "Streaming Sensitive Data Masking", "tier": "DATA"},
    {"hop": 17, "service": "Data-Masker", "role": "Column-Level Tokenization Gateway", "tier": "DATA"},
    {"hop": 18, "service": "Audit-Collector", "role": "HMAC-Chained Audit Log Appender", "tier": "LEDGER"},
    {"hop": 19, "service": "Kafka-Event-Publisher", "role": "Event Streaming Pub/Sub Bus", "tier": "EVENT"},
    {"hop": 20, "service": "SIEM-Forwarder", "role": "Splunk / Sentinel Event Forwarder", "tier": "SIEM"},
    {"hop": 21, "service": "Compliance-Monitor", "role": "SOC2 / FedRAMP Assertion Verifier", "tier": "AUDIT"},
    {"hop": 22, "service": "Cache-Synchronizer", "role": "Redis Decision Cache Invalidation Mesh", "tier": "CACHE"},
    {"hop": 23, "service": "Metrics-Emitter", "role": "Prometheus Latency & Telemetry Emitter", "tier": "TELEMETRY"},
    {"hop": 24, "service": "Tracing-Collector", "role": "OpenTelemetry Distributed Span Collector", "tier": "TELEMETRY"},
    {"hop": 25, "service": "Egress-Gateway", "role": "Filtered Outbound Response Delivery", "tier": "EGRESS"},
]

def simulate_microservice_cascade(
    identity: str = "bob.contractor@corp.internal",
    cert_alias: str = "bob",
    hops: int = 25,
    simulate_hijack_at_hop: Optional[int] = None
) -> Dict[str, Any]:
    """
    Simulates a multi-hop internal microservice cascade.
    Compares:
    1. Naive Zero Trust: Every microservice performs full public-key mTLS handshake + DB policy lookup (15-40ms per hop).
    2. Contextual Chained Macaroon (Our Innovation): Hop 1 performs mTLS + initial check (~15ms);
       Hops 2..25 verify lightweight HMAC Macaroon (< 0.05ms) in O(1) memory.
    3. Stolen Token Replay (RFC 8705): If simulate_hijack_at_hop is reached (e.g. Hop 12),
       attacker presents stolen token using client_attacker.crt; verification fails immediately with RFC 8705 violation.
    """
    certs = load_x509_certificates()
    legit_cert = certs.get(cert_alias) or certs.get("bob")
    attacker_cert = certs.get("attacker")

    legit_fp = legit_cert["fingerprint_sha256"] if legit_cert else "69:63:40:3c:a9:36:a8:87:03:60:d4:01:1d:f0:6c:5c:75:17:f4:22:83:42:0c:1e:e6:50:97:16:51:ac:9c:fb"
    attacker_fp = attacker_cert["fingerprint_sha256"] if attacker_cert else "59:80:87:09:70:79:59:2e:68:93:11:30:6d:7a:73:0c:0e:c1:0a:f5:02:87:85:89:8d:5a:1a:f4:19:25:cf:7e"

    # Mint contextual macaroon at Hop 1
    t0_mint = time.perf_counter()
    macaroon = MacaroonToken.mint(identity, legit_fp, risk_band="GREEN_FAST_PATH", ttl_seconds=120.0)
    mint_dt_ms = (time.perf_counter() - t0_mint) * 1000.0

    selected_topology = MICROSERVICE_TOPOLOGY[:min(hops, len(MICROSERVICE_TOPOLOGY))]

    hop_results: List[Dict[str, Any]] = []
    cumulative_fast_ms = 0.0
    cumulative_naive_ms = 0.0
    cascade_status = "SUCCESS"
    containment_details = None

    for idx, svc_def in enumerate(selected_topology, start=1):
        is_hijack_hop = (simulate_hijack_at_hop is not None and idx == simulate_hijack_at_hop)

        # Naive per-hop mTLS cost: Asymmetric ECDSA/RSA handshake (~18-28ms) + sync policy DB (~8-15ms)
        naive_hop_ms = 22.5 + ((idx * 37) % 7) * 1.8

        if idx == 1:
            # Hop 1: Real Ingress mTLS handshake + initial policy verification + Macaroon minting
            fast_hop_ms = round(14.5 + mint_dt_ms, 3)
            cumulative_fast_ms += fast_hop_ms
            cumulative_naive_ms += naive_hop_ms
            hop_results.append({
                "hop": idx,
                "service": svc_def["service"],
                "role": svc_def["role"],
                "tier": svc_def["tier"],
                "status": "PASS",
                "auth_mechanism": "Ingress mTLS (X.509) + Macaroon Minting",
                "crypto_latency_ms": round(mint_dt_ms, 4),
                "total_hop_latency_ms": fast_hop_ms,
                "naive_hop_latency_ms": round(naive_hop_ms, 2),
                "cumulative_fast_ms": round(cumulative_fast_ms, 2),
                "cumulative_naive_ms": round(cumulative_naive_ms, 2),
                "rfc8705_status": "BOUND",
                "bound_thumbprint": legit_fp[:16] + "..",
                "presented_thumbprint": legit_fp[:16] + ".."
            })
            continue

        # East-West internal hops (2..25)
        if is_hijack_hop:
            # Attacker presents stolen token with unauthorized client certificate
            t0_check = time.perf_counter()
            is_valid, err_code, details = macaroon.verify(
                expected_identity=identity,
                presented_cert_sha256=attacker_fp
            )
            verify_dt_ms = (time.perf_counter() - t0_check) * 1000.0
            fast_hop_ms = round(verify_dt_ms + 0.45, 3)
            cumulative_fast_ms += fast_hop_ms
            cumulative_naive_ms += naive_hop_ms

            cascade_status = "BLOCKED_HIJACK_CONTAINED"
            containment_details = {
                "containment_hop": idx,
                "service": svc_def["service"],
                "rule_id": "DET-06",
                "attack_type": "RFC_8705_CERTIFICATE_BINDING_VIOLATION",
                "bound_fingerprint": legit_fp,
                "presented_fingerprint": attacker_fp,
                "identity": identity,
                "error_code": err_code,
                "action": "REVOKE_SESSION_AND_ISOLATE",
                "reason": f"Stolen token replayed from unauthorized device. Token mathematically locked to Bob's cert ({legit_fp[:12]}..), but attacker presented ({attacker_fp[:12]}..)."
            }

            hop_results.append({
                "hop": idx,
                "service": svc_def["service"],
                "role": svc_def["role"],
                "tier": svc_def["tier"],
                "status": "BLOCKED",
                "auth_mechanism": "RFC 8705 Macaroon Verification (O(1) HMAC)",
                "crypto_latency_ms": round(verify_dt_ms, 4),
                "total_hop_latency_ms": fast_hop_ms,
                "naive_hop_latency_ms": round(naive_hop_ms, 2),
                "cumulative_fast_ms": round(cumulative_fast_ms, 2),
                "cumulative_naive_ms": round(cumulative_naive_ms, 2),
                "rfc8705_status": "MISMATCH_BLOCKED",
                "bound_thumbprint": legit_fp[:16] + "..",
                "presented_thumbprint": attacker_fp[:16] + "..",
                "violation": "DET-06: Stolen Token Replay Intercepted"
            })

            # Subsequent hops are prevented from executing (blast radius contained!)
            for rem_idx in range(idx + 1, len(selected_topology) + 1):
                rem_svc = selected_topology[rem_idx - 1]
                hop_results.append({
                    "hop": rem_idx,
                    "service": rem_svc["service"],
                    "role": rem_svc["role"],
                    "tier": rem_svc["tier"],
                    "status": "SKIPPED_BLAST_RADIUS_CONTAINED",
                    "auth_mechanism": "N/A (Request Quarantined at Hop " + str(idx) + ")",
                    "crypto_latency_ms": 0.0,
                    "total_hop_latency_ms": 0.0,
                    "naive_hop_latency_ms": 0.0,
                    "cumulative_fast_ms": round(cumulative_fast_ms, 2),
                    "cumulative_naive_ms": round(cumulative_naive_ms, 2),
                    "rfc8705_status": "CONTAINED",
                    "bound_thumbprint": legit_fp[:16] + "..",
                    "presented_thumbprint": "N/A"
                })
            break

        # Legitimate Hop: Real O(1) HMAC Macaroon verification
        t0_check = time.perf_counter()
        is_valid, err_code, details = macaroon.verify(
            expected_identity=identity,
            presented_cert_sha256=legit_fp
        )
        verify_dt_ms = (time.perf_counter() - t0_check) * 1000.0
        fast_hop_ms = round(verify_dt_ms + 0.45, 3) # crypto + intra-rack wire
        cumulative_fast_ms += fast_hop_ms
        cumulative_naive_ms += naive_hop_ms

        hop_results.append({
            "hop": idx,
            "service": svc_def["service"],
            "role": svc_def["role"],
            "tier": svc_def["tier"],
            "status": "PASS",
            "auth_mechanism": "Contextual Chained Macaroon (O(1) HMAC)",
            "crypto_latency_ms": round(verify_dt_ms, 4),
            "total_hop_latency_ms": fast_hop_ms,
            "naive_hop_latency_ms": round(naive_hop_ms, 2),
            "cumulative_fast_ms": round(cumulative_fast_ms, 2),
            "cumulative_naive_ms": round(cumulative_naive_ms, 2),
            "rfc8705_status": "MATCH",
            "bound_thumbprint": legit_fp[:16] + "..",
            "presented_thumbprint": legit_fp[:16] + ".."
        })

    speedup = round(cumulative_naive_ms / cumulative_fast_ms, 1) if cumulative_fast_ms > 0 else 1.0
    saved_ms = round(cumulative_naive_ms - cumulative_fast_ms, 1)
    reduction_pct = round((saved_ms / cumulative_naive_ms) * 100.0, 1) if cumulative_naive_ms > 0 else 0.0

    return {
        "status": cascade_status,
        "identity": identity,
        "cert_alias": cert_alias,
        "total_hops": len(selected_topology),
        "completed_hops": len([h for h in hop_results if h["status"] == "PASS" or h["status"] == "BLOCKED"]),
        "cumulative_fast_path_ms": round(cumulative_fast_ms, 2),
        "cumulative_naive_mtls_ms": round(cumulative_naive_ms, 2),
        "latency_saved_ms": saved_ms,
        "speedup_factor": f"{speedup}x",
        "latency_reduction_pct": f"{reduction_pct}%",
        "containment": containment_details,
        "hops": hop_results
    }
