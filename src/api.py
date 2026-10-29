import os
from fastapi import FastAPI, HTTPException, Body
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Dict, Any

from src.db import get_db
from src.config import COLLECTIONS
from src.simulator import execute_simulated_action
from src.audit import create_audit_entry
from src.graph import build_attack_graph
from src.feedback import get_current_weights, apply_analyst_feedback, revert_last_feedback, get_tuning_log

app = FastAPI(title="Zero Trust Identity Protection API", version="1.0.0")

# Allowed origins: local dev, preview Vercel domains, and VERCEL_URL
cors_origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
]
if os.getenv("VERCEL_URL"):
    cors_origins.append(f"https://{os.getenv('VERCEL_URL')}")

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_origin_regex=r"https://.*\.vercel\.app",
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    import traceback
    return JSONResponse(
        status_code=500,
        content={
            "status": "ERROR",
            "detail": str(exc),
            "traceback": traceback.format_exc()
        }
    )

@app.middleware("http")
async def add_security_headers(request, call_next):
    try:
        path = request.scope.get("path", "")
        if path and not path.startswith("/api") and not path.startswith("/docs") and not path.startswith("/openapi") and path != "/":
            request.scope["path"] = "/api" + path
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        return response
    except Exception as exc:
        import traceback
        return JSONResponse(
            status_code=500,
            content={
                "status": "ERROR",
                "detail": str(exc),
                "traceback": traceback.format_exc()
            }
        )

def sanitize_query_param(val: Any) -> Any:
    if isinstance(val, dict):
        raise HTTPException(status_code=400, detail="Invalid parameter type: dict prohibited")
    if isinstance(val, str) and val.startswith("$"):
        raise HTTPException(status_code=400, detail="Invalid parameter: operators prohibited")
    return val

@app.on_event("startup")
def startup_populate():
    try:
        db = get_db()
        if db[COLLECTIONS["alerts"]].count_documents({}) == 0:
            from src.pipeline import run_pipeline_slice
            run_pipeline_slice()
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"Startup populate error: {e}", exc_info=True)

@app.get("/")
def root_index():
    return {"status": "ok", "service": "zero-trust-engine", "mode": "SIMULATION"}

@app.get("/api/health")
def health_check():
    return {"status": "ok", "service": "zero-trust-engine", "mode": "SIMULATION"}

@app.get("/api/alerts")
def get_alerts():
    db = get_db()
    alerts = list(db[COLLECTIONS["alerts"]].find({}, {"_id": 0}))
    return {"alerts": alerts, "count": len(alerts)}

@app.get("/api/chains")
def get_chains():
    db = get_db()
    chains = list(db[COLLECTIONS["incident_chains"]].find({}, {"_id": 0}))
    return {"chains": chains, "count": len(chains)}

@app.get("/api/scores")
def get_scores():
    db = get_db()
    scores = list(db[COLLECTIONS["risk_scores"]].find({}, {"_id": 0}))
    return {"scores": scores, "count": len(scores)}

@app.get("/api/eval")
def get_eval():
    db = get_db()
    evals = list(db[COLLECTIONS["eval_results"]].find({}, {"_id": 0}))
    return {"eval_results": evals}

@app.get("/api/graph")
def get_attack_graph():
    db = get_db()
    events = list(db[COLLECTIONS["normalized_events"]].find({}, {"_id": 0}))
    chains = list(db[COLLECTIONS["incident_chains"]].find({}, {"_id": 0}))
    graph = build_attack_graph(events, chains)
    return {"graph": graph}

# --- Autonomous Model Tuning Endpoints ---

@app.get("/api/feedback/weights")
def get_weights():
    return {"weights": get_current_weights()}

@app.get("/api/feedback/tuning-log")
def get_model_tuning_log():
    return {"tuning_log": get_tuning_log()}

@app.post("/api/feedback")
def submit_feedback(payload: Dict[str, Any] = Body(...)):
    # Explicit requirement: User is NOT allowed to modify model tuning
    raise HTTPException(
        status_code=403,
        detail="Manual model tuning is disabled. Model tuning is autonomously governed by the Synthetic Attack Engine."
    )

@app.post("/api/feedback/revert")
def revert_feedback():
    raise HTTPException(
        status_code=403,
        detail="Manual model rollback is disabled. Model weights are tuned autonomously based on live synthetic threat patterns."
    )

# --- Synthetic Attack Generator Endpoints ---

@app.post("/api/synthetic/generate")
def api_generate_synthetic_attack(payload: Dict[str, Any] = Body(default={})):
    try:
        from src.synthetic_generator import generate_synthetic_attack
        archetype = payload.get("archetype")
        result = generate_synthetic_attack(archetype)
        return result
    except Exception as e:
        import traceback
        return JSONResponse(
            status_code=500,
            content={"status": "ERROR", "detail": str(e), "traceback": traceback.format_exc()}
        )

@app.get("/api/synthetic/history")
def api_get_synthetic_history():
    from src.synthetic_generator import get_attack_history
    return {"history": get_attack_history()}

@app.get("/api/synthetic/status")
def api_get_synthetic_status():
    from src.synthetic_generator import is_auto_streaming, get_attack_history
    return {
        "auto_streaming": is_auto_streaming(),
        "total_generated": len(get_attack_history()),
        "active_weights": get_current_weights()
    }

@app.post("/api/synthetic/auto")
def api_toggle_auto_streaming(payload: Dict[str, Any] = Body(...)):
    from src.synthetic_generator import set_auto_streaming
    enabled = bool(payload.get("enabled", False))
    interval = float(payload.get("interval", 6.0))
    active = set_auto_streaming(enabled, interval)
    return {"auto_streaming": active, "interval": interval}

# --- Action & Containment Endpoints ---

@app.post("/api/actions/approve")
def approve_action(payload: Dict[str, Any] = Body(...)):
    incident_id = sanitize_query_param(payload.get("incident_id"))
    action = sanitize_query_param(payload.get("action"))
    target = sanitize_query_param(payload.get("target"))
    approver = sanitize_query_param(payload.get("approver", "analyst@corp.internal"))

    if not (incident_id and action and target):
        raise HTTPException(status_code=400, detail="Missing required parameters")

    sim_action = execute_simulated_action(
        incident_id=incident_id,
        action=action,
        target_identity=target,
        approved=True,
        approver=approver
    )

    db = get_db()
    db[COLLECTIONS["simulator_actions"]].update_one(
        {"action_id": sim_action.action_id},
        {"$set": sim_action.model_dump()},
        upsert=True
    )

    last_log = db[COLLECTIONS["audit_logs"]].find_one(sort=[("_id", -1)])
    prev_hash = last_log.get("curr_hash") if last_log else "0000000000000000000000000000000000000000000000000000000000000000"
    audit_entry = create_audit_entry(
        actor=approver,
        action=f"APPROVE_{action}",
        details={"incident_id": incident_id, "target": target, "result": sim_action.result},
        prev_hash=prev_hash
    )
    db[COLLECTIONS["audit_logs"]].insert_one(audit_entry.model_dump())

    return {"status": "success", "action": sim_action.model_dump()}

@app.post("/api/actions/step-up")
def trigger_step_up(payload: Dict[str, Any] = Body(...)):
    target = sanitize_query_param(payload.get("target"))
    incident_id = sanitize_query_param(payload.get("incident_id", "inc-general"))

    return {
        "status": "CHALLENGE_ISSUED",
        "action": "STEP_UP",
        "target": target,
        "challenge_type": "FIDO2_WEBAUTHN",
        "label": "SIMULATED",
        "prompt": f"Simulated MFA push prompt delivered to hardware token for user '{target}'."
    }

# --- Risk-Adaptive mTLS Endpoints (Phase 7) ---

@app.post("/api/mtls/bind")
def api_bind_mtls_session(payload: Dict[str, Any] = Body(...)):
    from src.mtls import get_binding_store
    identity = sanitize_query_param(payload.get("identity"))
    session_id = sanitize_query_param(payload.get("session_id"))
    fingerprint = sanitize_query_param(payload.get("fingerprint"))

    if not (identity and session_id and fingerprint):
        raise HTTPException(status_code=400, detail="Missing required parameters: identity, session_id, fingerprint")

    store = get_binding_store()
    rec = store.bind(identity, session_id, fingerprint)
    return {"status": "SUCCESS", "binding": rec}

@app.post("/api/mtls/decide")
def api_mtls_decide(payload: Dict[str, Any] = Body(...)):
    from src.mtls import evaluate_mtls_decision
    identity = sanitize_query_param(payload.get("identity"))
    session_id = sanitize_query_param(payload.get("session_id"))
    cert_fp = sanitize_query_param(payload.get("cert_fingerprint"))
    risk_score = payload.get("current_risk_score")

    if not (identity and session_id):
        raise HTTPException(status_code=400, detail="Missing identity or session_id")

    decision = evaluate_mtls_decision(
        identity=identity,
        session_id=session_id,
        peer_fingerprint=cert_fp,
        current_risk_score=risk_score
    )
    return decision

@app.get("/api/mtls/stats")
def api_mtls_stats():
    from src.mtls import get_decision_cache
    return {"stats": get_decision_cache().stats()}

@app.post("/api/mtls/approve-rotation")
def api_approve_rotation(payload: Dict[str, Any] = Body(...)):
    from src.mtls import get_binding_store
    identity = sanitize_query_param(payload.get("identity"))
    session_id = sanitize_query_param(payload.get("session_id"))
    new_fp = sanitize_query_param(payload.get("new_fingerprint"))
    approver = sanitize_query_param(payload.get("approver", "sec_ops@corp.internal"))

    if not (identity and session_id and new_fp):
        raise HTTPException(status_code=400, detail="Missing required parameters")

    store = get_binding_store()
    ok = store.approve_rotation(identity, session_id, new_fp, approver)
    return {"status": "ROTATION_APPROVED", "identity": identity, "session_id": session_id, "approved_fingerprint": new_fp}

@app.get("/api/mtls/status")
def api_mtls_status():
    from src.mtls import load_x509_certificates, get_binding_store, get_decision_cache
    certs = load_x509_certificates()
    bindings = get_binding_store().list_bindings()
    stats = get_decision_cache().stats()
    return {
        "status": "ONLINE",
        "certificates": list(certs.values()),
        "active_bindings": bindings,
        "cache_stats": stats,
        "risk_bands": {
            "GREEN_FAST_PATH": {
                "range": "0-29",
                "action": "FAST_PATH_ALLOW",
                "ttl_seconds": 120,
                "description": "Sub-millisecond fast-path cache hit + Contextual Chained Macaroon verification"
            },
            "YELLOW_ASYNC_REVALIDATE": {
                "range": "30-59",
                "action": "MONITOR_AND_RESCORE",
                "ttl_seconds": 15,
                "description": "Low-friction allow with asynchronous background re-evaluation and shortened lease"
            },
            "RED_STEP_UP_OR_REVOKE": {
                "range": "60-100",
                "action": "FULL_VERIFY_STEP_UP / REVOKE",
                "ttl_seconds": 0,
                "description": "Immediate decision cache eviction, token revocation, DET-06 audit alert"
            }
        },
        "standards": {
            "rfc": "RFC 8705 OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens",
            "macaroon_hash": "HMAC-SHA256 Contextual Chaining",
            "fast_path_latency_target_ms": "< 0.05 ms",
            "naive_hop_latency_ms": "~22-35 ms per hop"
        }
    }

@app.post("/api/mtls/simulate-cascade")
def api_simulate_cascade(payload: Dict[str, Any] = Body(...)):
    from src.mtls import simulate_microservice_cascade
    identity = sanitize_query_param(payload.get("identity", "bob.contractor@corp.internal"))
    cert_alias = sanitize_query_param(payload.get("cert_alias", "bob"))
    hops = int(payload.get("hops", 25))
    hops = max(5, min(hops, 30))

    result = simulate_microservice_cascade(
        identity=identity,
        cert_alias=cert_alias,
        hops=hops
    )
    return result

@app.post("/api/mtls/simulate-hijack")
def api_simulate_hijack(payload: Dict[str, Any] = Body(...)):
    from src.mtls import simulate_microservice_cascade
    identity = sanitize_query_param(payload.get("identity", "bob.contractor@corp.internal"))
    cert_alias = sanitize_query_param(payload.get("cert_alias", "bob"))
    hijack_hop = int(payload.get("hijack_hop", 12))
    hops = int(payload.get("hops", 25))
    hops = max(5, min(hops, 30))

    result = simulate_microservice_cascade(
        identity=identity,
        cert_alias=cert_alias,
        hops=hops,
        simulate_hijack_at_hop=hijack_hop
    )
    return result
