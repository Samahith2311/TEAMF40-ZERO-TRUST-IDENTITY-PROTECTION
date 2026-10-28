from fastapi import FastAPI, HTTPException, Body
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Dict, Any

from src.db import get_db
from src.config import COLLECTIONS
from src.simulator import execute_simulated_action
from src.audit import create_audit_entry
from src.graph import build_attack_graph
from src.feedback import get_current_weights, apply_analyst_feedback, revert_last_feedback, get_tuning_log

app = FastAPI(title="Zero Trust Identity Protection API", version="1.0.0")

# Restrict CORS to development frontend origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    return response

def sanitize_query_param(val: Any) -> Any:
    if isinstance(val, dict):
        raise HTTPException(status_code=400, detail="Invalid parameter type: dict prohibited")
    if isinstance(val, str) and val.startswith("$"):
        raise HTTPException(status_code=400, detail="Invalid parameter: operators prohibited")
    return val

@app.on_event("startup")
def startup_populate():
    db = get_db()
    if db[COLLECTIONS["alerts"]].count_documents({}) == 0:
        from src.pipeline import run_pipeline_slice
        run_pipeline_slice()

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
    from src.synthetic_generator import generate_synthetic_attack
    archetype = payload.get("archetype")
    result = generate_synthetic_attack(archetype)
    return result

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
