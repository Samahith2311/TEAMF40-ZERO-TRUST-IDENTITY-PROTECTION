import os
from pathlib import Path
from dotenv import load_dotenv

# Load local environment if present
env_path = Path(__file__).resolve().parent.parent / ".env"
if env_path.exists():
    load_dotenv(env_path)

MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017/zero_trust_db")
API_HOST = os.getenv("API_HOST", "127.0.0.1")
API_PORT = int(os.getenv("API_PORT", "8000"))
WEB_PORT = int(os.getenv("WEB_PORT", "5173"))
ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

# Collection names matching contract seed
COLLECTIONS = {
    "normalized_events": "normalized_events",
    "validation_results": "validation_results",
    "identity_links": "identity_links",
    "risk_scores": "risk_scores",
    "alerts": "alerts",
    "incident_chains": "incident_chains",
    "simulator_actions": "simulator_actions",
    "audit_logs": "audit_logs",
    "eval_results": "eval_results",
    "evaluation_labels": "evaluation_labels",
}
