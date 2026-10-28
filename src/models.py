from typing import List, Optional, Dict, Any, Literal
from pydantic import BaseModel, Field

class ValidationDetails(BaseModel):
    status: Literal["VALID", "INVALID", "QUARANTINED"] = "VALID"
    reasons: List[str] = Field(default_factory=list)

class NormalizedEvent(BaseModel):
    event_id: str
    source: Literal["okta", "cloudtrail", "synthetic"]
    source_file: str
    record_ref: Any
    ts_utc: str
    ts_original_tz: Optional[str] = None
    identity_key: str
    principal_raw: str
    session_id: Optional[str] = None
    ip: str
    geo: Dict[str, Any] = Field(default_factory=dict)
    user_agent: str
    action: str
    resource: str
    outcome: Literal["SUCCESS", "FAILURE", "UNKNOWN"] = "SUCCESS"
    privilege_context: Dict[str, Any] = Field(default_factory=dict)
    raw_hash: str
    validation: ValidationDetails = Field(default_factory=ValidationDetails)

class ValidationResult(BaseModel):
    record_ref: str
    structural_ok: bool
    timestamp_ok: bool
    order_ok: bool
    duplicate_of: Optional[str] = None
    identity_ref_ok: bool
    reasons: List[str] = Field(default_factory=list)

class IdentityLink(BaseModel):
    link_id: str
    from_subject: str
    to_subject: str
    basis: List[str] = Field(default_factory=list)
    confidence: float
    provenance: Literal["LABEL_DERIVED", "VALIDATED_OBSERVATION", "ANALYTICAL_INFERENCE"]

class RiskFactor(BaseModel):
    name: str
    weight: float
    value: float
    contribution: float
    evidence_refs: List[Dict[str, str]] = Field(default_factory=list)

class RiskScore(BaseModel):
    subject: Dict[str, str] # {"type": "identity"|"session", "id": "..."}
    total: int = Field(ge=0, le=100)
    factors: List[RiskFactor] = Field(default_factory=list)
    explanation: Dict[str, Any] = Field(default_factory=dict)

class EvidenceRef(BaseModel):
    source_file: str
    record_id: str

class Alert(BaseModel):
    alert_id: str
    incident_id: str
    subject: Dict[str, str]
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    what: str
    why: str
    evidence_refs: List[EvidenceRef] = Field(default_factory=list)
    risk_score_ref: str
    impact: str
    recommended_action: Literal["MONITOR", "STEP_UP", "REVOKE_SESSION", "RESTRICT"]
    status: Literal["OPEN", "INVESTIGATING", "RESOLVED", "DISMISSED"] = "OPEN"
    first_seen: str
    last_seen: str
    dup_count: int = 1

class ChainStage(BaseModel):
    stage: str
    event_ref: str
    link_provenance: str

class IncidentChain(BaseModel):
    incident_id: str
    stages: List[ChainStage] = Field(default_factory=list)
    links: List[str] = Field(default_factory=list)
    subject_ids: List[str] = Field(default_factory=list)
    confidence: float
    unresolved: List[str] = Field(default_factory=list)

class SimulatorAction(BaseModel):
    action_id: str
    incident_id: str
    action: Literal["MONITOR", "STEP_UP", "REVOKE_SESSION", "RESTRICT"]
    target: str
    expected_loss: Dict[str, float] = Field(default_factory=dict)
    approval: Dict[str, Any] = Field(default_factory=dict)
    preview: str
    result: str
    rollback: str
    label: Literal["SIMULATED", "MOCKED"] = "SIMULATED"

class AuditLog(BaseModel):
    log_id: str
    prev_hash: str
    curr_hash: str
    ts_utc: str
    actor: str
    action: str
    details: Dict[str, Any] = Field(default_factory=dict)

class EvalResult(BaseModel):
    level: Literal["event", "identity", "session", "chain"]
    detector: str
    tp: int
    fp: int
    fn: int
    precision: float
    recall: float
    f1: float
    baseline: Dict[str, float] = Field(default_factory=dict)
    delta: Dict[str, float] = Field(default_factory=dict)
    split: str = "synthetic_eval"
    n: int = 0
    label: Literal["VERIFIED", "MOCKED", "NOT RUN"] = "VERIFIED"
    latency: Dict[str, float] = Field(default_factory=dict)
    evidence_ref_valid_pct: float = 100.0
