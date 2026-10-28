import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Set, Optional
from src.models import SimulatorAction

_IDENTITIES_CACHE: Optional[Dict[str, bool]] = None

def load_protected_identities_map(identities_file: str = "fixtures/identities.json") -> Dict[str, bool]:
    global _IDENTITIES_CACHE
    path = Path(identities_file)
    if not path.exists():
        path = Path(__file__).resolve().parent.parent / "fixtures" / "identities.json"
    
    if path.exists():
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return {item["identity_key"]: bool(item.get("is_protected", False)) for item in data}
        except Exception:
            pass
    return {}

def is_identity_protected(target_identity: str, identities_file: str = "fixtures/identities.json") -> bool:
    """Authoritative check reading fixtures/identities.json + defense-in-depth ARN/root patterns."""
    ident_map = load_protected_identities_map(identities_file)
    if target_identity in ident_map:
        return ident_map[target_identity]
    
    # Strip arn prefixes if needed
    clean_target = target_identity.split(":")[-1] if ":" in target_identity and not target_identity.startswith("arn:") else target_identity
    if clean_target in ident_map:
        return ident_map[clean_target]

    # Defense-in-depth patterns for root / break-glass
    lower = target_identity.lower()
    if lower == "root" or lower.endswith(":root") or "breakglass" in lower or "break-glass" in lower:
        return True

    return False

def execute_simulated_action(
    incident_id: str,
    action: str,
    target_identity: str,
    approved: bool = False,
    approver: str = "analyst@corp.internal",
    identities_file: str = "fixtures/identities.json"
) -> SimulatorAction:
    action_id = f"sim-{incident_id}-{action.lower()}"
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Safeguard 1: Protected identities can never be auto-restricted or revoked
    if is_identity_protected(target_identity, identities_file) and action in ["RESTRICT", "REVOKE_SESSION"]:
        return SimulatorAction(
            action_id=action_id,
            incident_id=incident_id,
            action=action,
            target=target_identity,
            expected_loss={"disruption_cost": 10000.0, "breach_risk": 0.0},
            approval={"required": True, "by": approver, "ts": now_utc, "status": "DENIED"},
            preview=f"DENIED: Target {target_identity} is a protected break-glass / administrative identity.",
            result="DENIED_PROTECTED_IDENTITY",
            rollback="NONE",
            label="SIMULATED"
        )

    # Safeguard 2: Require approval for high impact actions
    requires_approval = action in ["REVOKE_SESSION", "RESTRICT"]
    if requires_approval and not approved:
        return SimulatorAction(
            action_id=action_id,
            incident_id=incident_id,
            action=action,
            target=target_identity,
            expected_loss={"disruption_cost": 250.0, "breach_risk": 1500.0},
            approval={"required": True, "by": None, "ts": None, "status": "PENDING_APPROVAL"},
            preview=f"PENDING: {action} on {target_identity} awaits analyst sign-off.",
            result="PENDING_APPROVAL",
            rollback=f"Unquarantine {target_identity} / Reissue session",
            label="SIMULATED"
        )

    return SimulatorAction(
        action_id=action_id,
        incident_id=incident_id,
        action=action,
        target=target_identity,
        expected_loss={"disruption_cost": 100.0, "breach_risk": 50.0},
        approval={"required": requires_approval, "by": approver, "ts": now_utc, "status": "APPROVED"},
        preview=f"APPLY: {action} dispatched to simulator for target {target_identity}.",
        result="SUCCESS_SIMULATED",
        rollback=f"Revert {action} on {target_identity}",
        label="SIMULATED"
    )
