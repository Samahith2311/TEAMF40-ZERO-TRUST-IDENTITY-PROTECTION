from datetime import datetime, timezone
from typing import Dict, Any
from src.models import SimulatorAction

PROTECTED_IDENTITIES = {
    "breakglass-admin@corp.internal",
    "root",
    "arn:aws:iam::123456789012:root"
}

def execute_simulated_action(
    incident_id: str,
    action: str,
    target_identity: str,
    approved: bool = False,
    approver: str = "analyst@corp.internal"
) -> SimulatorAction:
    action_id = f"sim-{incident_id}-{action.lower()}"
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Safeguard 1: Protected identities can never be auto-restricted
    if target_identity in PROTECTED_IDENTITIES and action in ["RESTRICT", "REVOKE_SESSION"]:
        return SimulatorAction(
            action_id=action_id,
            incident_id=incident_id,
            action=action,
            target=target_identity,
            expected_loss={"disruption_cost": 10000.0, "breach_risk": 0.0},
            approval={"required": True, "by": approver, "ts": now_utc, "status": "DENIED"},
            preview=f"DENIED: Target {target_identity} is a protected break-glass identity.",
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
