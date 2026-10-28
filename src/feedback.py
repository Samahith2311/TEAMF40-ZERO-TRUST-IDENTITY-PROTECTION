from datetime import datetime, timezone
from typing import Dict, Any, List
from src.scoring import FACTOR_WEIGHTS

# Dynamic weight state initialized from baseline
_dynamic_weights = dict(FACTOR_WEIGHTS)
_history: List[Dict[str, Any]] = []
_tuning_log: List[Dict[str, Any]] = []

def get_current_weights() -> Dict[str, float]:
    return dict(_dynamic_weights)

def get_tuning_log() -> List[Dict[str, Any]]:
    return list(_tuning_log)

def apply_analyst_feedback(factor: str, direction: str, analyst: str = "analyst@corp.internal") -> Dict[str, Any]:
    """
    Applies bounded multiplicative weight update (+/-10%).
    Clamped strictly between 0.5x and 2.0x of baseline weight.
    Reversible via rollback.
    """
    if factor not in FACTOR_WEIGHTS:
        raise ValueError(f"Unknown factor: {factor}")
    if direction not in ["INCREASE", "DECREASE"]:
        raise ValueError(f"Direction must be INCREASE or DECREASE, got: {direction}")

    base_w = FACTOR_WEIGHTS[factor]
    min_w = base_w * 0.5
    max_w = base_w * 2.0
    curr_w = _dynamic_weights[factor]

    # Save snapshot for revertibility
    _history.append({
        "weights": dict(_dynamic_weights),
        "factor": factor,
        "direction": direction,
        "analyst": analyst
    })

    multiplier = 1.10 if direction == "INCREASE" else 0.90
    new_w = curr_w * multiplier

    # Strict clamping bounds
    clamped_w = max(min_w, min(max_w, new_w))
    _dynamic_weights[factor] = round(clamped_w, 4)

    return {
        "factor": factor,
        "previous_weight": curr_w,
        "new_weight": _dynamic_weights[factor],
        "baseline_weight": base_w,
        "bounds": {"min": round(min_w, 4), "max": round(max_w, 4)},
        "analyst": analyst
    }

def revert_last_feedback() -> Dict[str, Any]:
    global _dynamic_weights
    if not _history:
        return {"status": "NO_HISTORY", "weights": dict(_dynamic_weights)}
    last = _history.pop()
    _dynamic_weights = dict(last["weights"])
    return {"status": "REVERTED", "weights": dict(_dynamic_weights)}

def autonomous_tune_from_attack(
    attack_type: str,
    detected_rules: List[str],
    target_identity: str,
    score_factors: Dict[str, float]
) -> Dict[str, Any]:
    """
    Autonomously calibrates model weights based on synthetic attack detection feedback.
    Enforces strict mathematical bounds (0.5x - 2.0x baseline).
    Manual user modification is prevented.
    """
    global _dynamic_weights
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    prev_weights = dict(_dynamic_weights)
    reasons = []

    # Calculate dynamic adjustments based on attack detection signals
    multipliers = {f: 1.0 for f in FACTOR_WEIGHTS}

    if any(r in detected_rules for r in ["DET-01", "DET-05"]):
        # Behavioral anomaly or impossible travel detected
        multipliers["behavioral_anomaly"] += 0.06
        reasons.append("Boosted behavioral_anomaly (+6%) due to dormant reactivation / impossible travel")

    if "DET-03" in detected_rules or score_factors.get("privilege_delta", 0) > 80:
        # Privilege escalation observed
        multipliers["privilege_delta"] += 0.08
        multipliers["sequence_stage"] += 0.05
        reasons.append("Boosted privilege_delta (+8%) and sequence_stage (+5%) for multi-stage privilege escalation")

    if "DET-04" in detected_rules or score_factors.get("resource_sensitivity", 0) > 80:
        # Sensitive target accessed
        multipliers["resource_sensitivity"] += 0.06
        reasons.append("Boosted resource_sensitivity (+6%) for unauthorized access to sensitive catalog resource")

    if not reasons:
        # Minor general calibration
        multipliers["behavioral_anomaly"] += 0.02
        reasons.append("Baseline background recalibration from benign/low-severity synthetic run")

    # Apply adjustments with strict boundary clamping
    new_weights = {}
    for factor, base_w in FACTOR_WEIGHTS.items():
        min_w = base_w * 0.5
        max_w = base_w * 2.0
        curr_w = _dynamic_weights[factor]
        updated = curr_w * multipliers[factor]
        clamped = max(min_w, min(max_w, updated))
        new_weights[factor] = round(clamped, 4)

    # Re-normalize proportionally so sum remains close to 1.0
    total = sum(new_weights.values())
    if total > 0:
        for factor, base_w in FACTOR_WEIGHTS.items():
            min_w = base_w * 0.5
            max_w = base_w * 2.0
            norm_w = max(min_w, min(max_w, (new_weights[factor] / total) * 1.0))
            new_weights[factor] = round(norm_w, 4)

    _dynamic_weights = new_weights

    entry = {
        "id": f"tune-{len(_tuning_log) + 1}",
        "timestamp": now_iso,
        "trigger": f"SYNTHETIC_ATTACK_{attack_type}",
        "target_identity": target_identity,
        "detected_rules": detected_rules,
        "reasons": reasons,
        "previous_weights": prev_weights,
        "tuned_weights": dict(_dynamic_weights),
        "status": "AUTONOMOUS_TUNED"
    }
    _tuning_log.append(entry)

    # Keep log bounded to last 50 events
    if len(_tuning_log) > 50:
        _tuning_log.pop(0)

    return entry
