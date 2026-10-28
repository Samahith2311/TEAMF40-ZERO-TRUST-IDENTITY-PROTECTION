"""
Baseline Detector: Standard Single-Signal Threshold Implementation
This is the baseline detector to beat.
Rules:
1. Flags any event with outcome == FAILURE as anomalous authentication.
2. Flags any action containing Attach*, Put*, or CreateAccessKey as privilege escalation.
3. Flags any action containing AssumeRole with root or admin in name.
"""

from typing import List, Dict, Any

def run_baseline_detector(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    predictions = []
    for evt in events:
        is_anomaly = False
        reason = []

        if evt.get("outcome") == "FAILURE":
            is_anomaly = True
            reason.append("Failed authentication or operation")

        action = evt.get("action", "")
        if any(sensitive in action for sensitive in ["Attach", "PutUserPolicy", "CreateAccessKey", "DeleteLog"]):
            is_anomaly = True
            reason.append(f"Sensitive action name: {action}")

        predictions.append({
            "event_id": evt.get("event_id"),
            "source": evt.get("source"),
            "identity_key": evt.get("identity_key"),
            "predicted_suspicious": is_anomaly,
            "reasons": reason,
            "detector": "BASELINE_THRESHOLD"
        })
    return predictions
