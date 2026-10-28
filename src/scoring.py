from typing import List, Dict, Any, Optional
from src.models import RiskScore, RiskFactor

FACTOR_WEIGHTS = {
    "behavioral_anomaly": 0.25,
    "privilege_level": 0.20,
    "privilege_delta": 0.25,
    "resource_sensitivity": 0.15,
    "sequence_stage": 0.15
}

def calculate_risk_score(
    subject_type: str,
    subject_id: str,
    factor_values: Dict[str, float],
    evidence_map: Dict[str, List[Dict[str, str]]],
    weights: Optional[Dict[str, float]] = None
) -> RiskScore:
    """
    Computes additive factor risk score strictly clamped between 0 and 100.
    Explanation includes the top-3 contributing factors.
    Uses dynamically tuned model weights when available.
    """
    factors = []
    total_contribution = 0.0

    if weights is None:
        try:
            from src.feedback import get_current_weights
            active_weights = get_current_weights()
        except Exception:
            active_weights = FACTOR_WEIGHTS
    else:
        active_weights = weights

    for name, base_w in FACTOR_WEIGHTS.items():
        weight = active_weights.get(name, base_w)
        val = factor_values.get(name, 0.0)
        contrib = weight * val
        total_contribution += contrib
        factors.append(RiskFactor(
            name=name,
            weight=weight,
            value=val,
            contribution=round(contrib, 2),
            evidence_refs=evidence_map.get(name, [])
        ))

    clamped_total = max(0, min(100, int(round(total_contribution))))

    # Sort factors by contribution descending to extract top-3
    sorted_factors = sorted(factors, key=lambda f: f.contribution, reverse=True)
    top_factors = [f.name for f in sorted_factors[:3] if f.contribution > 0]

    return RiskScore(
        subject={"type": subject_type, "id": subject_id},
        total=clamped_total,
        factors=factors,
        explanation={
            "top_factors": top_factors,
            "counterfactual": f"Removing {top_factors[0]} reduces risk score by {sorted_factors[0].contribution:.1f}" if top_factors else "Baseline risk profile"
        }
    )
