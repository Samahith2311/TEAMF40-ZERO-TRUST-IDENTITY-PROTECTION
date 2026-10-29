import json
from pathlib import Path
from typing import List, Dict, Any, Tuple
from src.models import Alert, EvidenceRef

def get_action_for_score(score: int) -> Tuple[str, str]:
    if score >= 85:
        return "CRITICAL", "RESTRICT"
    elif score >= 60:
        return "HIGH", "REVOKE_SESSION"
    elif score >= 30:
        return "MEDIUM", "STEP_UP"
    return "LOW", "MONITOR"

def create_alert_from_incident(
    incident_id: str,
    subject_id: str,
    score: int,
    risk_score_ref: str,
    evidences: List[Dict[str, str]],
    what: str,
    why: str,
    first_seen: str,
    last_seen: str
) -> Alert:
    severity, rec_action = get_action_for_score(score)
    evidence_refs = [EvidenceRef(source_file=e["source_file"], record_id=str(e["record_id"])) for e in evidences]

    impact = f"Potential lateral movement and privileged access exploitation by subject {subject_id}."
    alert_id = f"alt-{incident_id}"

    return Alert(
        alert_id=alert_id,
        incident_id=incident_id,
        subject={"type": "identity", "id": subject_id},
        severity=severity,
        what=what,
        why=why,
        evidence_refs=evidence_refs,
        risk_score_ref=risk_score_ref,
        impact=impact,
        recommended_action=rec_action,
        status="OPEN",
        first_seen=first_seen,
        last_seen=last_seen,
        dup_count=1
    )

def verify_evidence_refs(alerts: List[Dict[str, Any]], fixtures_dir: str = "fixtures") -> Dict[str, Any]:
    """
    U5 Evidence Verifier:
    Re-resolves every cited (source_file, record_id) against the raw files,
    checks if line exists and parses valid JSON, and prints/returns % valid.
    """
    total_refs = 0
    valid_refs = 0
    invalid_citations = []

    base_path = Path(fixtures_dir)
    if not base_path.exists():
        repo_fixtures = Path(__file__).resolve().parent.parent / "fixtures"
        if repo_fixtures.exists():
            base_path = repo_fixtures

    for alt in alerts:
        for ref in alt.get("evidence_refs", []):
            total_refs += 1
            sf = ref.get("source_file")
            rid = str(ref.get("record_id"))
            
            # Record ref is in format "filename:line_no" or line_no
            line_no = int(rid.split(":")[-1]) if ":" in rid else int(rid)
            file_path = base_path / sf

            if not file_path.exists():
                invalid_citations.append({"ref": ref, "reason": "File does not exist"})
                continue

            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                    if 1 <= line_no <= len(lines):
                        json.loads(lines[line_no - 1].strip())
                        valid_refs += 1
                    else:
                        invalid_citations.append({"ref": ref, "reason": "Line index out of bounds"})
            except Exception as e:
                invalid_citations.append({"ref": ref, "reason": str(e)})

    valid_pct = (valid_refs / total_refs * 100.0) if total_refs > 0 else 100.0
    return {
        "total_citations": total_refs,
        "valid_citations": valid_refs,
        "valid_pct": round(valid_pct, 2),
        "invalid_citations": invalid_citations
    }
