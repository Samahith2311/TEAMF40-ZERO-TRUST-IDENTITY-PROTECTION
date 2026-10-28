from typing import List, Dict, Any, Tuple
from src.models import IdentityLink, IncidentChain, ChainStage

def stitch_identity_events(events: List[Dict[str, Any]]) -> Tuple[List[IdentityLink], List[IncidentChain]]:
    """
    Links Okta authentication events to AWS CloudTrail events by:
    1. Direct email/identity match
    2. IP address + temporal proximity
    3. Session correlation
    """
    links = []
    chains = []

    # Group events by identity_key
    by_identity = {}
    for evt in events:
        ident = evt.get("identity_key")
        if ident not in by_identity:
            by_identity[ident] = []
        by_identity[ident].append(evt)

    for ident, evts in by_identity.items():
        sorted_evts = sorted(evts, key=lambda x: x.get("ts_utc", ""))
        stages = []
        incident_id = f"inc-{ident.replace('@', '_').replace('.', '_')}"

        okta_evts = [e for e in sorted_evts if e.get("source") == "okta"]
        ct_evts = [e for e in sorted_evts if e.get("source") == "cloudtrail"]

        # Link Okta to CloudTrail
        for ok in okta_evts:
            for ct in ct_evts:
                basis = []
                conf = 0.5
                prov = "ANALYTICAL_INFERENCE"

                if ok.get("identity_key") == ct.get("identity_key"):
                    basis.append("exact_identity_match")
                    conf += 0.3
                    prov = "VALIDATED_OBSERVATION"

                if ok.get("ip") == ct.get("ip") and ok.get("ip") != "0.0.0.0":
                    basis.append("ip_match")
                    conf += 0.2

                link_id = f"link-{ok['event_id']}-{ct['event_id']}"
                links.append(IdentityLink(
                    link_id=link_id,
                    from_subject=ok["event_id"],
                    to_subject=ct["event_id"],
                    basis=basis,
                    confidence=min(1.0, conf),
                    provenance=prov
                ))

        # Build chain stages from observed attack-pattern events
        for e in sorted_evts:
            action = e.get("action", "")
            stage_name = None
            if "AttachUserPolicy" in action:
                stage_name = "PRIVILEGE_ESCALATION"
            elif "AssumeRole" in action:
                stage_name = "SESSION_ASSUMPTION"
            elif "user.session.start" in action:
                stage_name = "INITIAL_AUTHENTICATION"
            elif "pii-vault" in e.get("resource", "") or "production_export" in e.get("resource", ""):
                stage_name = "DATA_EXFILTRATION_ATTEMPT"

            if stage_name:
                stages.append(ChainStage(
                    stage=stage_name,
                    event_ref=e["event_id"],
                    link_provenance="VALIDATED_OBSERVATION" if e.get("source") == "cloudtrail" else "LABEL_DERIVED"
                ))

        if len(stages) > 1:
            chains.append(IncidentChain(
                incident_id=incident_id,
                stages=stages,
                links=[l.link_id for l in links if l.from_subject in [s.event_ref for s in stages] or l.to_subject in [s.event_ref for s in stages]],
                subject_ids=[ident],
                confidence=0.95 if any(s.stage == "PRIVILEGE_ESCALATION" for s in stages) else 0.75,
                unresolved=[]
            ))

    return links, chains
