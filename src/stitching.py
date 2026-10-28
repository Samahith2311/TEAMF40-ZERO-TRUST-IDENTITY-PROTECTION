from typing import List, Dict, Any, Tuple
from src.models import IdentityLink, IncidentChain, ChainStage

def stitch_identity_events(events: List[Dict[str, Any]]) -> Tuple[List[IdentityLink], List[IncidentChain]]:
    """
    Correlates Okta authentication and AWS CloudTrail events across identities and sessions:
    1. Direct identity candidate overlap (email, user ID, ARN)
    2. Session correlation (Okta debugContext.session_id, CloudTrail roleSessionName)
    3. IP address and temporal proximity
    Reconstructs ordered multi-step attack chains with evidence references.
    """
    links: List[IdentityLink] = []
    chains: List[IncidentChain] = []

    # Group events by canonical identity candidates
    identity_to_events: Dict[str, List[Dict[str, Any]]] = {}
    session_to_events: Dict[str, List[Dict[str, Any]]] = {}

    for evt in events:
        ident = evt.get("identity_key", "unknown")
        identity_to_events.setdefault(ident, []).append(evt)
        candidates = evt.get("identity_candidates") or [ident]
        for c in candidates:
            if c != ident:
                identity_to_events.setdefault(c, []).append(evt)

        sess_id = evt.get("session_id")
        if sess_id:
            session_to_events.setdefault(sess_id, []).append(evt)

    # Process each primary identity group
    primary_identities = {e.get("identity_key") for e in events if e.get("identity_key") and e.get("identity_key") != "unknown"}

    for ident in primary_identities:
        evts = identity_to_events.get(ident, [])
        # Deduplicate events in group by event_id
        seen_eids = set()
        unique_evts = []
        for e in evts:
            eid = e.get("event_id")
            if eid and eid not in seen_eids:
                seen_eids.add(eid)
                unique_evts.append(e)

        sorted_evts = sorted(unique_evts, key=lambda x: x.get("ts_utc", ""))
        stages: List[ChainStage] = []
        incident_id = f"inc-{ident.replace('@', '_').replace('.', '_')}"

        okta_evts = [e for e in sorted_evts if e.get("source") == "okta"]
        ct_evts = [e for e in sorted_evts if e.get("source") == "cloudtrail"]

        # Link Okta to CloudTrail with typed provenance
        for ok in okta_evts:
            for ct in ct_evts:
                basis = []
                conf = 0.5
                prov = "ANALYTICAL_INFERENCE"

                # Check exact identity match or candidate overlap
                ok_candidates = set(ok.get("identity_candidates") or [ok.get("identity_key")])
                ct_candidates = set(ct.get("identity_candidates") or [ct.get("identity_key")])

                if ok.get("identity_key") == ct.get("identity_key") or bool(ok_candidates.intersection(ct_candidates)):
                    basis.append("identity_candidate_overlap")
                    conf += 0.3
                    prov = "VALIDATED_OBSERVATION"

                # Check session ID correlation
                if ok.get("session_id") and ct.get("session_id") and ok.get("session_id") == ct.get("session_id"):
                    basis.append("session_id_match")
                    conf += 0.2
                    prov = "VALIDATED_OBSERVATION"

                # Check IP match
                if ok.get("ip") == ct.get("ip") and ok.get("ip") != "0.0.0.0":
                    basis.append("ip_match")
                    conf += 0.15

                link_id = f"link-{ok['event_id']}-{ct['event_id']}"
                links.append(IdentityLink(
                    link_id=link_id,
                    from_subject=ok["event_id"],
                    to_subject=ct["event_id"],
                    basis=basis,
                    confidence=min(1.0, conf),
                    provenance=prov
                ))

        # Build chronological chain stages from semantics
        prev_stage = None
        for e in sorted_evts:
            action = e.get("action", "")
            resource = e.get("resource", "").lower()
            stage_name = None

            if "user.session.start" in action or "login" in action.lower() or "authentication" in action.lower():
                stage_name = "INITIAL_AUTHENTICATION"
            elif "AssumeRole" in action or "GetSessionToken" in action:
                stage_name = "SESSION_ASSUMPTION"
            elif any(act in action for act in ["AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy", "PutRolePolicy", "CreateAccessKey"]):
                stage_name = "PRIVILEGE_ESCALATION"
            elif "pii-vault" in resource or "production_export" in resource or "customer-pii" in resource or "secret" in resource:
                stage_name = "DATA_EXFILTRATION_ATTEMPT"

            # Deduplicate stages: ensure INITIAL_AUTHENTICATION only appears at sequence start
            if stage_name:
                if stage_name == "INITIAL_AUTHENTICATION" and any(s.stage == "INITIAL_AUTHENTICATION" for s in stages):
                    continue
                if stage_name != prev_stage:
                    stages.append(ChainStage(
                        stage=stage_name,
                        event_ref=e["event_id"],
                        link_provenance="VALIDATED_OBSERVATION"
                    ))
                    prev_stage = stage_name

        if len(stages) >= 2:
            stage_event_refs = {s.event_ref for s in stages}
            matched_links = [l.link_id for l in links if l.from_subject in stage_event_refs or l.to_subject in stage_event_refs]
            
            chain_conf = 0.75
            if any(s.stage == "PRIVILEGE_ESCALATION" for s in stages):
                chain_conf += 0.15
            if any(s.stage == "DATA_EXFILTRATION_ATTEMPT" for s in stages):
                chain_conf += 0.10

            chains.append(IncidentChain(
                incident_id=incident_id,
                stages=stages,
                links=matched_links[:10],
                subject_ids=[ident],
                confidence=min(1.0, chain_conf),
                unresolved=[]
            ))

    return links, chains
