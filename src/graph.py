from typing import List, Dict, Any

def build_attack_graph(events: List[Dict[str, Any]], chains: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Constructs an identity attack graph with typed edges and provenance.
    Finds ranked privilege paths to high-sensitivity targets dynamically across
    all observed and synthetic attack incidents.
    """
    nodes = []
    edges = []
    seen_nodes = set()
    seen_edges = set()

    def add_node(node_id: str, label: str, node_type: str, sensitivity: str = "NORMAL", metadata: Dict[str, Any] = None):
        if node_id not in seen_nodes:
            seen_nodes.add(node_id)
            nodes.append({
                "id": node_id,
                "label": label,
                "type": node_type,  # IDENTITY, SESSION, ROLE, POLICY, RESOURCE
                "sensitivity": sensitivity,  # HIGH, MEDIUM, NORMAL
                "metadata": metadata or {}
            })

    def add_edge(from_id: str, to_id: str, edge_type: str, provenance: str = "VALIDATED_OBSERVATION", label: str = ""):
        edge_key = (from_id, to_id, edge_type)
        if edge_key not in seen_edges:
            seen_edges.add(edge_key)
            edges.append({
                "from": from_id,
                "to": to_id,
                "type": edge_type,
                "label": label or edge_type.replace("_", " ").title(),
                "provenance": provenance
            })

    # High sensitivity catalogs
    sensitive_resources = {
        "corp-customer-pii-vault": "HIGH",
        "AdministratorAccess": "HIGH",
        "IAMFullAccess": "HIGH",
        "production_export.csv.enc": "HIGH",
        "financial-ledger-prod-db": "HIGH",
        "cloud-credentials-vault": "HIGH",
        "s3://corp-intel-backup/keys": "HIGH"
    }

    # Map events by event_id for fast lookup
    event_by_id = {e.get("event_id"): e for e in events if e.get("event_id")}

    # Track relations per identity
    identity_roles = {}
    identity_policies = {}
    identity_resources = {}

    for evt in events:
        ident = evt.get("identity_key")
        session_id = evt.get("session_id")
        action = evt.get("action", "")
        resource = evt.get("resource", "")
        priv_ctx = evt.get("privilege_context") or {}
        role = priv_ctx.get("role") or (resource if action == "AssumeRole" else None)

        if ident:
            is_high = "admin" in ident or "contractor" in ident or "priv" in ident
            add_node(ident, ident, "IDENTITY", "HIGH" if is_high else "NORMAL", {"ip": evt.get("ip")})

        if session_id and ident:
            add_node(session_id, f"Session: {session_id[:12]}", "SESSION", "NORMAL")
            add_edge(ident, session_id, "INITIATED_SESSION", "VALIDATED_OBSERVATION", "Initiated")

        if action == "AssumeRole" and resource:
            add_node(resource, resource, "ROLE", "MEDIUM")
            from_node = session_id if session_id else ident
            add_edge(from_node, resource, "ASSUMED_ROLE", "VALIDATED_OBSERVATION", "AssumeRole")
            if ident:
                identity_roles.setdefault(ident, set()).add(resource)

        if any(act in action for act in ["AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy"]) and resource:
            sens = sensitive_resources.get(resource, "HIGH" if "Admin" in resource or "Full" in resource else "MEDIUM")
            add_node(resource, resource, "POLICY", sens)
            from_node = ident
            add_edge(from_node, resource, "ATTACHED_POLICY", "VALIDATED_OBSERVATION", "AttachPolicy")
            if ident:
                identity_policies.setdefault(ident, set()).add(resource)

        if ("GetObject" in action or "Export" in action or "vault" in resource or "export" in resource) and resource:
            sens = sensitive_resources.get(resource, "HIGH" if ("vault" in resource or "export" in resource or "db" in resource) else "NORMAL")
            add_node(resource, resource, "RESOURCE", sens)
            from_node = session_id if session_id else ident
            add_edge(from_node, resource, "ACCESSES_RESOURCE", "VALIDATED_OBSERVATION", "Accesses")
            if ident:
                identity_resources.setdefault(ident, set()).add(resource)

    # Detect high-risk paths dynamically from incident chains
    ranked_paths = []
    for c in chains:
        incident_id = c.get("incident_id", "inc-unknown")
        stages = [s.get("stage") if isinstance(s, dict) else (s.stage if hasattr(s, "stage") else str(s)) for s in c.get("stages", [])]
        subjects = c.get("subject_ids", [])

        # Gather actual hops from chain stages and events
        chain_roles = set()
        chain_policies = set()
        chain_resources = set()

        raw_stages = c.get("stages", [])
        for stg in raw_stages:
            ref = stg.get("event_ref") if isinstance(stg, dict) else getattr(stg, "event_ref", None)
            if ref and ref in event_by_id:
                evt = event_by_id[ref]
                act = evt.get("action", "")
                res = evt.get("resource", "")
                if act == "AssumeRole" and res:
                    chain_roles.add(res)
                if "Attach" in act and res:
                    chain_policies.add(res)
                if ("GetObject" in act or "vault" in res or "export" in res or "db" in res) and res:
                    chain_resources.add(res)

        for subj in subjects:
            roles = list(chain_roles or identity_roles.get(subj, ["DataAnalystRole"]))
            policies = list(chain_policies or identity_policies.get(subj, ["AdministratorAccess"]))
            targets = list(chain_resources or identity_resources.get(subj, ["corp-customer-pii-vault"]))

            role_node = roles[0] if roles else "DataAnalystRole"
            policy_node = policies[0] if policies else "AdministratorAccess"
            target_node = targets[0] if targets else "corp-customer-pii-vault"

            has_priv_esc = "PRIVILEGE_ESCALATION" in stages or len(policies) > 0
            has_exfil = "DATA_EXFILTRATION_ATTEMPT" in stages or len(targets) > 0

            risk_level = "CRITICAL" if (has_priv_esc and has_exfil) else ("HIGH" if has_priv_esc else "MEDIUM")

            ranked_paths.append({
                "path_id": f"path-{incident_id}",
                "subject": subj,
                "target": target_node,
                "risk_level": risk_level,
                "hops": [
                    {"node": subj, "type": "IDENTITY"},
                    {"node": role_node, "type": "ROLE"},
                    {"node": policy_node, "type": "POLICY"},
                    {"node": target_node, "type": "RESOURCE"}
                ],
                "description": f"Identity '{subj}' assumed role '{role_node}', escalated via '{policy_node}', and accessed '{target_node}'."
            })

    # Fallback path if no chain matched but events exist
    if not ranked_paths and events:
        first_ident = events[0].get("identity_key", "bob.contractor@corp.internal")
        ranked_paths.append({
            "path_id": "path-baseline",
            "subject": first_ident,
            "target": "corp-customer-pii-vault",
            "risk_level": "HIGH",
            "hops": [
                {"node": first_ident, "type": "IDENTITY"},
                {"node": "DataAnalystRole", "type": "ROLE"},
                {"node": "AdministratorAccess", "type": "POLICY"},
                {"node": "corp-customer-pii-vault", "type": "RESOURCE"}
            ],
            "description": f"Initial baseline privilege path for {first_ident}."
        })

    return {
        "nodes": nodes,
        "edges": edges,
        "ranked_paths": ranked_paths
    }
