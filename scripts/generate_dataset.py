import argparse
import copy
import hashlib
import json
import math
import os
import random
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, Any, List, Tuple, Set

CITIES = [
    {"city": "Seattle", "country": "US", "lat": 47.6062, "lon": -122.3321},
    {"city": "Austin", "country": "US", "lat": 30.2672, "lon": -97.7431},
    {"city": "New York", "country": "US", "lat": 40.7128, "lon": -74.0060},
    {"city": "London", "country": "GB", "lat": 51.5074, "lon": -0.1278},
    {"city": "Frankfurt", "country": "DE", "lat": 50.1109, "lon": 8.6821},
    {"city": "Tokyo", "country": "JP", "lat": 35.6762, "lon": 139.6503},
    {"city": "Singapore", "country": "SG", "lat": 1.3521, "lon": 103.8198},
    {"city": "Sydney", "country": "AU", "lat": -33.8688, "lon": 151.2093}
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/17.4",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "aws-cli/2.15.15 Python/3.11.8 Windows/10 exe/AMD64",
    "aws-sdk-python/1.34.26 Botocore/1.34.26 Python/3.11.8",
    "aws-sdk-go/v1.44.0"
]

BENIGN_RESOURCES = [
    "corp-dev-builds/artifact.tar.gz",
    "corp-analytics-reports/daily_summary.parquet",
    "corp-marketing-assets/logo.png",
    "corp-doc-templates/standard_sow.docx",
    "corp-infra-tfstate/staging.tfstate"
]

SENSITIVE_RESOURCES = [
    "corp-customer-pii-vault/customers.parquet.enc",
    "corp-financial-records/q3_earnings_draft.xlsx",
    "corp-credentials-vault/prod_db_master_key.json",
    "corp-customer-pii-vault/production_export.csv.enc"
]

IAM_ACTIONS = [
    "AttachUserPolicy",
    "AttachRolePolicy",
    "PutUserPolicy",
    "PutRolePolicy",
    "CreateAccessKey"
]

def sha256_file(filepath: Path) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

def generate_dataset(
    seed: int = 42,
    num_identities: int = 60,
    days: int = 30,
    target_events: int = 5000,
    num_attacks: int = 40,
    noise_level: float = 0.05,
    difficulty: str = "standard",
    output_dir: str = "data/synthetic",
    quick: bool = False
) -> Dict[str, Any]:
    if quick:
        num_identities = 12
        days = 7
        target_events = 250
        num_attacks = 8

    rng = random.Random(seed)
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    base_time = datetime(2026, 10, 1, 8, 0, 0, tzinfo=timezone.utc)
    time_window_seconds = days * 86400

    # 1. Generate Identities Directory
    identities = []
    first_names = ["alex", "jordan", "taylor", "morgan", "casey", "riley", "sam", "cameron", "avery", "quinn", "logan", "dakota", "reese", "skyler", "rowan", "charlie", "diana", "marcus", "elena", "lucas"]
    last_names = ["dev", "analyst", "eng", "contractor", "admin", "lead", "ops", "sec", "finance", "support"]

    id_keys = []
    for i in range(num_identities):
        fn = rng.choice(first_names)
        ln = rng.choice(last_names)
        suffix = f"_{i}" if i >= len(first_names) else ""
        key = f"{fn}.{ln}{suffix}@corp.internal"
        if key in id_keys:
            key = f"{fn}.{ln}_{i}@corp.internal"
        id_keys.append(key)

        clearance = rng.choices([1, 2, 3, 4, 5], weights=[0.45, 0.30, 0.15, 0.08, 0.02])[0]
        is_prot = (clearance >= 4) or ("admin" in ln) or (i == 0)
        identities.append({
            "identity_key": key,
            "roles": [ln],
            "clearance_level": clearance,
            "peer_group": f"group_{ln}",
            "mfa_enforced": True,
            "last_active_ts": (base_time - timedelta(days=rng.uniform(1.0, 45.0))).isoformat().replace("+00:00", "Z"),
            "p95_gap_days": round(rng.uniform(2.0, 14.0), 1),
            "is_protected": is_prot
        })

    # Save identities.json
    id_file = out_path / "identities.json"
    with open(id_file, "w", encoding="utf-8") as f:
        json.dump(identities, f, indent=2)

    # 2. Attack allocation
    # Divide attacks among 6 attack types
    attack_types = [
        "DORMANT_REACTIVATION",
        "TOKEN_ABUSE",
        "PRIVILEGE_ESCALATION",
        "UNUSUAL_API_CALLS",
        "IMPOSSIBLE_TRAVEL",
        "CERT_BINDING_VIOLATION"
    ]
    attack_counts = {at: max(1, num_attacks // len(attack_types)) for at in attack_types}
    rem = num_attacks - sum(attack_counts.values())
    for at in rng.sample(attack_types, max(0, rem)):
        attack_counts[at] += 1

    # Select target attack identities (non-protected for major attacks)
    eligible_attack_ids = [i["identity_key"] for i in identities if not i["is_protected"]]
    if not eligible_attack_ids:
        eligible_attack_ids = [identities[0]["identity_key"]]

    attack_episodes = []
    for at, count in attack_counts.items():
        for _ in range(count):
            target_id = rng.choice(eligible_attack_ids)
            t_offset = rng.uniform(3600, time_window_seconds - 7200)
            attack_episodes.append({
                "attack_type": at,
                "target_identity": target_id,
                "start_time": base_time + timedelta(seconds=t_offset)
            })

    # Sort attack episodes chronologically
    attack_episodes.sort(key=lambda x: x["start_time"])

    # 3. Generate Events & Labels
    okta_events = []
    ct_events = []
    event_labels = {}
    session_labels = {}
    identity_labels = {i["identity_key"]: "BENIGN" for i in identities}
    chains_ground_truth = []

    evt_seq = 1

    # Generate Benign Events
    for i in range(target_events - (len(attack_episodes) * 4)):
        ident_meta = rng.choice(identities)
        ident = ident_meta["identity_key"]
        t = base_time + timedelta(seconds=rng.uniform(0, time_window_seconds))
        ts_str = t.strftime("%Y-%m-%dT%H:%M:%SZ")
        loc = rng.choice(CITIES)
        ip = f"198.51.{rng.randint(1, 254)}.{rng.randint(1, 254)}"
        sess_id = f"sess-{ident[:6]}-{rng.randint(1000, 9999)}"
        session_labels[sess_id] = "BENIGN"

        is_okta = (i % 2 == 0)
        if is_okta:
            eid = f"synth-okta-{evt_seq:06d}"
            evt_seq += 1
            okta_rec = {
                "event_id": eid,
                "published": ts_str,
                "eventType": "user.session.start",
                "actor": {"id": f"usr_{ident[:8]}", "alternateId": ident, "displayName": ident.split("@")[0]},
                "client": {
                    "ipAddress": ip,
                    "geographicalContext": {
                        "city": loc["city"],
                        "country": loc["country"],
                        "latitude": loc["lat"],
                        "longitude": loc["lon"]
                    },
                    "userAgent": rng.choice(USER_AGENTS[:3])
                },
                "outcome": {"result": "SUCCESS", "reason": "MFA passed"},
                "target": [{"id": "app_aws_sso", "displayName": "AWS SSO Portal"}],
                "debugContext": {"session_id": sess_id}
            }
            okta_events.append(okta_rec)
            event_labels[eid] = "BENIGN"
        else:
            eid = f"synth-ct-{evt_seq:06d}"
            evt_seq += 1
            res_name = rng.choice(BENIGN_RESOURCES)
            ct_rec = {
                "event_id": eid,
                "eventTime": ts_str,
                "eventSource": "s3.amazonaws.com",
                "eventName": "GetObject",
                "userIdentity": {
                    "type": "AssumedRole",
                    "principalId": f"AROA_{ident[:6]}:{ident}",
                    "arn": f"arn:aws:sts::123456789012:assumed-role/StandardRole/{ident}",
                    "userName": ident
                },
                "sourceIPAddress": ip,
                "userAgent": rng.choice(USER_AGENTS[3:]),
                "requestParameters": {"bucketName": res_name.split("/")[0], "key": res_name.split("/")[-1]},
                "responseElements": None,
                "errorCode": None
            }
            ct_events.append(ct_rec)
            event_labels[eid] = "BENIGN"

    # Inject Attack Episodes
    for ep_idx, ep in enumerate(attack_episodes):
        at = ep["attack_type"]
        ident = ep["target_identity"]
        identity_labels[ident] = "COMPROMISED"
        t0 = ep["start_time"]
        sess_id = f"sess-atk-{ep_idx:04d}-{ident[:6]}"
        session_labels[sess_id] = "COMPROMISED"
        attacker_ip = f"185.220.{rng.randint(100, 250)}.{rng.randint(1, 254)}"
        loc_tokyo = next(c for c in CITIES if c["city"] == "Tokyo")
        loc_london = next(c for c in CITIES if c["city"] == "London")

        # Step 1: Okta Login Event
        e1_id = f"synth-okta-atk-{ep_idx:04d}-1"
        e1_ts = t0.strftime("%Y-%m-%dT%H:%M:%SZ")
        e1_label = "DORMANT_REACTIVATION" if at == "DORMANT_REACTIVATION" else "BENIGN"
        okta_rec = {
            "event_id": e1_id,
            "published": e1_ts,
            "eventType": "user.session.start",
            "actor": {"id": f"usr_{ident[:8]}", "alternateId": ident, "displayName": ident.split("@")[0]},
            "client": {
                "ipAddress": attacker_ip if at == "DORMANT_REACTIVATION" else "203.0.113.10",
                "geographicalContext": loc_london,
                "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
            },
            "outcome": {"result": "SUCCESS", "reason": "Password authentication"},
            "target": [{"id": "app_aws_sso", "displayName": "AWS SSO Portal"}],
            "debugContext": {"session_id": sess_id}
        }
        okta_events.append(okta_rec)
        event_labels[e1_id] = e1_label

        # Step 2: Second Action (Travel, Token Abuse, or Cert Replay)
        t1 = t0 + timedelta(minutes=15)
        e2_ts = t1.strftime("%Y-%m-%dT%H:%M:%SZ")
        if at == "IMPOSSIBLE_TRAVEL":
            e2_id = f"synth-okta-atk-{ep_idx:04d}-2"
            okta_rec2 = {
                "event_id": e2_id,
                "published": e2_ts,
                "eventType": "user.session.start",
                "actor": {"id": f"usr_{ident[:8]}", "alternateId": ident, "displayName": ident.split("@")[0]},
                "client": {
                    "ipAddress": attacker_ip,
                    "geographicalContext": loc_tokyo, # London -> Tokyo in 15 mins
                    "userAgent": "Mozilla/5.0"
                },
                "outcome": {"result": "SUCCESS", "reason": "Token replay"},
                "target": [{"id": "app_aws_sso", "displayName": "AWS SSO Portal"}],
                "debugContext": {"session_id": f"sess-atk2-{ep_idx:04d}"}
            }
            okta_events.append(okta_rec2)
            event_labels[e2_id] = "IMPOSSIBLE_TRAVEL"
        elif at == "TOKEN_ABUSE":
            e2_id = f"synth-ct-atk-{ep_idx:04d}-2"
            ct_rec2 = {
                "event_id": e2_id,
                "eventTime": e2_ts,
                "eventSource": "sts.amazonaws.com",
                "eventName": "AssumeRole",
                "userIdentity": {"type": "IAMUser", "userName": ident, "arn": f"arn:aws:iam::123:user/{ident}"},
                "sourceIPAddress": attacker_ip, # IP change or automated SDK
                "userAgent": "aws-sdk-go/v1.44.0",
                "requestParameters": {"roleArn": "arn:aws:iam::123:role/DataRole", "roleSessionName": sess_id},
                "responseElements": {"credentials": {"accessKeyId": "ASIA_STOLEN"}},
                "errorCode": None
            }
            ct_events.append(ct_rec2)
            event_labels[e2_id] = "TOKEN_ABUSE"
        elif at == "CERT_BINDING_VIOLATION":
            e2_id = f"synth-ct-atk-{ep_idx:04d}-2"
            ct_rec2 = {
                "event_id": e2_id,
                "eventTime": e2_ts,
                "eventSource": "sts.amazonaws.com",
                "eventName": "AssumeRole",
                "userIdentity": {"type": "IAMUser", "userName": ident, "arn": f"arn:aws:iam::123:user/{ident}"},
                "sourceIPAddress": attacker_ip,
                "userAgent": "aws-sdk-go/v1.44.0",
                "cert_fingerprint": "FA:KE:CE:RT:FP:00:11:22", # Mismatched cert
                "requestParameters": {"roleArn": "arn:aws:iam::123:role/DataRole", "roleSessionName": sess_id},
                "responseElements": {"credentials": {"accessKeyId": "ASIA_STOLEN"}},
                "errorCode": None
            }
            ct_events.append(ct_rec2)
            event_labels[e2_id] = "CERT_BINDING_VIOLATION"
        else:
            e2_id = f"synth-ct-atk-{ep_idx:04d}-2"
            ct_rec2 = {
                "event_id": e2_id,
                "eventTime": e2_ts,
                "eventSource": "sts.amazonaws.com",
                "eventName": "AssumeRole",
                "userIdentity": {"type": "IAMUser", "userName": ident, "arn": f"arn:aws:iam::123:user/{ident}"},
                "sourceIPAddress": attacker_ip,
                "userAgent": "aws-sdk-go/v1.44.0",
                "requestParameters": {"roleArn": "arn:aws:iam::123:role/DataRole", "roleSessionName": sess_id},
                "responseElements": {"credentials": {"accessKeyId": "ASIA_STOLEN"}},
                "errorCode": None
            }
            ct_events.append(ct_rec2)
            event_labels[e2_id] = "BENIGN"

        # Step 3: Privilege Escalation
        t2 = t1 + timedelta(minutes=10)
        e3_id = f"synth-ct-atk-{ep_idx:04d}-3"
        e3_ts = t2.strftime("%Y-%m-%dT%H:%M:%SZ")
        e3_label = "PRIVILEGE_ESCALATION" if at == "PRIVILEGE_ESCALATION" else "BENIGN"
        ct_rec3 = {
            "event_id": e3_id,
            "eventTime": e3_ts,
            "eventSource": "iam.amazonaws.com",
            "eventName": "AttachUserPolicy",
            "userIdentity": {"type": "AssumedRole", "userName": ident, "arn": f"arn:aws:sts::123:assumed-role/DataRole/{sess_id}"},
            "sourceIPAddress": attacker_ip,
            "userAgent": "python-requests/2.28.1",
            "requestParameters": {"userName": ident, "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"},
            "responseElements": None,
            "errorCode": None
        }
        ct_events.append(ct_rec3)
        event_labels[e3_id] = e3_label

        # Step 4: Sensitive API Exfiltration
        t3 = t2 + timedelta(minutes=10)
        e4_id = f"synth-ct-atk-{ep_idx:04d}-4"
        e4_ts = t3.strftime("%Y-%m-%dT%H:%M:%SZ")
        e4_label = "UNUSUAL_API_CALLS" if at == "UNUSUAL_API_CALLS" else "BENIGN"
        ct_rec4 = {
            "event_id": e4_id,
            "eventTime": e4_ts,
            "eventSource": "s3.amazonaws.com",
            "eventName": "GetObject",
            "userIdentity": {"type": "AssumedRole", "userName": ident, "arn": f"arn:aws:sts::123:assumed-role/DataRole/{sess_id}"},
            "sourceIPAddress": attacker_ip,
            "userAgent": "python-requests/2.28.1",
            "requestParameters": {"bucketName": "corp-customer-pii-vault", "key": "production_export.csv.enc"},
            "responseElements": None,
            "errorCode": None
        }
        ct_events.append(ct_rec4)
        event_labels[e4_id] = e4_label

        # Chain ground truth
        chains_ground_truth.append({
            "incident_id": f"inc-synth-atk-{ep_idx:04d}",
            "subject": ident,
            "expected_stages": ["INITIAL_AUTHENTICATION", "SESSION_ASSUMPTION", "PRIVILEGE_ESCALATION", "DATA_EXFILTRATION_ATTEMPT"]
        })

    # Sort raw event files by timestamp
    okta_events.sort(key=lambda x: x["published"])
    ct_events.sort(key=lambda x: x["eventTime"])

    # Write raw Okta
    raw_okta_file = out_path / "raw_okta.jsonl"
    with open(raw_okta_file, "w", encoding="utf-8") as f:
        for ev in okta_events:
            f.write(json.dumps(ev) + "\n")

    # Write raw CloudTrail
    raw_ct_file = out_path / "raw_cloudtrail.jsonl"
    with open(raw_ct_file, "w", encoding="utf-8") as f:
        for ev in ct_events:
            f.write(json.dumps(ev) + "\n")

    # Write separate labels.json
    labels_file = out_path / "labels.json"
    ground_truth_dict = {
        "events": event_labels,
        "identities": identity_labels,
        "sessions": session_labels,
        "chains": chains_ground_truth
    }
    with open(labels_file, "w", encoding="utf-8") as f:
        json.dump(ground_truth_dict, f, indent=2)

    # Write manifest.json
    manifest_file = out_path / "manifest.json"
    manifest = {
        "generator": "scripts/generate_dataset.py",
        "version": "2.0.0",
        "seed": seed,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "config": {
            "num_identities": num_identities,
            "days": days,
            "target_events": len(okta_events) + len(ct_events),
            "num_attacks": num_attacks,
            "noise_level": noise_level,
            "difficulty": difficulty,
            "quick": quick
        },
        "counts": {
            "okta_events": len(okta_events),
            "cloudtrail_events": len(ct_events),
            "total_events": len(okta_events) + len(ct_events),
            "attack_episodes": len(attack_episodes),
            "compromised_identities": sum(1 for v in identity_labels.values() if v == "COMPROMISED"),
            "benign_identities": sum(1 for v in identity_labels.values() if v == "BENIGN")
        },
        "sha256": {
            "raw_okta.jsonl": sha256_file(raw_okta_file),
            "raw_cloudtrail.jsonl": sha256_file(raw_ct_file),
            "labels.json": sha256_file(labels_file),
            "identities.json": sha256_file(id_file)
        }
    }
    with open(manifest_file, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    print(f"Generated synthetic dataset in '{output_dir}':")
    print(f"  - Total Events: {manifest['counts']['total_events']} (Okta: {len(okta_events)}, CT: {len(ct_events)})")
    print(f"  - Attack Episodes: {len(attack_episodes)}")
    print(f"  - Identities: {num_identities} ({manifest['counts']['compromised_identities']} compromised)")
    print(f"  - Manifest written to {manifest_file}")

    return manifest

def main():
    parser = argparse.ArgumentParser(description="Reproducible Synthetic Dataset Generator (Phase 4)")
    parser.add_argument("--seed", type=int, default=42, help="Deterministic random seed")
    parser.add_argument("--identities", type=int, default=60, help="Number of identities to generate")
    parser.add_argument("--days", type=int, default=30, help="Time horizon in days")
    parser.add_argument("--events", type=int, default=5000, help="Target total events")
    parser.add_argument("--attacks", type=int, default=40, help="Number of attack episodes")
    parser.add_argument("--noise", type=float, default=0.05, help="Noise level float")
    parser.add_argument("--difficulty", type=str, default="standard", choices=["standard", "hard"], help="Dataset difficulty")
    parser.add_argument("--output", type=str, default="data/synthetic", help="Output directory")
    parser.add_argument("--quick", action="store_true", help="Generate smaller profile for fast testing")

    args = parser.parse_args()
    generate_dataset(
        seed=args.seed,
        num_identities=args.identities,
        days=args.days,
        target_events=args.events,
        num_attacks=args.attacks,
        noise_level=args.noise,
        difficulty=args.difficulty,
        output_dir=args.output,
        quick=args.quick
    )

if __name__ == "__main__":
    main()

