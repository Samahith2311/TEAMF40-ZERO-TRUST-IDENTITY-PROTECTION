import datetime
import hashlib
import json
from pathlib import Path
from typing import Dict, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

CERTS_DIR = Path("certs")

def compute_fingerprint(cert: x509.Certificate) -> str:
    """Returns colon-separated lowercase SHA-256 fingerprint."""
    der_bytes = cert.public_bytes(serialization.Encoding.DER)
    raw_hex = hashlib.sha256(der_bytes).hexdigest().lower()
    return ":".join(raw_hex[i:i+2] for i in range(0, len(raw_hex), 2))

def generate_ca() -> Tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ZeroTrust Internal Security"),
        x509.NameAttribute(NameOID.COMMON_NAME, "ZeroTrust Local Development CA"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=90))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert

def generate_signed_cert(
    common_name: str,
    ca_key: ec.EllipticCurvePrivateKey,
    ca_cert: x509.Certificate,
    is_server: bool = False,
    san_list: list = None
) -> Tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ZeroTrust Local"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    )

    if is_server and san_list:
        san_names = []
        for name in san_list:
            if name.replace(".", "").isdigit():
                import ipaddress
                san_names.append(x509.IPAddress(ipaddress.IPv4Address(name)))
            else:
                san_names.append(x509.DNSName(name))
        builder = builder.add_extension(x509.SubjectAlternativeName(san_names), critical=False)

    cert = builder.sign(ca_key, hashes.SHA256())
    return key, cert

def save_pem(path: Path, data: bytes):
    with open(path, "wb") as f:
        f.write(data)

def main():
    CERTS_DIR.mkdir(parents=True, exist_ok=True)
    print("Generating local development mTLS PKI materials...")

    # 1. CA
    ca_key, ca_cert = generate_ca()
    save_pem(CERTS_DIR / "ca.key", ca_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))
    save_pem(CERTS_DIR / "ca.crt", ca_cert.public_bytes(serialization.Encoding.PEM))
    print(f"[CA] Created CA cert: {CERTS_DIR / 'ca.crt'} (Fingerprint: {compute_fingerprint(ca_cert)})")

    # 2. Server Cert (localhost, 127.0.0.1)
    srv_key, srv_cert = generate_signed_cert(
        "localhost", ca_key, ca_cert, is_server=True, san_list=["localhost", "127.0.0.1"]
    )
    save_pem(CERTS_DIR / "server.key", srv_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))
    save_pem(CERTS_DIR / "server.crt", srv_cert.public_bytes(serialization.Encoding.PEM))
    print(f"[Server] Created server cert: {CERTS_DIR / 'server.crt'}")

    # 3. Client Cert 1 (Legitimate User Alice)
    c1_key, c1_cert = generate_signed_cert("alice@corp.internal", ca_key, ca_cert)
    save_pem(CERTS_DIR / "client_alice.key", c1_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))
    save_pem(CERTS_DIR / "client_alice.crt", c1_cert.public_bytes(serialization.Encoding.PEM))
    fp_alice = compute_fingerprint(c1_cert)
    print(f"[Client 1] Alice cert: {CERTS_DIR / 'client_alice.crt'} | Fingerprint: {fp_alice}")

    # 4. Client Cert 2 (Legitimate User Bob)
    c2_key, c2_cert = generate_signed_cert("bob.contractor@corp.internal", ca_key, ca_cert)
    save_pem(CERTS_DIR / "client_bob.key", c2_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))
    save_pem(CERTS_DIR / "client_bob.crt", c2_cert.public_bytes(serialization.Encoding.PEM))
    fp_bob = compute_fingerprint(c2_cert)
    print(f"[Client 2] Bob cert: {CERTS_DIR / 'client_bob.crt'} | Fingerprint: {fp_bob}")

    # 5. Attacker / Replay Client Cert
    atk_key, atk_cert = generate_signed_cert("attacker.replayer@external.net", ca_key, ca_cert)
    save_pem(CERTS_DIR / "client_attacker.key", atk_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))
    save_pem(CERTS_DIR / "client_attacker.crt", atk_cert.public_bytes(serialization.Encoding.PEM))
    fp_atk = compute_fingerprint(atk_cert)
    print(f"[Attacker] Replay cert: {CERTS_DIR / 'client_attacker.crt'} | Fingerprint: {fp_atk}")

    # Manifest
    fingerprints = {
        "ca": compute_fingerprint(ca_cert),
        "server": compute_fingerprint(srv_cert),
        "alice": fp_alice,
        "bob": fp_bob,
        "attacker": fp_atk
    }
    with open(CERTS_DIR / "fingerprints.json", "w", encoding="utf-8") as f:
        json.dump(fingerprints, f, indent=2)

    print(f"\nAll certificates generated successfully in '{CERTS_DIR}'.")
    return fingerprints

if __name__ == "__main__":
    main()
