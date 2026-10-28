import pytest
from pathlib import Path
from fastapi.testclient import TestClient
from src.api import app

def test_no_dangerously_set_inner_html_in_frontend():
    """Security rule: Frontend must not contain dangerouslySetInnerHTML."""
    src_dir = Path("web/src")
    found = False
    for p in src_dir.rglob("*.tsx"):
        content = p.read_text(encoding="utf-8")
        if "dangerouslySetInnerHTML" in content:
            found = True
            break
    assert found is False

def test_api_endpoints_read_only():
    """FastAPI test: Verifies alerts, chains, scores endpoints respond with 200."""
    client = TestClient(app)
    r1 = client.get("/api/alerts")
    assert r1.status_code == 200
    assert "alerts" in r1.json()

    r2 = client.get("/api/chains")
    assert r2.status_code == 200
    assert "chains" in r2.json()

    r3 = client.get("/api/scores")
    assert r3.status_code == 200
    assert "scores" in r3.json()

def test_api_security_headers():
    """Security test: Strict CSP and security headers must be present."""
    client = TestClient(app)
    resp = client.get("/api/health")
    assert "Content-Security-Policy" in resp.headers
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
