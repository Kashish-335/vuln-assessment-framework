"""
End-to-End integration tests for Mini WAF Reverse Proxy middleware.
"""
import pytest
from waf.waf_proxy import app as waf_app
from core.database import init_db, SessionLocal
from core.models import WafEvent

@pytest.fixture
def waf_client():
    waf_app.config['TESTING'] = True
    init_db()
    with waf_app.test_client() as client:
        yield client

def test_waf_blocks_sqli_query(waf_client):
    res = waf_client.get("/rest/products/search?q=' OR '1'='1")
    assert res.status_code == 403
    assert b"403 Forbidden" in res.data
    assert b"Malicious Request Blocked by Mini WAF" in res.data
    assert b"SQLi" in res.data

def test_waf_blocks_xss_form(waf_client):
    res = waf_client.post("/api/feedback", data={"comment": "<script>alert(1)</script>"})
    assert res.status_code == 403
    assert b"XSS" in res.data

def test_waf_blocks_path_traversal(waf_client):
    res = waf_client.get("/ftp?file=../../../../etc/passwd")
    assert res.status_code == 403
    assert b"PathTraversal" in res.data

def test_waf_blocks_command_injection(waf_client):
    res = waf_client.post("/api/diag", data={"ip": "; id"})
    assert res.status_code == 403
    assert b"CommandInjection" in res.data

def test_waf_allows_safe_request_and_injects_security_headers(waf_client):
    res = waf_client.get("/rest/products/search?q=apple-juice")
    # In test mode with upstream offline, WAF returns 200 WAF Pass-Through Mode
    assert res.status_code == 200
    assert "Content-Security-Policy" in res.headers
    assert res.headers.get("X-Frame-Options") == "SAMEORIGIN"
    assert res.headers.get("X-Content-Type-Options") == "nosniff"
    assert res.headers.get("X-WAF-Protected-By") == "Mini-WAF-v1.0"

def test_waf_logs_events_to_db(waf_client):
    db = SessionLocal()
    initial_count = db.query(WafEvent).count()
    db.close()

    waf_client.get("/search?q=UNION SELECT 1,2,3")

    db = SessionLocal()
    new_count = db.query(WafEvent).count()
    latest_event = db.query(WafEvent).order_by(WafEvent.id.desc()).first()
    db.close()

    assert new_count == initial_count + 1
    assert latest_event.attack_type == "SQLi"
    assert latest_event.action == "BLOCKED_403"
