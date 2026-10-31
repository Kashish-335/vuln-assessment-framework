"""
Integration tests for the Flask Scanner Dashboard and API routes.
"""
import pytest
from dashboard.app import app
from core.database import init_db, SessionLocal
from core.models import Scan, Finding

@pytest.fixture
def client():
    app.config['TESTING'] = True
    init_db()
    with app.test_client() as client:
        yield client

def test_home_page_loads(client):
    response = client.get('/')
    assert response.status_code == 200
    assert b"Web Application Vulnerability Assessment" in response.data
    assert b"target_url" in response.data

def test_start_scan_rejects_unauthorized(client):
    response = client.post('/api/scans/start', data={
        'target_url': 'http://127.0.0.1:3000',
        # authorized missing
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b"Authorization required" in response.data

def test_start_scan_rejects_public_domain(client):
    response = client.post('/api/scans/start', data={
        'target_url': 'https://8.8.8.8',
        'authorized': 'true'
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b"Security Scope Violation" in response.data

def test_start_scan_accepts_valid_localhost(client):
    response = client.post('/api/scans/start', data={
        'target_url': 'http://127.0.0.1:3000',
        'scan_mode': 'direct',
        'authorized': 'true'
    }, follow_redirects=False)
    # Should redirect to /scans/<id>
    assert response.status_code == 302
    assert "/scans/" in response.headers['Location']

def test_scan_status_api(client):
    db = SessionLocal()
    scan = Scan(
        target_url="http://127.0.0.1:3000",
        target_ip="127.0.0.1",
        target_host="127.0.0.1",
        target_port=3000,
        status="running",
        phase="spider",
        progress=45,
        scan_mode="direct",
        authorized=True
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    scan_id = scan.id
    db.close()

    response = client.get(f'/api/scans/{scan_id}/status')
    assert response.status_code == 200
    data = response.get_json()
    assert data['id'] == scan_id
    assert data['progress'] == 45
    assert data['phase'] == 'spider'

def test_pdf_report_download(client):
    db = SessionLocal()
    scan = Scan(
        target_url="http://127.0.0.1:3000",
        target_ip="127.0.0.1",
        target_host="127.0.0.1",
        target_port=3000,
        status="completed",
        phase="completed",
        progress=100,
        scan_mode="direct",
        high_count=1,
        medium_count=0,
        low_count=0,
        info_count=0,
        total_findings=1,
        authorized=True
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    finding = Finding(
        scan_id=scan.id,
        title="Test SQL Injection",
        severity="High",
        confidence="High",
        owasp_category="A03:2021-Injection",
        cwe_id="CWE-89",
        url="http://127.0.0.1:3000/rest/products/search",
        parameter="q",
        attack_payload="' OR '1'='1",
        evidence="HTTP 200 returned all rows",
        description="SQL injection vulnerability test",
        remediation="Use parameterized queries",
        cvss_score=8.8
    )
    db.add(finding)
    db.commit()
    scan_id = scan.id
    db.close()

    response = client.get(f'/scans/{scan_id}/report/pdf')
    assert response.status_code == 200
    assert response.mimetype == 'application/pdf'
    assert len(response.data) > 1000  # Non-empty valid PDF byte stream
