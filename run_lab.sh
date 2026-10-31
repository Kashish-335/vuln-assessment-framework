#!/usr/bin/env bash
# ==============================================================================
# Academic Vulnerability Assessment Framework & Mini WAF Orchestration Script
# ==============================================================================
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "$DIR"

# Ensure venv exists
if [ ! -d "venv" ]; then
    echo "[!] Virtual environment not found. Creating venv..."
    python3 -m venv venv
    ./venv/bin/pip install -r requirements.txt
fi

PYTHON="./venv/bin/python"

# Ensure local .env exists for execution
if [ ! -f ".env" ]; then
    echo "[!] Local .env configuration file not found."
    if [ -f ".env.example" ]; then
        echo "[*] Initializing local .env from .env.example with secure generated secrets..."
        cp .env.example .env
        $PYTHON -c "
import secrets
with open('.env', 'r') as f:
    content = f.read()
content = content.replace('your-generated-secret-key-here', secrets.token_hex(32))
content = content.replace('your-secure-zap-api-key-here', secrets.token_hex(16))
with open('.env', 'w') as f:
    f.write(content)
"
        echo "[✓] Local .env created with fresh secrets (never committed to git)."
    fi
fi

# Initialize database
$PYTHON -c "from core.database import init_db; init_db(); print('[✓] SQLite database initialized successfully.')"

MODE="${1:-all}"

case "$MODE" in
    dashboard)
        echo "[*] Starting Vulnerability Scanner Dashboard on http://localhost:5000..."
        exec $PYTHON dashboard/app.py
        ;;
    waf)
        echo "[*] Starting Mini WAF Reverse Proxy on http://localhost:8080..."
        echo "[*] Forwarding legitimate requests to http://localhost:3000..."
        exec $PYTHON waf/waf_proxy.py
        ;;
    test)
        echo "[*] Running comprehensive academic test suite..."
        exec ./venv/bin/pytest tests/ -v
        ;;
    seed)
        echo "[*] Generating Baseline and WAF assessment datasets..."
        $PYTHON -c "
from core.database import SessionLocal, init_db
from core.models import Scan, Finding, WafEvent
from dashboard.scanner import execute_scan_task
from datetime import datetime, timezone
import json

init_db()
db = SessionLocal()

# 1. Direct Baseline Scan
scan_direct = Scan(
    target_url='http://127.0.0.1:3000',
    target_ip='127.0.0.1',
    target_host='127.0.0.1',
    target_port=3000,
    status='pending',
    phase='initializing',
    scan_mode='direct',
    authorized=True,
    started_at=datetime.now(timezone.utc)
)
db.add(scan_direct)
db.commit()
db.refresh(scan_direct)
print(f'[*] Executing baseline scan #{scan_direct.id} against direct target (:3000)...')
execute_scan_task(scan_direct.id)

# 2. WAF Protected Scan
scan_waf = Scan(
    target_url='http://127.0.0.1:8080',
    target_ip='127.0.0.1',
    target_host='127.0.0.1',
    target_port=8080,
    status='pending',
    phase='initializing',
    scan_mode='waf_protected',
    authorized=True,
    started_at=datetime.now(timezone.utc)
)
db.add(scan_waf)
db.commit()
db.refresh(scan_waf)
print(f'[*] Executing protected scan #{scan_waf.id} against WAF target (:8080)...')
execute_scan_task(scan_waf.id)

# 3. Simulate WAF blocked attacks for telemetry
attacks = [
    ('SQLi', 'SQLI_001', 'SQL Injection - Tautology Bypass', \"' OR '1'='1\", '/rest/products/search?q=\' OR \'1\'=\'1'),
    ('SQLi', 'SQLI_002', 'SQL Injection - UNION SELECT', 'UNION SELECT 1,2,3', '/search?q=UNION SELECT 1,2,3'),
    ('XSS', 'XSS_001', 'Cross-Site Scripting - Script Tag', '<script>alert(1)</script>', '/api/feedback'),
    ('PathTraversal', 'TRAV_001', 'Path Traversal - Dot-Dot-Slash', '../../../../etc/passwd', '/ftp?file=../../../../etc/passwd'),
    ('CommandInjection', 'CMDI_001', 'OS Command Injection', '; id', '/api/diag'),
    ('RateLimit', 'RATE_LIMIT_EXCEEDED', 'Rate Limit Exceeded', 'Burst 60 requests/min', '/rest/products/search')
]

for atype, rid, rdesc, payload, url in attacks:
    ev = WafEvent(
        timestamp=datetime.now(timezone.utc),
        client_ip='127.0.0.1',
        attack_type=atype,
        rule_id=rid,
        rule_description=rdesc,
        matched_pattern=payload,
        http_method='GET',
        request_url=url,
        location='query',
        payload_snippet=payload,
        user_agent='Mozilla/5.0 (Macintosh; Intel Mac OS X)',
        action='BLOCKED_403' if atype != 'RateLimit' else 'RATE_LIMITED_429'
    )
    db.add(ev)

db.commit()
db.close()
print('[✓] Seeding complete! Launch ./run_lab.sh all to view comparison and telemetry.')
"
        ;;
    all)
        echo "================================================================="
        echo "  Automated Web App Vulnerability Assessment & Mini WAF Suite"
        echo "================================================================="
        echo "  [1] Mini WAF Reverse Proxy:      http://localhost:8080"
        echo "  [2] Scanner Web Dashboard:       http://localhost:5000"
        echo "  [3] Mini WAF Telemetry & Logs:   http://localhost:5000/waf-admin"
        echo "  [4] Before/After Mitigation:     http://localhost:5000/compare"
        echo "================================================================="
        echo "[*] Launching Mini WAF (PID background)..."
        $PYTHON waf/waf_proxy.py &
        WAF_PID=$!
        trap "echo '[*] Stopping WAF and Dashboard...'; kill $WAF_PID 2>/dev/null || true; exit 0" INT TERM EXIT

        sleep 1
        echo "[*] Launching Scanner Dashboard on port 5000..."
        $PYTHON dashboard/app.py
        ;;
    *)
        echo "Usage: ./run_lab.sh [all|dashboard|waf|test|seed]"
        exit 1
        ;;
esac
