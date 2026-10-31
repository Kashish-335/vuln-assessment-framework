"""
Mini Web Application Firewall (WAF) Reverse Proxy.
Inspects incoming HTTP traffic for injection, traversal, and malicious patterns,
enforces rate limiting, adds defense-in-depth security headers, and logs attack events.
"""
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import re
import uuid

from flask import Flask, request, Response, render_template, jsonify
import requests

from core.config import Config
from core.database import SessionLocal, init_db
from core.models import WafEvent
from waf.rate_limiter import SlidingWindowRateLimiter

logger = logging.getLogger(__name__)
RULES_FILE = Path(__file__).resolve().parent / 'rules.json'

def load_and_compile_rules():
    """Load and compile regular expressions from rules.json."""
    try:
        with open(RULES_FILE, 'r') as f:
            data = json.load(f)
            rules = []
            for r in data.get('rules', []):
                try:
                    compiled = re.compile(r['pattern'])
                    rules.append({
                        'id': r['id'],
                        'category': r['category'],
                        'name': r['name'],
                        'severity': r.get('severity', 'High'),
                        'description': r.get('description', ''),
                        'regex': compiled,
                        'raw_pattern': r['pattern']
                    })
                except re.error as re_err:
                    logger.error(f"Failed to compile regex for rule {r.get('id')}: {re_err}")
            return rules
    except Exception as e:
        logger.error(f"Could not load WAF rules from {RULES_FILE}: {e}")
        return []

COMPILED_RULES = load_and_compile_rules()
rate_limiter = SlidingWindowRateLimiter(max_requests=Config.WAF_RATE_LIMIT_RPM, window_seconds=60)

app = Flask(__name__, template_folder='templates')
app.config.from_object(Config)

def inspect_value(value: str, location: str):
    """
    Test a string value against all compiled WAF rules.
    Returns matched rule dict or None.
    """
    if not isinstance(value, str) or not value:
        return None

    for rule in COMPILED_RULES:
        if rule['regex'].search(value):
            return {
                'rule': rule,
                'location': location,
                'matched_text': value[:200]
            }
    return None

def inspect_recursive(data, location_prefix="data"):
    """Recursively check dictionaries, lists, and strings against rules."""
    if isinstance(data, dict):
        for k, v in data.items():
            hit = inspect_value(str(k), f"{location_prefix}_key")
            if hit:
                return hit
            hit = inspect_recursive(v, f"{location_prefix}[{k}]")
            if hit:
                return hit
    elif isinstance(data, list):
        for idx, item in enumerate(data):
            hit = inspect_recursive(item, f"{location_prefix}[{idx}]")
            if hit:
                return hit
    elif isinstance(data, str):
        return inspect_value(data, location_prefix)
    return None

def log_waf_attack(client_ip, attack_type, rule_id, rule_desc, pattern, method, url, location, payload, user_agent, action='BLOCKED_403'):
    """Persist an attack event into SQLite database."""
    db = SessionLocal()
    try:
        event = WafEvent(
            timestamp=datetime.now(timezone.utc),
            client_ip=client_ip,
            attack_type=attack_type,
            rule_id=rule_id,
            rule_description=rule_desc,
            matched_pattern=pattern,
            http_method=method,
            request_url=url,
            location=location,
            payload_snippet=payload[:500] if payload else '',
            user_agent=user_agent[:300] if user_agent else '',
            action=action
        )
        db.add(event)
        db.commit()
    except Exception as e:
        logger.error(f"Failed to log WAF event to DB: {e}")
    finally:
        db.close()

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'healthy',
        'service': 'Mini WAF Reverse Proxy',
        'rules_loaded': len(COMPILED_RULES),
        'upstream': Config.UPSTREAM_TARGET_URL
    })

@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'])
def reverse_proxy_waf(path):
    """
    Main WAF inspection and reverse-proxy handler.
    """
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr or '127.0.0.1')

    # 1. Rate Limiting Check
    allowed, retry_after = rate_limiter.is_allowed(client_ip)
    if not allowed:
        log_waf_attack(
            client_ip=client_ip,
            attack_type="RateLimit",
            rule_id="RATE_LIMIT_EXCEEDED",
            rule_desc=f"Exceeded threshold of {Config.WAF_RATE_LIMIT_RPM} requests/minute",
            pattern="N/A",
            method=request.method,
            url=request.url,
            location="ip",
            payload=f"Rapid requests from {client_ip}",
            user_agent=request.headers.get('User-Agent', ''),
            action="RATE_LIMITED_429"
        )
        resp = Response(
            json.dumps({"error": "Too Many Requests", "retry_after": retry_after}),
            status=429,
            mimetype="application/json"
        )
        resp.headers['Retry-After'] = str(retry_after)
        return resp

    # 2. Deep Payload Inspection
    hit = None

    # Inspect URI Path & Query string
    hit = inspect_value(request.path, 'path')
    if not hit and request.query_string:
        hit = inspect_value(request.query_string.decode('utf-8', errors='ignore'), 'query_string')

    # Inspect Query Args
    if not hit:
        for k, v in request.args.items():
            hit = inspect_value(v, f"query_param:{k}")
            if hit:
                break

    # Inspect Headers (User-Agent, Referer)
    if not hit:
        for hdr in ('User-Agent', 'Referer'):
            val = request.headers.get(hdr)
            if val:
                hit = inspect_value(val, f"header:{hdr}")
                if hit:
                    break

    # Inspect Cookies
    if not hit:
        for c_name, c_val in request.cookies.items():
            hit = inspect_value(c_val, f"cookie:{c_name}")
            if hit:
                break

    # Inspect Body (JSON, Form, Raw text)
    if not hit:
        if request.is_json:
            try:
                body_json = request.get_json(silent=True)
                if body_json:
                    hit = inspect_recursive(body_json, 'json_body')
            except Exception:
                pass
        elif request.form:
            for f_key, f_val in request.form.items():
                hit = inspect_value(f_val, f"form_data:{f_key}")
                if hit:
                    break
        else:
            raw_data = request.get_data(as_text=True)
            if raw_data:
                hit = inspect_value(raw_data, 'raw_body')

    # 3. Action on Match: Block with 403 Forbidden
    if hit:
        rule = hit['rule']
        incident_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
        timestamp_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

        log_waf_attack(
            client_ip=client_ip,
            attack_type=rule['category'],
            rule_id=rule['id'],
            rule_desc=rule['description'],
            pattern=rule['raw_pattern'],
            method=request.method,
            url=request.url,
            location=hit['location'],
            payload=hit['matched_text'],
            user_agent=request.headers.get('User-Agent', ''),
            action='BLOCKED_403'
        )

        return render_template(
            'blocked.html',
            incident_id=incident_id,
            attack_type=rule['category'],
            rule_name=rule['name'],
            rule_id=rule['id'],
            client_ip=client_ip,
            timestamp=timestamp_str,
            payload_sample=hit['matched_text']
        ), 403

    # 4. Forward Safe Request to Upstream
    upstream_base = Config.UPSTREAM_TARGET_URL.rstrip('/')
    upstream_url = f"{upstream_base}/{path}"
    if request.query_string:
        upstream_url += f"?{request.query_string.decode('utf-8', errors='ignore')}"

    # Prepare forwarding headers
    excluded_headers = {'host', 'content-length', 'content-encoding', 'transfer-encoding', 'connection'}
    forward_headers = {k: v for k, v in request.headers.items() if k.lower() not in excluded_headers}
    forward_headers['X-Forwarded-For'] = client_ip
    forward_headers['X-Forwarded-Host'] = request.host

    try:
        upstream_resp = requests.request(
            method=request.method,
            url=upstream_url,
            headers=forward_headers,
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False,
            timeout=5.0
        )

        # Build client response
        client_response = Response(
            upstream_resp.content,
            status=upstream_resp.status_code,
            headers=dict(upstream_resp.headers)
        )
    except requests.exceptions.ConnectionError:
        # Graceful fallback when upstream application is not currently active
        mock_body = (
            f"<html><head><title>Mini WAF Gateway</title></head>"
            f"<body style='font-family:sans-serif;padding:30px;background:#f8fafc;color:#1e293b;'>"
            f"<h2>Mini WAF Gateway Active</h2>"
            f"<p>Request successfully inspected and passed by WAF rules.</p>"
            f"<p><b>Notice:</b> Upstream target at <code>{Config.UPSTREAM_TARGET_URL}</code> is currently offline or unreachable.</p>"
            f"<hr/><small>Status: 200 OK (WAF Pass-Through Mode)</small>"
            f"</body></html>"
        )
        client_response = Response(mock_body, status=200, mimetype='text/html')
    except Exception as e:
        return Response(f"WAF Proxy Gateway Error: {str(e)}", status=502)

    # 5. Inject Defense-in-Depth Security Headers
    client_response.headers['Content-Security-Policy'] = "default-src 'self' 'unsafe-inline' 'unsafe-eval' https: data: blob:;"
    client_response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    client_response.headers['X-Content-Type-Options'] = 'nosniff'
    client_response.headers['X-XSS-Protection'] = '1; mode=block'
    client_response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    client_response.headers['X-WAF-Protected-By'] = 'Mini-WAF-v1.0'

    # Remove hop-by-hop headers from response
    for h in ['content-encoding', 'transfer-encoding', 'connection']:
        client_response.headers.pop(h, None)

    return client_response

if __name__ == '__main__':
    init_db()
    print(f"[*] Starting Mini WAF on port {Config.WAF_PORT}...")
    print(f"[*] Upstream Target: {Config.UPSTREAM_TARGET_URL}")
    app.run(host='0.0.0.0', port=Config.WAF_PORT, debug=False)
