"""
Scanner Dashboard Flask Web Application.
Provides interactive assessment launchpad, real-time scan progress,
results visualization with Chart.js, PDF report downloads,
WAF telemetry monitoring, and Before/After mitigation comparison.
"""
from datetime import datetime, timezone
import json
import logging
from pathlib import Path

from flask import (
    Flask, render_template, request, redirect, url_for,
    jsonify, flash, send_file, abort
)

from core.config import Config
from core.database import SessionLocal, init_db
from core.models import Scan, Finding, WafEvent
from core.validator import validate_target
from dashboard.scanner import start_background_scan
from reports.generator import generate_pdf_report

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__, template_folder='templates', static_folder='static')
app.config.from_object(Config)

# Ensure a secure secret key is set for session and flash signing
if not app.config.get('SECRET_KEY'):
    if app.config.get('TESTING'):
        app.config['SECRET_KEY'] = 'test-secret-key-for-testing-only'
    else:
        import secrets
        logger.warning("SECRET_KEY environment variable not set. Generating a dynamic ephemeral secret key. Set SECRET_KEY in .env for persistent sessions.")
        app.config['SECRET_KEY'] = secrets.token_hex(32)

# Jinja custom filter for parsing JSON strings in templates
@app.template_filter('from_json')
def from_json_filter(val):
    if not val:
        return {}
    if isinstance(val, dict):
        return val
    try:
        return json.loads(val)
    except Exception:
        return {}

@app.route('/')
def index():
    """Home landing page with target launcher and safety validation."""
    return render_template('index.html')

@app.route('/api/scans/start', methods=['POST'])
def start_scan():
    """
    Validate target and start background vulnerability scan.
    """
    target_url = request.form.get('target_url', '').strip()
    scan_mode = request.form.get('scan_mode', 'direct')
    authorized = request.form.get('authorized') in ('true', '1', 'on', 'yes')

    # Enforce strict scope & ethical rules
    is_valid, error_msg, target_info = validate_target(target_url, authorized_acknowledged=authorized)
    if not is_valid:
        flash(f"Scan Request Blocked: {error_msg}", "danger")
        return redirect(url_for('index'))

    db = SessionLocal()
    try:
        scan = Scan(
            target_url=target_info['clean_url'],
            target_ip=target_info['ip'],
            target_host=target_info['hostname'],
            target_port=target_info['port'],
            status='pending',
            phase='initializing',
            progress=5,
            scan_mode=scan_mode,
            authorized=True,
            started_at=datetime.now(timezone.utc)
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        scan_id = scan.id

        # Spawn background scanner thread
        start_background_scan(scan_id)
        return redirect(url_for('scan_progress', scan_id=scan_id))

    except Exception as e:
        logger.error(f"Failed to create scan: {e}")
        flash(f"Failed to initiate scan: {str(e)}", "danger")
        return redirect(url_for('index'))
    finally:
        db.close()

@app.route('/scans/<int:scan_id>')
def scan_progress(scan_id):
    """Live progress page with step tracker and log stream."""
    db = SessionLocal()
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    db.close()
    if not scan:
        abort(404, "Scan record not found")

    if scan.status == 'completed':
        return redirect(url_for('scan_results', scan_id=scan_id))

    return render_template('scan_progress.html', scan=scan)

@app.route('/api/scans/<int:scan_id>/status')
def api_scan_status(scan_id):
    """JSON API endpoint returning live progress percentage, phase, and status."""
    db = SessionLocal()
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    db.close()
    if not scan:
        return jsonify({'error': 'Scan not found'}), 404

    return jsonify({
        'id': scan.id,
        'status': scan.status,
        'phase': scan.phase,
        'progress': scan.progress,
        'high_count': scan.high_count,
        'medium_count': scan.medium_count,
        'low_count': scan.low_count,
        'info_count': scan.info_count,
        'total_findings': scan.total_findings,
        'error_message': scan.error_message
    })

@app.route('/scans/<int:scan_id>/results')
def scan_results(scan_id):
    """Detailed results dashboard with Chart.js charts and findings table."""
    db = SessionLocal()
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        db.close()
        abort(404, "Scan record not found")

    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    db.close()
    return render_template('scan_results.html', scan=scan, findings=findings)

@app.route('/scans')
def scan_history():
    """List of all historical vulnerability assessment scans."""
    db = SessionLocal()
    scans = db.query(Scan).order_by(Scan.id.desc()).all()
    db.close()
    return render_template('scan_history.html', scans=scans)

@app.route('/scans/<int:scan_id>/report/pdf')
def download_pdf(scan_id):
    """Generate and stream the executive PDF report."""
    db = SessionLocal()
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        db.close()
        abort(404, "Scan record not found")

    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    db.close()

    pdf_buffer = generate_pdf_report(scan, findings)
    filename = f"Vulnerability_Report_Scan_{scan.id}_{scan.target_host}.pdf"

    return send_file(
        pdf_buffer,
        mimetype='application/pdf',
        as_attachment=True,
        download_name=filename
    )

@app.route('/compare')
def comparison_view():
    """
    Before vs After WAF defense comparison view.
    Compares Direct Target (:3000) scan against WAF Target (:8080) scan.
    """
    db = SessionLocal()
    all_scans = db.query(Scan).filter(Scan.status == 'completed').order_by(Scan.id.desc()).all()

    direct_id = request.args.get('direct_scan_id', type=int)
    waf_id = request.args.get('waf_scan_id', type=int)

    # Automatically select most relevant scans if not explicitly provided
    if not direct_id:
        for s in all_scans:
            if s.scan_mode == 'direct' or s.target_port == 3000:
                direct_id = s.id
                break

    if not waf_id:
        for s in all_scans:
            if s.scan_mode == 'waf_protected' or s.target_port == Config.WAF_PORT:
                waf_id = s.id
                break

    direct_scan = db.query(Scan).filter(Scan.id == direct_id).first() if direct_id else None
    waf_scan = db.query(Scan).filter(Scan.id == waf_id).first() if waf_id else None

    diff_results = []
    if direct_scan and waf_scan:
        direct_findings = db.query(Finding).filter(Finding.scan_id == direct_scan.id).all()
        waf_findings = db.query(Finding).filter(Finding.scan_id == waf_scan.id).all()

        waf_cwe_set = {f.cwe_id for f in waf_findings}

        for df in direct_findings:
            is_mitigated = df.cwe_id not in waf_cwe_set
            defense_mech = "Neutralized by Mini WAF inspection engine."
            if "89" in df.cwe_id:
                defense_mech = "WAF SQLi rule matched payload and returned HTTP 403 Forbidden."
            elif "79" in df.cwe_id:
                defense_mech = "WAF XSS rule filtered HTML tags/event handlers with HTTP 403."
            elif "22" in df.cwe_id:
                defense_mech = "WAF Path Traversal rule blocked relative '../' paths with HTTP 403."
            elif "78" in df.cwe_id:
                defense_mech = "WAF Command Injection rule intercepted shell operators with HTTP 403."
            elif "693" in df.cwe_id:
                defense_mech = "Mini WAF middleware injected CSP, X-Frame-Options, and nosniff headers."

            diff_results.append({
                'title': df.title,
                'cwe_id': df.cwe_id,
                'direct_severity': df.severity,
                'mitigated': is_mitigated,
                'waf_severity': 'Mitigated' if is_mitigated else 'Residual',
                'defense_mechanism': defense_mech
            })

    db.close()
    return render_template(
        'comparison.html',
        all_scans=all_scans,
        direct_scan=direct_scan,
        waf_scan=waf_scan,
        diff_results=diff_results
    )

@app.route('/waf-admin')
def waf_admin():
    """WAF dashboard displaying attack event telemetry and rules catalog."""
    db = SessionLocal()
    events = db.query(WafEvent).order_by(WafEvent.id.desc()).limit(50).all()
    total_events = db.query(WafEvent).count()

    # Category counts
    sqli_count = db.query(WafEvent).filter(WafEvent.attack_type == 'SQLi').count()
    xss_count = db.query(WafEvent).filter(WafEvent.attack_type == 'XSS').count()
    trav_count = db.query(WafEvent).filter(WafEvent.attack_type == 'PathTraversal').count()
    cmdi_count = db.query(WafEvent).filter(WafEvent.attack_type == 'CommandInjection').count()
    rate_count = db.query(WafEvent).filter(WafEvent.attack_type == 'RateLimit').count()
    db.close()

    # Load rules catalog
    rules_path = Path(__file__).resolve().parent.parent / 'waf' / 'rules.json'
    rules = []
    try:
        with open(rules_path, 'r') as f:
            rules = json.load(f).get('rules', [])
    except Exception as e:
        logger.error(f"Failed to load rules: {e}")

    return render_template(
        'waf_admin.html',
        events=events,
        total_events=total_events,
        sqli_count=sqli_count,
        xss_count=xss_count,
        trav_count=trav_count,
        cmdi_count=cmdi_count,
        rate_count=rate_count,
        rules=rules
    )

if __name__ == '__main__':
    init_db()
    print(f"[*] Starting Vulnerability Assessment Dashboard on port {Config.DASHBOARD_PORT}...")
    app.run(host='0.0.0.0', port=Config.DASHBOARD_PORT, debug=Config.DEBUG)
