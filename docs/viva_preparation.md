# College Viva & Presentation Preparation Guide

## Project Title
**Automated Web Application Vulnerability Assessment Framework with Scanner Dashboard and Mini WAF**

---

## 1. Project Elevator Pitch (30-Second Summary)

> *"This project is an end-to-end web application security assessment and defense framework built for isolated lab environments. On the offensive side, it orchestrates network reconnaissance with Nmap and dynamic application security testing (DAST) via OWASP ZAP, automatically classifying vulnerabilities against the OWASP Top 10 (2021) and CWE standards, and generating professional PDF audit reports. On the defensive side, it implements a reverse-proxy Mini WAF that inspects HTTP traffic, neutralizes SQL injection, XSS, path traversal, and command injection attacks with HTTP 403 Forbidden pages, injects defense-in-depth security headers, and provides live Before-vs-After mitigation analytics demonstrating quantifiable risk reduction."*

---

## 2. Comprehensive Viva Q&A Cheat Sheet

### Q1: What is DAST and how does it differ from SAST?
- **DAST (Dynamic Application Security Testing)**: Tests a running application from the outside in (black-box / gray-box). It sends crafted HTTP requests to live endpoints and analyzes responses for behavioral evidence of vulnerabilities. It identifies runtime misconfigurations, authentication flaws, and environmental issues.
- **SAST (Static Application Security Testing)**: Analyzes source code or byte-code from the inside out (white-box) without running the application. It highlights exact source code lines but cannot detect runtime or environmental misconfigurations and tends to produce higher false-positive rates.

### Q2: What is the difference between a Vulnerability Scanner and a Web Application Firewall (WAF)?
- **Scanner (Offensive / Auditing)**: Discovers, catalogs, and reports vulnerabilities in applications. It does not alter or protect traffic; it informs developers of needed fixes.
- **WAF (Defensive / Middleware)**: Acts as a protective reverse-proxy layer in front of the web application. It inspects incoming HTTP traffic in real time, actively blocking malicious requests before they reach the vulnerable code.

### Q3: Explain how your Mini WAF reverse-proxy operates.
- The WAF listens on port `8080` while the target application resides on port `3000`.
- Incoming client requests pass through a pipeline:
  1. **Rate Limiting**: Sliding window checking if the client IP exceeded 60 requests/minute.
  2. **Deep Inspection**: Recursively checks query strings, form data, JSON bodies, raw payloads, headers (`User-Agent`, `Referer`), and cookies against compiled regular expressions from `rules.json`.
  3. **Decision**: If a rule matches, the WAF immediately returns HTTP `403 Forbidden` with a custom security intercept page, and logs the incident to the SQLite database.
  4. **Pass-Through & Hardening**: If clean, the request is forwarded to port 3000, and the response is hardened with `Content-Security-Policy`, `X-Frame-Options: SAMEORIGIN`, and `X-Content-Type-Options: nosniff`.

### Q4: What is a Positive Security Model vs a Negative Security Model? Which does this WAF use?
- **Negative Security Model (Blacklist / Signature-based)**: Defines what is *prohibited* (e.g., regexes matching `' OR '1'='1` or `<script>`). Everything not matching a signature is permitted. This Mini WAF primarily employs a negative model for rapid attack detection.
- **Positive Security Model (Whitelist / Specification-based)**: Defines what is *allowed* (e.g., parameter `age` must be an integer between 1 and 120). Everything else is blocked.
- *Viva Tip*: In enterprise production, hybrid models (ModSecurity Core Rule Set) combine negative regex signatures with positive input validation schemas.

### Q5: How did you implement ethical hacking safeguards in this framework?
- The backend features a strict **Scope & Safety Validator** (`core/validator.py`):
  1. Resolves target hostnames to IP addresses using system DNS resolution.
  2. Enforces RFC 1918 loopback (`127.0.0.1`, `::1`) and private IPv4 blocks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
  3. Rejects any public or external IP/domain (e.g., `google.com`, `8.8.8.8`).
  4. Requires a mandatory "Authorized Testing Confirmation" boolean checkbox before any scan job begins.
  5. The scanner only orchestrates assessment tools; no autonomous exploit payloads are authored.

### Q6: How does the Before/After comparison demonstrate security posture improvement?
- Scanning the target application directly (port 3000) exposes severe High-risk vulnerabilities (SQLi, XSS, Path Traversal, Command Injection) and missing security headers.
- Scanning the exact same application through the Mini WAF (port 8080) reveals that:
  - All injection and traversal vectors are blocked with HTTP 403 Forbidden responses.
  - The missing header vulnerabilities are resolved because the WAF middleware injects CSP, X-Frame-Options, and nosniff headers.
  - Result: High-severity findings drop to zero, demonstrating an 80%+ overall risk reduction.

---

## 3. Step-by-Step Viva Demonstration Script

### Step 1: Start the Entire Laboratory Suite
In your terminal, run:
```bash
cd /Users/kashish3359/.gemini/antigravity/scratch/vuln-assessment-framework
./run_lab.sh all
```
*Explain to the examiner:*
> "This launches the Mini WAF on port 8080 and the Scanner Dashboard on port 5000."

### Step 2: Demonstrate Ethical Target Scope Validation
1. Open browser to `http://localhost:5000`.
2. Try typing `https://google.com` or `https://8.8.8.8` and click Start Scan.
   - Show the red alert: *"Security Scope Violation: Scanning is strictly limited to localhost and private networks (RFC 1918)."*
3. Uncheck the "Authorized Testing" box and click Start Scan.
   - Show the alert: *"Authorization required: You must explicitly confirm authorization for isolated lab testing."*

### Step 3: Run Baseline Scan (Direct Target)
1. Select the preset `Juice Shop Direct (:3000)`.
2. Check the authorization confirmation checkbox.
3. Click **Start Vulnerability Assessment**.
4. Show the examiner the live progress bar, the 4-phase tracker, and the streaming execution telemetry.
5. Once completed, explore:
   - Severity Distribution Doughnut Chart (High, Medium, Low, Info).
   - OWASP Top 10 Horizontal Bar Chart.
   - Nmap Open Ports & Service Banner table.
   - Expandable Findings with CWE IDs, technical evidence, and remediations.
6. Click **Download PDF Report** to show the generated PDF report.

### Step 4: Test the Mini WAF in Real Time
Open a separate terminal window and simulate active attacks against port 8080:

```bash
# 1. SQL Injection Probe
curl -i "http://localhost:8080/rest/products/search?q=' OR '1'='1"

# 2. XSS Probe
curl -i -X POST -d "comment=<script>alert(1)</script>" "http://localhost:8080/api/feedback"

# 3. Path Traversal Probe
curl -i "http://localhost:8080/ftp?file=../../../../etc/passwd"

# 4. Safe Request (observes security headers)
curl -i "http://localhost:8080/rest/products/search?q=apple"
```
*Point out to the examiner:*
- The attacks receive **HTTP 403 Forbidden** with incident IDs.
- The safe request receives **HTTP 200 OK** with `Content-Security-Policy`, `X-Frame-Options: SAMEORIGIN`, and `X-Content-Type-Options: nosniff`.

### Step 5: Show Mini WAF Telemetry & Before/After Comparison
1. In the browser, navigate to `http://localhost:5000/waf-admin`:
   - Show the real-time attack logs, attacks by category chart, and active regex rules.
2. Navigate to `http://localhost:5000/compare`:
   - Show the side-by-side comparison chart and mitigation diff matrix proving 100% mitigation of High-severity vulnerabilities.
