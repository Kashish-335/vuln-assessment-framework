# Automated Web Application Vulnerability Assessment Framework with Scanner Dashboard and Mini WAF

An academic, defense-in-depth cybersecurity framework designed for isolated laboratory environments. It combines automated vulnerability assessment (Nmap + OWASP ZAP DAST), taxonomy classification mapped to OWASP Top 10 (2021) and CWE standards, executive ReportLab PDF reporting, a standalone Mini Web Application Firewall (WAF) reverse-proxy, and a Before/After mitigation analytics dashboard.

---

## Architecture Diagram

```mermaid
flowchart TD
    subgraph Client ["Client / Auditor"]
        Browser["Security Auditor / Web Browser"]
    end

    subgraph ScannerApp ["Scanner & Dashboard (Port 5000)"]
        DashboardUI["Bootstrap 5 & Chart.js UI"]
        Validator["Scope & Safety Validator\n(RFC 1918 / Loopback Enforcement)"]
        ScannerWorker["Asynchronous Scanner Orchestrator"]
        NmapEngine["Nmap Service Recon (-sV -Pn)"]
        DASTEngine["DAST Engine (OWASP ZAP API / Lab Engine)"]
        PDFGen["ReportLab PDF Generator"]
    end

    subgraph Defense ["Mini WAF Reverse Proxy (Port 8080)"]
        RateLimiter["Sliding Window Rate Limiter (60 RPM)"]
        RegexEngine["Regex Deep Inspection Engine (rules.json)\n(SQLi, XSS, Path Traversal, CMDi)"]
        HeaderInjector["Security Header Injector\n(CSP, X-Frame-Options, nosniff)"]
        BlockHandler["403 Forbidden Intercept Handler"]
    end

    subgraph Target ["Lab Target Application (Port 3000)"]
        JuiceShop["OWASP Juice Shop / Web Application"]
    end

    subgraph Storage ["Persistence Layer (SQLite)"]
        DB[(assessment_framework.db)]
    end

    %% Interactions
    Browser -->|Launch Scan / View Reports| DashboardUI
    DashboardUI --> Validator
    Validator -->|Authorized Target Validated| ScannerWorker
    ScannerWorker --> NmapEngine
    ScannerWorker --> DASTEngine
    ScannerWorker -->|Store Scans & Findings| DB
    DashboardUI -->|Export Audit| PDFGen

    %% Scanning Targets
    DASTEngine -->|Baseline Scan (Direct)| JuiceShop
    DASTEngine -->|Protected Scan (Through WAF)| RateLimiter

    %% WAF Pipeline
    RateLimiter -->|Clean Traffic| RegexEngine
    RateLimiter -->|Rate Limit Exceeded (429)| BlockHandler
    RegexEngine -->|Attack Detected (403)| BlockHandler
    BlockHandler -->|Log Audit Event| DB
    RegexEngine -->|Forward Valid Traffic| JuiceShop
    JuiceShop -->|Upstream Response| HeaderInjector
    HeaderInjector -->|Response with CSP/X-Frame| DASTEngine

    %% Telemetry
    DashboardUI -->|Query Scan & WAF Events| DB
```

---

## Key Features & Modules

### 1. Scanner Web Dashboard (`dashboard/`)
- **Safety & Scope Validator**: Restricts assessment targets strictly to `localhost`, `127.0.0.1`, `::1`, and RFC 1918 private IPv4 subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`). Rejects all public internet domains.
- **Mandatory Authorization Gate**: Requires explicit confirmation of authorization before starting any scan.
- **Multi-Phase Recon & DAST**:
  - Phase 1: Port and service version reconnaissance using `nmap` (`-sV -Pn`).
  - Phase 2: Web endpoint spidering.
  - Phase 3: Active DAST injection probing (via live OWASP ZAP API on port 8090 or built-in Lab DAST engine).
  - Phase 4: Correlation with OWASP Top 10 (2021) and CWE taxonomy via `cwe_owasp_mapping.json`.
- **Interactive UI**: Real-time progress polling, severity doughnut charts, OWASP Top 10 bar charts, and expandable detail inspection modals with evidence and remediation fixes.

### 2. Executive PDF Report Generator (`reports/`)
- Built with Python `reportlab` (Platypus flowable document architecture).
- Includes formal cover page, executive summary, OWASP WSTG v4.2 testing methodology, findings summary matrix, in-depth technical finding cards, and academic evaluator sign-off blocks.
- Two-pass canvas with running headers and dynamic `"Page X of Y"` footers.

### 3. Mini Web Application Firewall (`waf/`)
- Reverse-proxy middleware listening on port `8080`, forwarding clean requests to the upstream application (port `3000`).
- Deep inspection of query parameters, form fields, JSON bodies, raw payloads, cookies, and HTTP headers (`User-Agent`, `Referer`).
- Pre-compiled regex detection rules (`waf/rules.json`) protecting against:
  - **SQL Injection (SQLi)**: Tautologies (`' OR '1'='1`), `UNION SELECT`, stacked queries, blind sleep functions.
  - **Cross-Site Scripting (XSS)**: `<script>` tags, inline event handlers (`onerror=`, `onload=`), pseudo-protocols (`javascript:`).
  - **Path Traversal / LFI**: Dot-dot-slash sequences (`../`), URL-encoded variants (`%2e%2e%2f`), sensitive system files (`/etc/passwd`, `win.ini`).
  - **OS Command Injection**: Shell operators (`;`, `|`, `&&`, `` ` ``, `$()`) paired with execution binaries.
- Intercepts malicious traffic with a custom, responsive **HTTP 403 Forbidden** incident page.
- In-memory thread-safe sliding window rate limiter (60 RPM).
- Injects defense-in-depth headers: `Content-Security-Policy`, `X-Frame-Options: SAMEORIGIN`, `X-Content-Type-Options: nosniff`.
- Persists all blocked incidents to SQLite (`WafEvent`).

### 4. Before / After Comparison System
- Side-by-side comparison between baseline direct scan (port 3000) and protected WAF scan (port 8080).
- Quantifies risk reduction percentage and High-severity mitigation rate.
- Grouped bar chart comparison and detailed mitigation diff table.

---

## Tech Stack

| Component | Technology |
|---|---|
| **Backend Framework** | Python 3.11+ / Flask |
| **Database & ORM** | SQLite / SQLAlchemy |
| **Network Reconnaissance** | python-nmap / Nmap |
| **DAST Engine** | OWASP ZAP API (`zaproxy`) / Lab Engine |
| **Report Generation** | ReportLab (Platypus) |
| **Frontend UI** | Bootstrap 5, FontAwesome 6, Chart.js |
| **Reverse Proxy & WAF** | Flask, Requests, Regex Engine |
| **Testing** | Pytest (65 unit and integration tests) |

---

## Project Structure

```text
vuln-assessment-framework/
├── .env.example                # Environment configuration template
├── README.md                   # Project documentation & viva guide
├── docker-compose.yml          # Containerized lab (Juice Shop + OWASP ZAP)
├── requirements.txt            # Python dependencies
├── run_lab.sh                  # Centralized orchestration script
├── core/
│   ├── __init__.py
│   ├── config.py               # Settings loader
│   ├── database.py             # SQLAlchemy session & init
│   ├── models.py               # Scan, Finding, and WafEvent models
│   └── validator.py            # Scope validator (RFC 1918 enforcement)
├── dashboard/
│   ├── __init__.py
│   ├── app.py                  # Dashboard Flask routes & controllers
│   ├── scanner.py              # Background scanner orchestrator
│   ├── cwe_owasp_mapping.json  # CWE and OWASP Top 10 taxonomy map
│   ├── templates/              # HTML templates (Bootstrap 5)
│   │   ├── base.html
│   │   ├── index.html
│   │   ├── scan_progress.html
│   │   ├── scan_results.html
│   │   ├── scan_history.html
│   │   ├── comparison.html
│   │   └── waf_admin.html
│   └── static/
│       ├── css/style.css       # Custom cyber-dark stylesheet
│       └── js/dashboard.js     # Table filtering & interactive controls
├── waf/
│   ├── __init__.py
│   ├── waf_proxy.py            # Reverse proxy WAF application
│   ├── rules.json              # Regex attack detection signatures
│   ├── rate_limiter.py         # Sliding window rate limiter
│   └── templates/
│       └── blocked.html        # 403 Forbidden intercept page
├── reports/
│   ├── __init__.py
│   └── generator.py            # ReportLab PDF generator
├── tests/
│   ├── __init__.py
│   ├── test_validator.py       # Target scope unit tests
│   ├── test_waf_rules.py       # Regex rule detection unit tests
│   ├── test_rate_limiter.py    # Rate limiter unit tests
│   ├── test_scanner_parser.py  # CWE/OWASP mapping tests
│   ├── test_dashboard_routes.py# Web app route integration tests
│   └── test_waf_proxy_e2e.py   # WAF reverse proxy end-to-end tests
└── docs/
    ├── architecture.md         # In-depth architectural design
    └── viva_preparation.md     # Viva cheat sheet & demo script
```

---

## Quickstart & Installation

### Prerequisites
- Python 3.11+
- Nmap installed (`brew install nmap` or `sudo apt install nmap`)
- *(Optional)* Docker for running Juice Shop and ZAP daemon

### 1. Clone & Set Up Environment
```bash
git clone <repo-url> vuln-assessment-framework
cd vuln-assessment-framework

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Configure Environment Variables
Copy `.env.example` to create your local `.env` file:
```bash
cp .env.example .env
```
Generate and configure a strong `SECRET_KEY` for Flask session signing:
```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```
Open `.env` and set:
- `SECRET_KEY`: Paste the generated 64-character hex string.
- `ZAP_API_KEY`: Set a secure random string (used by both the framework scanner and the Docker ZAP daemon).

> **Note:** The orchestration script `./run_lab.sh` will also automatically initialize `.env` with fresh, securely generated secrets if you run it without creating `.env` beforehand.

### 3. Optional: Start Lab Target via Docker
If Docker is installed on your system:
```bash
docker compose up -d
```
This spins up:
- **OWASP Juice Shop**: `http://localhost:3000`
- **OWASP ZAP Daemon**: `http://localhost:8090` (Authenticated via the `ZAP_API_KEY` configured in `.env`)

*(Note: If Docker is not installed, the framework seamlessly engages its built-in Lab DAST Engine, enabling 100% of the vulnerability assessment, WAF filtering, and reporting functionality out-of-the-box!)*

---

## Running the Framework

The `./run_lab.sh` orchestration script manages all services:

### Start All Services (Dashboard + Mini WAF)
```bash
./run_lab.sh all
```
Access the web applications:
- **Scanner Dashboard**: [http://localhost:5000](http://localhost:5000)
- **Mini WAF Reverse Proxy**: [http://localhost:8080](http://localhost:8080)
- **WAF Telemetry & Attack Logs**: [http://localhost:5000/waf-admin](http://localhost:5000/waf-admin)
- **Before / After Comparison**: [http://localhost:5000/compare](http://localhost:5000/compare)

### Run Unit & Integration Tests
```bash
./run_lab.sh test
# or
./venv/bin/pytest tests/ -v
```
*(65 test cases validating safety scope, regex accuracy, rate limits, routes, and PDF exports).*

### Seed Demonstration Datasets
To instantly populate the database with Baseline (:3000) and Protected (:8080) scans for a presentation:
```bash
./run_lab.sh seed
```

---

## Testing the Mini WAF Live

With the Mini WAF running on port `8080`, test attack detection via `curl`:

```bash
# 1. SQL Injection (Blocked 403)
curl -i "http://localhost:8080/rest/products/search?q=' OR '1'='1"

# 2. Cross-Site Scripting (Blocked 403)
curl -i -X POST -d "comment=<script>alert('XSS')</script>" "http://localhost:8080/api/feedback"

# 3. Path Traversal (Blocked 403)
curl -i "http://localhost:8080/ftp?file=../../../../etc/passwd"

# 4. OS Command Injection (Blocked 403)
curl -i -X POST -d "ip=; id" "http://localhost:8080/api/diag"

# 5. Safe Traffic (Allowed 200 with CSP and X-Frame-Options headers)
curl -i "http://localhost:8080/rest/products/search?q=apple-juice"
```

Inspect the logged attacks in real time at `http://localhost:5000/waf-admin`.

---

## Ethical Disclaimer
This project is developed solely for educational and authorized academic lab security assessments. The framework contains hardcoded restrictions enforcing testing only within loopback (`127.0.0.1`) and RFC 1918 private subnets. Scanning unauthorized third-party systems is strictly prohibited.
