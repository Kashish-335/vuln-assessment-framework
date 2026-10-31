# Architecture & Technical Design Document

## Automated Web Application Vulnerability Assessment Framework with Scanner Dashboard and Mini WAF

### 1. High-Level Architecture Overview

The framework adopts a decoupled, defense-in-depth architecture consisting of three primary operational domains:
1. **Dynamic Application Security Testing (DAST) Engine & Scanner Dashboard (Port 5000)**: Coordinates network reconnaissance via Nmap and dynamic web vulnerability probing via OWASP ZAP (or simulated lab fallback), mapping all discoveries to OWASP Top 10 (2021) and CWE standards.
2. **Defensive Mini Web Application Firewall (WAF) (Port 8080)**: Reverse-proxy middleware that inspects full HTTP request contexts (URI, query params, form data, JSON payloads, headers, cookies) against regex detection rules, blocks malicious payloads with HTTP 403 Forbidden, rate limits abusive IPs, and injects defense-in-depth security response headers.
3. **Assessment Target Application (Port 3000)**: The vulnerable lab application (e.g., OWASP Juice Shop).

```mermaid
flowchart TD
    subgraph Client ["Client / Auditor"]
        Browser["Web Browser / Security Auditor"]
    end

    subgraph ScannerApp ["Scanner & Dashboard (Port 5000)"]
        DashboardUI["Bootstrap 5 & Chart.js UI"]
        Validator["Scope & Safety Validator\n(RFC 1918 / Loopback Enforcement)"]
        ScannerWorker["Asynchronous Scanner Orchestrator"]
        NmapEngine["Nmap Service Recon (-sV -Pn)"]
        DASTEngine["DAST Engine (OWASP ZAP API / Lab Engine)"]
        PDFGen["ReportLab PDF Generator (Platypus)"]
    end

    subgraph Defense ["Mini WAF Reverse Proxy (Port 8080)"]
        RateLimiter["Sliding Window Rate Limiter (60 RPM)"]
        RegexEngine["Regex Deep Inspection Engine (rules.json)\n(SQLi, XSS, Path Traversal, CMDi)"]
        HeaderInjector["Security Header Injector\n(CSP, X-Frame-Options, nosniff)"]
        BlockHandler["403 Forbidden Intercept Handler"]
    end

    subgraph Target ["Target Lab Application (Port 3000)"]
        JuiceShop["OWASP Juice Shop / Web Application"]
    end

    subgraph Persistence ["Persistence Layer (SQLite)"]
        DB[(assessment_framework.db)]
        ScansTable["scans"]
        FindingsTable["findings"]
        WafEventsTable["waf_events"]
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
    RateLimiter -->|Pass| RegexEngine
    RateLimiter -->|Exceeded Rate Limit (429)| BlockHandler
    RegexEngine -->|Attack Detected (403)| BlockHandler
    BlockHandler -->|Audit Log| WafEventsTable
    RegexEngine -->|Clean Traffic Forwarded| JuiceShop
    JuiceShop -->|Upstream Response| HeaderInjector
    HeaderInjector -->|Response with CSP/X-Frame| DASTEngine

    %% Telemetry
    DashboardUI -->|Query Scan & WAF Events| DB
```

---

### 2. Core Subsystems

#### A. Target Scope & Safety Validator (`core/validator.py`)
- **Requirement**: Must only allow targets on `localhost`, `127.0.0.1`, `::1`, or RFC 1918 private IPv4 subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
- **Resolution Pipeline**:
  1. Parses URI scheme (`http`/`https` only).
  2. Resolves target hostname to IPv4/IPv6 addresses via `socket.getaddrinfo`.
  3. Validates each resolved IP using Python's standard `ipaddress` module (`is_loopback` or `is_private`).
  4. Immediate rejection of globally routable / public IP addresses (e.g. `8.8.8.8`, `google.com`).
  5. Mandatory verification of explicit user authorization flag.

#### B. Scanner Orchestrator (`dashboard/scanner.py`)
- **Phase 1: Reconnaissance (Nmap)**: Executes `-sV -Pn --version-light` to detect active TCP services, banners, and versions.
- **Phase 2: DAST Engine**:
  - Connects to OWASP ZAP API daemon if reachable on port 8090.
  - In absence of Docker/ZAP, seamlessly engages the **Academic Lab DAST Engine**, crawling application routes and benchmarking against OWASP Juice Shop vulnerability profiles.
- **Phase 3: CWE & OWASP Top 10 Mapping**:
  - Maps alerts to OWASP Top 10 (2021) categories (`A01` through `A10`) and Common Weakness Enumeration IDs (`CWE-89`, `CWE-79`, `CWE-22`, `CWE-78`, etc.) via `cwe_owasp_mapping.json`.
  - Calculates CVSS v3.1 approximate scores and attaches remediation advice.

#### C. Mini WAF Reverse Proxy (`waf/waf_proxy.py`)
- **Inspection Scope**: Inspects URL path, query string parameters, form POST fields, JSON body, raw body, cookies, and HTTP headers (`User-Agent`, `Referer`).
- **Detection Engine (`waf/rules.json`)**: Pre-compiled regular expression patterns categorized into SQLi, XSS, Path Traversal, and Command Injection.
- **Rate Limiting (`waf/rate_limiter.py`)**: Thread-safe in-memory sliding window enforcing 60 requests/minute per client IP.
- **Security Headers Injection**:
  - `Content-Security-Policy: default-src 'self' 'unsafe-inline' 'unsafe-eval' https: data: blob:;`
  - `X-Frame-Options: SAMEORIGIN`
  - `X-Content-Type-Options: nosniff`
  - `X-XSS-Protection: 1; mode=block`
  - `Referrer-Policy: strict-origin-when-cross-origin`
  - `X-WAF-Protected-By: Mini-WAF-v1.0`

#### D. Executive PDF Reporting (`reports/generator.py`)
- Utilizes ReportLab's Platypus flowable document model with custom `NumberedCanvas` two-pass page numbering.
- Generates cover page, executive summary, WSTG methodology, findings table, detailed finding pages, and examiner sign-off blocks.
