"""
Unit tests for the Scanner Parser and CWE/OWASP Top 10 Mapping.
"""
from dashboard.scanner import map_alert_to_cwe_owasp

def test_map_sqli():
    res = map_alert_to_cwe_owasp("SQL Injection - Generic Blind Probe")
    assert res['cwe_id'] == 'CWE-89'
    assert res['owasp_category'] == 'A03:2021-Injection'
    assert res['severity'] == 'High'

def test_map_xss():
    res = map_alert_to_cwe_owasp("Reflected Cross Site Scripting (XSS)")
    assert res['cwe_id'] == 'CWE-79'
    assert res['owasp_category'] == 'A03:2021-Injection'
    assert res['severity'] == 'High'

def test_map_path_traversal():
    res = map_alert_to_cwe_owasp("Path Traversal / Directory Listing")
    assert res['cwe_id'] == 'CWE-22'
    assert res['owasp_category'] == 'A01:2021-Broken Access Control'
    assert res['severity'] == 'High'

def test_map_command_injection():
    res = map_alert_to_cwe_owasp("Remote OS Command Injection")
    assert res['cwe_id'] == 'CWE-78'
    assert res['owasp_category'] == 'A03:2021-Injection'
    assert res['severity'] == 'High'

def test_map_missing_headers():
    res = map_alert_to_cwe_owasp("Missing Anti-Clickjacking Header")
    assert res['cwe_id'] == 'CWE-693'
    assert res['owasp_category'] == 'A05:2021-Security Misconfiguration'
    assert res['severity'] == 'Medium'

def test_map_unrecognized_fallback():
    res = map_alert_to_cwe_owasp("Some Unrecognized Custom Academic Alert")
    assert res['cwe_id'] == 'CWE-16'
    assert res['owasp_category'] == 'A05:2021-Security Misconfiguration'
    assert res['severity'] == 'Informational'
