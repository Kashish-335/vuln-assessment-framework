"""
Unit tests for the Target Scope & Safety Validator.
"""
import pytest
from core.validator import validate_target, is_ip_allowed

def test_ip_allowed_loopback():
    assert is_ip_allowed("127.0.0.1") is True
    assert is_ip_allowed("127.0.1.1") is True
    assert is_ip_allowed("::1") is True

def test_ip_allowed_rfc1918():
    assert is_ip_allowed("10.0.0.1") is True
    assert is_ip_allowed("10.254.254.254") is True
    assert is_ip_allowed("172.16.0.1") is True
    assert is_ip_allowed("172.31.255.255") is True
    assert is_ip_allowed("192.168.1.100") is True
    assert is_ip_allowed("192.168.0.1") is True

def test_ip_rejected_public():
    assert is_ip_allowed("8.8.8.8") is False
    assert is_ip_allowed("1.1.1.1") is False
    assert is_ip_allowed("142.250.190.46") is False
    assert is_ip_allowed("54.239.28.85") is False

def test_validate_target_requires_authorization():
    valid, err, details = validate_target("http://localhost:3000", authorized_acknowledged=False)
    assert valid is False
    assert "Authorization required" in err
    assert details is None

def test_validate_target_localhost_success():
    valid, err, details = validate_target("http://localhost:3000", authorized_acknowledged=True)
    assert valid is True
    assert err is None
    assert details['hostname'] == 'localhost'
    assert details['port'] == 3000
    assert details['ip'] == '127.0.0.1'
    assert details['is_loopback'] is True

def test_validate_target_127_success():
    valid, err, details = validate_target("http://127.0.0.1:8080", authorized_acknowledged=True)
    assert valid is True
    assert err is None
    assert details['ip'] == '127.0.0.1'
    assert details['port'] == 8080

def test_validate_target_private_ip_success():
    valid, err, details = validate_target("http://192.168.1.50:3000", authorized_acknowledged=True)
    assert valid is True
    assert err is None
    assert details['ip'] == '192.168.1.50'
    assert details['is_private'] is True

def test_validate_target_public_domain_rejection():
    # google.com or public IP should be rejected
    valid, err, details = validate_target("https://8.8.8.8", authorized_acknowledged=True)
    assert valid is False
    assert "Security Scope Violation" in err
    assert details is None

def test_validate_target_unsupported_scheme():
    valid, err, details = validate_target("ftp://127.0.0.1:21", authorized_acknowledged=True)
    assert valid is False
    assert "Unsupported protocol" in err
