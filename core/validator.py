"""
Safety & Scope Validator for Academic Ethical Hacking Lab.
Strictly validates that scan targets are restricted to localhost, 127.0.0.1,
or RFC 1918 private IP ranges, and that explicit authorization is confirmed.
"""
import ipaddress
import socket
from urllib.parse import urlparse

def is_ip_allowed(ip_str: str) -> bool:
    """
    Check if an IP address string is loopback or an RFC 1918 private range.
    Rejects all public / globally routable IP addresses.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        # Allow IPv4 loopback (127.0.0.0/8) and IPv6 loopback (::1)
        if ip.is_loopback:
            return True
        # Allow RFC 1918 private IPv4 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) and RFC 4193 IPv6
        if ip.is_private and not ip.is_link_local and not ip.is_multicast:
            return True
        return False
    except ValueError:
        return False

def validate_target(target_url: str, authorized_acknowledged: bool = False):
    """
    Validate target URL against academic safety rules.

    Returns:
        tuple: (is_valid: bool, error_message: str | None, details: dict | None)
    """
    if not authorized_acknowledged:
        return (
            False,
            "Authorization required: You must explicitly confirm authorization for isolated lab testing before scanning.",
            None
        )

    if not target_url or not isinstance(target_url, str):
        return (False, "Target URL is required.", None)

    target_url = target_url.strip()

    # Prepend scheme if user entered just host:port without any scheme
    if '://' not in target_url:
        target_url = 'http://' + target_url

    try:
        parsed = urlparse(target_url)
    except Exception as e:
        return (False, f"Malformed target URL: {str(e)}", None)

    if parsed.scheme.lower() not in ('http', 'https'):
        return (False, f"Unsupported protocol '{parsed.scheme}'. Only HTTP and HTTPS are permitted.", None)

    hostname = parsed.hostname
    if not hostname:
        return (False, "Invalid target: Hostname or IP address could not be identified.", None)

    # Determine default port if not explicitly provided
    port = parsed.port or (443 if parsed.scheme.lower() == 'https' else 80)

    # Check if hostname itself is directly an IP or localhost
    resolved_ips = []
    if hostname.lower() == 'localhost':
        resolved_ips = ['127.0.0.1']
    else:
        try:
            # Resolve hostname via DNS / system resolver
            addr_info = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
            for item in addr_info:
                sockaddr = item[4]
                resolved_ips.append(sockaddr[0])
        except socket.gaierror:
            return (False, f"Could not resolve host '{hostname}'. Ensure target is reachable in the lab.", None)
        except Exception as e:
            return (False, f"DNS resolution error: {str(e)}", None)

    if not resolved_ips:
        return (False, f"Host '{hostname}' did not resolve to any IP addresses.", None)

    # Check all resolved IPs; all must be in allowed private/loopback ranges
    for ip in resolved_ips:
        if not is_ip_allowed(ip):
            return (
                False,
                f"Security Scope Violation: Host '{hostname}' resolves to public/external IP '{ip}'. "
                "Scanning is strictly limited to localhost and private networks (RFC 1918: 10.x, 172.16-31.x, 192.168.x).",
                None
            )

    primary_ip = resolved_ips[0]
    normalized_url = f"{parsed.scheme.lower()}://{hostname}:{port}" if parsed.port else f"{parsed.scheme.lower()}://{hostname}"
    if parsed.path and parsed.path != '/':
        normalized_url += parsed.path

    details = {
        'original_url': target_url,
        'clean_url': normalized_url,
        'hostname': hostname,
        'port': port,
        'scheme': parsed.scheme.lower(),
        'ip': primary_ip,
        'all_ips': list(set(resolved_ips)),
        'is_loopback': ipaddress.ip_address(primary_ip).is_loopback,
        'is_private': ipaddress.ip_address(primary_ip).is_private
    }

    return (True, None, details)
