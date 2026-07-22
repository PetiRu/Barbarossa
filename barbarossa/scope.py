"""Scope and authorization validation."""

import ipaddress
from urllib.parse import urlparse

RESERVED_IPS = [
    "169.254.169.254",
    "127.0.0.1",
    "::1",
    "localhost",
]

CLOUD_METADATA_HOSTS = [
    "metadata.google.internal",
    "instance-data.ec2.internal",
    "168.63.129.16",
    "169.254.169.254",
]


def is_localhost(host: str) -> bool:
    """Check if host is localhost or loopback."""
    return host in ("localhost", "127.0.0.1", "::1") or host.lower() == "localhost"


def is_private_ip(ip_str: str) -> bool:
    """Check if IP is private (RFC1918) or loopback."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_loopback or ip.is_private
    except ValueError:
        return False


def is_blocked_ip(ip_str: str) -> bool:
    """Check if IP is blocked (cloud metadata, reserved, etc)."""
    blocked = [
        "169.254.169.254",
        "168.63.129.16",
        "127.0.0.1",
    ]
    if ip_str in blocked:
        return True

    try:
        ip = ipaddress.ip_address(ip_str)
        return (ip.is_multicast or
                ip.is_link_local or
                ip.is_reserved)
    except ValueError:
        return False


def is_blocked_hostname(hostname: str) -> bool:
    """Check if hostname is blocked (cloud metadata)."""
    blocked = CLOUD_METADATA_HOSTS + [h.lower() for h in CLOUD_METADATA_HOSTS]
    return hostname.lower() in blocked


def validate_target_url(url: str, authorized_targets: list[str]) -> tuple[bool, str]:
    """
    Validate that target URL is in authorized scope.

    Returns (is_valid, reason)
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""

        if not hostname:
            return False, "Could not extract hostname from URL"

        # Check for blocked hostnames
        if is_blocked_hostname(hostname):
            return False, f"Blocked cloud metadata host: {hostname}"

        # Check if localhost/loopback
        if is_localhost(hostname):
            return True, "Localhost allowed by default"

        # Check if private IP
        if is_private_ip(hostname):
            return True, "Private IP allowed by default"

        # Public domain - must be in allowlist
        if hostname not in authorized_targets:
            return False, f"Domain '{hostname}' not in allowlist. Add with --allowlist"

        return True, "In authorized allowlist"

    except Exception as e:
        return False, f"Error validating URL: {e}"


def validate_redirect(redirect_url: str, original_url: str, authorized_targets: list[str]) -> tuple[bool, str]:
    """
    Validate that redirect stays in scope.

    Returns (is_valid, reason)
    """
    original_host = urlparse(original_url).hostname
    redirect_host = urlparse(redirect_url).hostname

    if not redirect_host:
        return False, "Invalid redirect URL"

    # Same host is OK
    if redirect_host == original_host:
        return True, "Same host"

    # Check if blocked
    if is_blocked_hostname(redirect_host):
        return False, f"Redirect to blocked host: {redirect_host}"

    # Check if in scope
    valid, reason = validate_target_url(redirect_url, authorized_targets)
    return valid, f"Redirect validation: {reason}"


def get_hostname_for_security_check(url: str) -> str | None:
    """Extract and validate hostname for security checks."""
    try:
        parsed = urlparse(url)
        return parsed.hostname
    except Exception:
        return None
