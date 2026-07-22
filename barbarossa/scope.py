"""Scope, redirect, and DNS validation."""

import ipaddress
import socket
from urllib.parse import urlparse

CLOUD_METADATA_HOSTS = {
    "metadata.google.internal",
    "instance-data.ec2.internal",
    "metadata.azure.internal",
}

CLOUD_METADATA_IPS = {
    ipaddress.ip_address("169.254.169.254"),
    ipaddress.ip_address("168.63.129.16"),
    ipaddress.ip_address("100.100.100.200"),
    ipaddress.ip_address("fd00:ec2::254"),
}


class DNSResolutionError(ValueError):
    """Raised when a target cannot be resolved to a safe address set."""


def _normalized_host(host: str) -> str:
    return host.rstrip(".").lower()


def _effective_port(url: str) -> int | None:
    parsed = urlparse(url)
    try:
        if parsed.port is not None:
            return parsed.port
    except ValueError:
        return None
    if parsed.scheme == "https":
        return 443
    if parsed.scheme == "http":
        return 80
    return None


def _scope_entry_parts(entry: str) -> tuple[str, int | None, bool]:
    """Return host, optional port, and private-DNS permission for an allowlist entry."""
    value = entry.strip().lower()
    allow_private_dns = value.startswith("private:")
    if allow_private_dns:
        value = value.removeprefix("private:")

    parsed = urlparse(value if "://" in value else f"//{value}")
    try:
        port = parsed.port
    except ValueError:
        return value, None, allow_private_dns
    return _normalized_host(parsed.hostname or value), port, allow_private_dns


def _matching_scope_entry(
    host: str, port: int | None, authorized_targets: list[str]
) -> tuple[bool, bool]:
    normalized = _normalized_host(host)
    for entry in authorized_targets:
        entry_host, entry_port, allow_private_dns = _scope_entry_parts(entry)
        if normalized == entry_host and (entry_port is None or entry_port == port):
            return True, allow_private_dns
    return False, False


def is_localhost(host: str) -> bool:
    """Check if host is an explicit localhost name or loopback address."""
    normalized = _normalized_host(host)
    if normalized == "localhost":
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def is_private_ip(ip_str: str) -> bool:
    """Check if an address is private or loopback."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_loopback or ip.is_private
    except ValueError:
        return False


def is_blocked_ip(ip_str: str) -> bool:
    """Check if an address is unsafe even for an explicitly allowed target."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return (
        ip in CLOUD_METADATA_IPS
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def is_blocked_hostname(hostname: str) -> bool:
    """Check if a hostname names a known cloud metadata service."""
    return _normalized_host(hostname) in CLOUD_METADATA_HOSTS


def validate_target_url(url: str, authorized_targets: list[str]) -> tuple[bool, str]:
    """Validate URL syntax and confirm that the target is in authorized scope."""
    try:
        parsed = urlparse(url)
        hostname = _normalized_host(parsed.hostname or "")

        if parsed.scheme not in {"http", "https"}:
            return False, "Only http and https targets are supported"
        if not hostname:
            return False, "Could not extract hostname from URL"
        if parsed.username is not None or parsed.password is not None:
            return False, "Credentials in target URLs are not allowed"

        port = _effective_port(url)
        if port is None or not 1 <= port <= 65535:
            return False, "Invalid target port"

        if is_blocked_hostname(hostname) or is_blocked_ip(hostname):
            return False, f"Blocked metadata or special-use target: {hostname}"
        if is_localhost(hostname):
            return True, "Localhost allowed by default"
        if is_private_ip(hostname):
            return True, "Private IP allowed by default"

        matched, _ = _matching_scope_entry(hostname, port, authorized_targets)
        if not matched:
            return False, f"Domain '{hostname}' not in allowlist. Add with --allowlist"
        return True, "In authorized allowlist"
    except ValueError as exc:
        return False, f"Error validating URL: {exc}"


def validate_redirect(
    redirect_url: str, original_url: str, authorized_targets: list[str]
) -> tuple[bool, str]:
    """Validate scheme, host, and port for one redirect hop."""
    original = urlparse(original_url)
    redirect = urlparse(redirect_url)
    original_host = _normalized_host(original.hostname or "")
    redirect_host = _normalized_host(redirect.hostname or "")

    if not redirect_host:
        return False, "Invalid redirect URL"
    if original.scheme == "https" and redirect.scheme != "https":
        return False, "HTTPS downgrade redirect is not allowed"

    valid, reason = validate_target_url(redirect_url, authorized_targets)
    if not valid:
        return False, f"Redirect validation: {reason}"

    original_port = _effective_port(original_url)
    redirect_port = _effective_port(redirect_url)
    if redirect_host == original_host and redirect_port == original_port:
        return True, "Same host and port"

    matched, _ = _matching_scope_entry(redirect_host, redirect_port, authorized_targets)
    if not matched:
        return False, "Redirect changes host or port outside the explicit allowlist"
    return True, "Redirect target explicitly allowlisted"


def resolve_target_addresses(url: str, authorized_targets: list[str]) -> tuple[str, ...]:
    """Resolve every A/AAAA address and reject DNS rebinding to unsafe networks."""
    valid, reason = validate_target_url(url, authorized_targets)
    if not valid:
        raise DNSResolutionError(reason)

    parsed = urlparse(url)
    hostname = _normalized_host(parsed.hostname or "")
    port = _effective_port(url)
    if port is None:
        raise DNSResolutionError("Invalid target port")

    try:
        literal = ipaddress.ip_address(hostname)
        addresses = {literal}
    except ValueError:
        try:
            records = socket.getaddrinfo(
                hostname, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP
            )
        except socket.gaierror as exc:
            raise DNSResolutionError(f"DNS resolution failed for {hostname}") from exc
        addresses = {ipaddress.ip_address(record[4][0]) for record in records}

    if not addresses:
        raise DNSResolutionError(f"DNS returned no addresses for {hostname}")

    matched, allow_private_dns = _matching_scope_entry(hostname, port, authorized_targets)
    for address in addresses:
        if is_blocked_ip(str(address)):
            raise DNSResolutionError(f"DNS resolved {hostname} to blocked address {address}")
        if is_localhost(hostname) and address.is_loopback:
            continue
        if is_private_ip(hostname) and address == ipaddress.ip_address(hostname):
            continue
        if matched and allow_private_dns and (address.is_private or address.is_loopback):
            continue
        if not address.is_global:
            raise DNSResolutionError(
                f"DNS rebinding protection rejected non-global address {address} "
                f"for {hostname}; use a private: allowlist entry for an internal hostname"
            )

    return tuple(sorted(str(address) for address in addresses))


def get_hostname_for_security_check(url: str) -> str | None:
    """Extract and normalize a hostname for security checks."""
    try:
        hostname = urlparse(url).hostname
    except ValueError:
        return None
    return _normalized_host(hostname) if hostname else None
