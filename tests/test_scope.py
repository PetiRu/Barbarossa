"""Tests for scope validation."""

import socket

import pytest

from barbarossa.scope import (
    DNSResolutionError,
    is_blocked_hostname,
    is_blocked_ip,
    is_localhost,
    is_private_ip,
    resolve_target_addresses,
    validate_redirect,
    validate_target_url,
)


def test_localhost_detection() -> None:
    """Test localhost detection."""
    assert is_localhost("localhost")
    assert is_localhost("127.0.0.1")
    assert is_localhost("::1")
    assert not is_localhost("example.com")


def test_private_ip_detection() -> None:
    """Test private IP detection."""
    assert is_private_ip("192.168.1.1")
    assert is_private_ip("10.0.0.1")
    assert is_private_ip("172.16.0.1")
    assert is_private_ip("127.0.0.1")
    assert not is_private_ip("8.8.8.8")


def test_blocked_ip_detection() -> None:
    """Test blocked IP detection."""
    assert is_blocked_ip("169.254.169.254")
    assert is_blocked_ip("168.63.129.16")


def test_blocked_hostname_detection() -> None:
    """Test blocked hostname detection."""
    assert is_blocked_hostname("metadata.google.internal")
    assert is_blocked_hostname("instance-data.ec2.internal")
    assert not is_blocked_hostname("example.com")


def test_validate_localhost() -> None:
    """Test localhost validation."""
    valid, reason = validate_target_url("http://localhost:8000", [])
    assert valid
    assert "Localhost" in reason


def test_validate_private_ip() -> None:
    """Test private IP validation."""
    valid, reason = validate_target_url("http://192.168.1.1", [])
    assert valid
    assert "Private" in reason


def test_validate_blocked_metadata() -> None:
    """Test blocked metadata IP."""
    valid, reason = validate_target_url("http://169.254.169.254", [])
    assert not valid
    assert "Blocked" in reason


def test_validate_public_domain_not_allowed() -> None:
    """Test public domain without allowlist."""
    valid, reason = validate_target_url("http://example.com", [])
    assert not valid
    assert "allowlist" in reason.lower()


def test_validate_public_domain_allowed() -> None:
    """Test public domain in allowlist."""
    valid, reason = validate_target_url("http://example.com", ["example.com"])
    assert valid


def test_validate_redirect_same_host() -> None:
    """Test redirect to same host."""
    valid, reason = validate_redirect(
        "http://example.com/page2", "http://example.com/page1", ["example.com"]
    )
    assert valid


def test_validate_redirect_blocked_host() -> None:
    """Test redirect to blocked host."""
    valid, reason = validate_redirect(
        "http://metadata.google.internal/", "http://example.com", ["example.com"]
    )
    assert not valid


def test_validate_target_rejects_credentials() -> None:
    """Credentials must never be accepted in a target URL."""
    valid, reason = validate_target_url("https://user:secret@example.com", ["example.com"])
    assert not valid
    assert "Credentials" in reason


def test_validate_target_rejects_unsupported_scheme() -> None:
    """Only HTTP(S) probes are supported."""
    valid, reason = validate_target_url("file:///etc/passwd", [])
    assert not valid
    assert "http" in reason


def test_redirect_port_change_requires_explicit_allowlist() -> None:
    """A same-host redirect may not silently escape to a new port."""
    valid, reason = validate_redirect(
        "http://example.com:9000/next",
        "http://example.com/start",
        ["example.com:8000"],
    )
    assert not valid
    assert "allowlist" in reason.lower()


def test_dns_rebinding_to_private_address_is_blocked(monkeypatch: pytest.MonkeyPatch) -> None:
    """An ordinary public allowlist entry cannot resolve into a private network."""

    def fake_getaddrinfo(*args: object, **kwargs: object) -> list[tuple[object, ...]]:
        del args, kwargs
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.8", 80))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(DNSResolutionError, match="DNS rebinding"):
        resolve_target_addresses("http://example.com", ["example.com"])


def test_private_dns_requires_explicit_private_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    """Internal Docker/service names require an explicit private: allowlist entry."""

    def fake_getaddrinfo(*args: object, **kwargs: object) -> list[tuple[object, ...]]:
        del args, kwargs
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("172.20.0.3", 8000))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    assert resolve_target_addresses("http://vulnerable-demo:8000", ["private:vulnerable-demo"]) == (
        "172.20.0.3",
    )


def test_dns_metadata_address_is_always_blocked(monkeypatch: pytest.MonkeyPatch) -> None:
    """Even private scopes cannot resolve to cloud metadata endpoints."""

    def fake_getaddrinfo(*args: object, **kwargs: object) -> list[tuple[object, ...]]:
        del args, kwargs
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 80))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(DNSResolutionError, match="blocked address"):
        resolve_target_addresses("http://internal", ["private:internal"])
