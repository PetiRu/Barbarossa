"""Tests for scope validation."""

from barbarossa.scope import (
    is_blocked_hostname,
    is_blocked_ip,
    is_localhost,
    is_private_ip,
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
        "http://example.com/page2",
        "http://example.com/page1",
        ["example.com"]
    )
    assert valid


def test_validate_redirect_blocked_host() -> None:
    """Test redirect to blocked host."""
    valid, reason = validate_redirect(
        "http://metadata.google.internal/",
        "http://example.com",
        ["example.com"]
    )
    assert not valid
